//! The payload-format-3 message envelope: hybrid post-quantum encryption and signatures.
//! See `docs/design/0005-nostr-transport-and-pq-envelope.md` and `xbtc-swap-spec.md` section 5.
//!
//! Hybrid means an attacker must break both the classical and the post-quantum scheme: the session
//! key needs both the X25519 and the ML-KEM shared secret, and a signature is valid only if both the
//! secp256k1 Schnorr and the ML-DSA-87 signature verify. The relay and transport are untrusted; every
//! guarantee rests on this envelope.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use bitcoin::secp256k1::{schnorr, Keypair, Message, Secp256k1, XOnlyPublicKey};
use hkdf::Hkdf;
use libcrux_ml_dsa::ml_dsa_87::{self, MLDSA87Signature, MLDSA87VerificationKey};
use libcrux_ml_kem::mlkem1024::{self, MlKem1024Ciphertext, MlKem1024PublicKey};
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};

pub const VERSION: u8 = 3;
pub const SUITE: u8 = 1;

const KEM_PK: usize = 1568;
const KEM_CT: usize = 1568;
const DSA_VK: usize = 2592;
const DSA_SIG: usize = 4627;
const SCHNORR_SIG: usize = 64;
const X_PUB: usize = 32;
/// X25519 public + ML-KEM public + ML-DSA verification + Schnorr x-only.
pub const PUBLIC_IDENTITY_LEN: usize = X_PUB + KEM_PK + DSA_VK + 32;

#[derive(Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    Malformed,
    WrongVersionOrSuite,
    Decryption,
    BadClassicalSignature,
    BadPostQuantumSignature,
}

/// A party's public keys: what a counterparty needs to encrypt to it and verify it. Travels inside
/// a signed offer or bid.
#[derive(Clone)]
pub struct PublicIdentity {
    x25519: XPublic,
    kem: MlKem1024PublicKey,
    dsa: MLDSA87VerificationKey,
    schnorr: XOnlyPublicKey,
}

/// A party's secret keys. Derived from a 32-byte seed so a restored seed recovers every identity.
pub struct Identity {
    x25519: XSecret,
    kem: mlkem1024::MlKem1024KeyPair,
    dsa_signing: ml_dsa_87::MLDSA87SigningKey,
    schnorr: Keypair,
    public: PublicIdentity,
    secp: Secp256k1<bitcoin::secp256k1::All>,
}

fn expand(seed: &[u8; 32], label: &[u8], out: &mut [u8]) {
    Hkdf::<Sha512>::new(Some(b"sovswap/v3/keygen"), seed)
        .expand(label, out)
        .expect("hkdf output within length");
}

impl Identity {
    /// All key material is derived deterministically from `seed`, so the same seed rebuilds the same
    /// identity on any machine.
    pub fn from_seed(seed: &[u8; 32]) -> Identity {
        let secp = Secp256k1::new();

        let mut x = [0u8; 32];
        expand(seed, b"x25519", &mut x);
        let x25519 = XSecret::from(x);

        let mut kem_rand = [0u8; 64];
        expand(seed, b"ml-kem", &mut kem_rand);
        let kem = mlkem1024::generate_key_pair(kem_rand);

        let mut dsa_rand = [0u8; 32];
        expand(seed, b"ml-dsa", &mut dsa_rand);
        let dsa = ml_dsa_87::generate_key_pair(dsa_rand);

        let mut sk = [0u8; 32];
        expand(seed, b"schnorr", &mut sk);
        let schnorr =
            Keypair::from_seckey_slice(&secp, &sk).expect("hardened seed is a valid scalar");

        let public = PublicIdentity {
            x25519: XPublic::from(&x25519),
            kem: kem.public_key().clone(),
            dsa: MLDSA87VerificationKey::new(*dsa.verification_key.as_ref()),
            schnorr: schnorr.x_only_public_key().0,
        };
        Identity {
            x25519,
            kem,
            dsa_signing: dsa.signing_key,
            schnorr,
            public,
            secp,
        }
    }

    pub fn public(&self) -> &PublicIdentity {
        &self.public
    }
}

impl PublicIdentity {
    pub fn to_bytes(&self) -> [u8; PUBLIC_IDENTITY_LEN] {
        let mut out = [0u8; PUBLIC_IDENTITY_LEN];
        let mut o = 0;
        let mut put = |b: &[u8]| {
            out[o..o + b.len()].copy_from_slice(b);
            o += b.len();
        };
        put(self.x25519.as_bytes());
        put(self.kem.as_slice());
        put(self.dsa.as_ref());
        put(&self.schnorr.serialize());
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<PublicIdentity, EnvelopeError> {
        if b.len() != PUBLIC_IDENTITY_LEN {
            return Err(EnvelopeError::Malformed);
        }
        let (x, rest) = b.split_at(X_PUB);
        let (kem, rest) = rest.split_at(KEM_PK);
        let (dsa, schnorr) = rest.split_at(DSA_VK);
        Ok(PublicIdentity {
            x25519: XPublic::from(<[u8; 32]>::try_from(x).unwrap()),
            kem: MlKem1024PublicKey::try_from(kem).map_err(|_| EnvelopeError::Malformed)?,
            dsa: MLDSA87VerificationKey::new(<[u8; DSA_VK]>::try_from(dsa).unwrap()),
            schnorr: XOnlyPublicKey::from_slice(schnorr).map_err(|_| EnvelopeError::Malformed)?,
        })
    }
}

fn sig_transcript(
    domain: &[u8],
    sender: &PublicIdentity,
    recipient: Option<&PublicIdentity>,
    payload: &[u8],
) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(domain);
    h.update(sender.to_bytes());
    if let Some(r) = recipient {
        h.update(r.to_bytes());
    }
    h.update(payload);
    h.finalize().into()
}

fn hybrid_sign(
    id: &Identity,
    transcript: &[u8; 64],
    dsa_rand: [u8; 32],
) -> ([u8; SCHNORR_SIG], MLDSA87Signature) {
    let msg = Message::from_digest(Sha256::digest(transcript).into());
    let schnorr = id.secp.sign_schnorr_no_aux_rand(&msg, &id.schnorr);
    let dsa = ml_dsa_87::sign(&id.dsa_signing, transcript, b"", dsa_rand)
        .expect("signing cannot fail with valid key");
    (schnorr.serialize(), dsa)
}

fn hybrid_verify(
    sender: &PublicIdentity,
    transcript: &[u8; 64],
    schnorr_sig: &[u8],
    dsa_sig: &[u8],
) -> Result<(), EnvelopeError> {
    let sig = schnorr::Signature::from_slice(schnorr_sig)
        .map_err(|_| EnvelopeError::BadClassicalSignature)?;
    let msg = Message::from_digest(Sha256::digest(transcript).into());
    Secp256k1::new()
        .verify_schnorr(&sig, &msg, &sender.schnorr)
        .map_err(|_| EnvelopeError::BadClassicalSignature)?;
    let dsa_sig = MLDSA87Signature::new(
        <[u8; DSA_SIG]>::try_from(dsa_sig).map_err(|_| EnvelopeError::BadPostQuantumSignature)?,
    );
    ml_dsa_87::verify(&sender.dsa, transcript, b"", &dsa_sig)
        .map_err(|_| EnvelopeError::BadPostQuantumSignature)
}

/// A broadcast message (an offer): signed with both schemes, not encrypted.
/// Layout: version | suite | schnorr(64) | ml-dsa(4627) | payload.
pub fn sign_broadcast(id: &Identity, payload: &[u8], dsa_rand: [u8; 32]) -> Vec<u8> {
    let transcript = sig_transcript(b"sovswap/v3/offer", id.public(), None, payload);
    let (schnorr, dsa) = hybrid_sign(id, &transcript, dsa_rand);
    let mut out = vec![VERSION, SUITE];
    out.extend_from_slice(&schnorr);
    out.extend_from_slice(dsa.as_ref());
    out.extend_from_slice(payload);
    out
}

/// Read a broadcast's payload WITHOUT verifying either signature. For the untrusted relay only: the
/// relay authenticates a broadcast's author by the outer nostr event signature (`event.pubkey`) and
/// its tombstone/eviction logic keys on that author, so it never needs the envelope's own Schnorr or
/// ML-DSA signatures. Skipping them drops a ~4.6 KB ML-DSA verify per broadcast, the dominant cost on
/// the relay host. Clients MUST use `verify_broadcast` for end-to-end authenticity; this is deliberately
/// not a verification. Returns `None` on a malformed or too-short frame.
pub fn read_broadcast_payload(bytes: &[u8]) -> Option<&[u8]> {
    let rest = match bytes {
        [VERSION, SUITE, rest @ ..] => rest,
        _ => return None,
    };
    if rest.len() < SCHNORR_SIG + DSA_SIG {
        return None;
    }
    Some(&rest[SCHNORR_SIG + DSA_SIG..])
}

pub fn verify_broadcast(sender: &PublicIdentity, bytes: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    let rest = check_header(bytes)?;
    if rest.len() < SCHNORR_SIG + DSA_SIG {
        return Err(EnvelopeError::Malformed);
    }
    let (schnorr, rest) = rest.split_at(SCHNORR_SIG);
    let (dsa, payload) = rest.split_at(DSA_SIG);
    let transcript = sig_transcript(b"sovswap/v3/offer", sender, None, payload);
    hybrid_verify(sender, &transcript, schnorr, dsa)?;
    Ok(payload.to_vec())
}

fn check_header(bytes: &[u8]) -> Result<&[u8], EnvelopeError> {
    match bytes {
        [VERSION, SUITE, rest @ ..] => Ok(rest),
        [_, _, ..] => Err(EnvelopeError::WrongVersionOrSuite),
        _ => Err(EnvelopeError::Malformed),
    }
}

/// Derives the AEAD key and nonce from both shared secrets, bound to the recipient's static keys so
/// only the intended recipient reaches them.
fn kdf(
    ss_kem: &[u8; 32],
    ss_x: &[u8; 32],
    header_kem: &[u8],
    recipient: &PublicIdentity,
) -> ([u8; 32], [u8; 12]) {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ss_kem);
    ikm[32..].copy_from_slice(ss_x);
    let mut info = Sha512::new();
    info.update(header_kem);
    info.update(recipient.kem.as_slice());
    info.update(recipient.x25519.as_bytes());
    let info = info.finalize();

    let mut okm = [0u8; 44];
    Hkdf::<Sha512>::new(Some(b"sovswap/v3/0x01"), &ikm)
        .expand(&info, &mut okm)
        .expect("44 within length");
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&okm[32..]);
    (key, nonce)
}

/// A direct message (a bid and the swap steps): signed, then encrypted to `recipient`.
/// Layout: version | suite | x25519_eph(32) | ml-kem_ct(1568) | aead( payload_len(4) | payload | schnorr(64) | ml-dsa(4627) ).
/// `rand` supplies the ephemeral X25519 secret, the ML-KEM encaps coins, and the ML-DSA signing coins.
pub fn seal(
    sender: &Identity,
    recipient: &PublicIdentity,
    payload: &[u8],
    rand: &[u8; 96],
) -> Vec<u8> {
    let transcript = sig_transcript(b"sovswap/v3/msg", sender.public(), Some(recipient), payload);
    let (schnorr, dsa) = hybrid_sign(sender, &transcript, rand[64..].try_into().unwrap());

    let mut plaintext = (payload.len() as u32).to_le_bytes().to_vec();
    plaintext.extend_from_slice(payload);
    plaintext.extend_from_slice(&schnorr);
    plaintext.extend_from_slice(dsa.as_ref());

    let eph = XSecret::from(<[u8; 32]>::try_from(&rand[..32]).unwrap());
    let eph_pub = XPublic::from(&eph);
    let ss_x = eph.diffie_hellman(&recipient.x25519);
    let (ct, ss_kem) = mlkem1024::encapsulate(&recipient.kem, rand[32..64].try_into().unwrap());

    let mut aad = vec![VERSION, SUITE];
    aad.extend_from_slice(eph_pub.as_bytes());
    aad.extend_from_slice(ct.as_ref());
    let (key, nonce) = kdf(&ss_kem, ss_x.as_bytes(), &aad[2..], recipient);
    let nonce = Nonce::try_from(&nonce[..]).expect("12 bytes");
    let ciphertext = Aes256Gcm::new_from_slice(&key)
        .expect("32-byte key")
        .encrypt(
            &nonce,
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .expect("aes-gcm encryption cannot fail");

    let mut out = aad;
    out.extend_from_slice(&ciphertext);
    out
}

pub fn open(
    recipient: &Identity,
    sender: &PublicIdentity,
    bytes: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    let rest = check_header(bytes)?;
    if rest.len() < X_PUB + KEM_CT {
        return Err(EnvelopeError::Malformed);
    }
    let (eph, rest) = rest.split_at(X_PUB);
    let (ct, ciphertext) = rest.split_at(KEM_CT);

    let eph_pub = XPublic::from(<[u8; 32]>::try_from(eph).unwrap());
    let ss_x = recipient.x25519.diffie_hellman(&eph_pub);
    let ct = MlKem1024Ciphertext::try_from(ct).map_err(|_| EnvelopeError::Malformed)?;
    let ss_kem = mlkem1024::decapsulate(recipient.kem.private_key(), &ct);

    let aad = &bytes[..2 + X_PUB + KEM_CT];
    let (key, nonce) = kdf(&ss_kem, ss_x.as_bytes(), &aad[2..], recipient.public());
    let nonce = Nonce::try_from(&nonce[..]).expect("12 bytes");
    let plaintext = Aes256Gcm::new_from_slice(&key)
        .expect("32-byte key")
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| EnvelopeError::Decryption)?;

    if plaintext.len() < 4 {
        return Err(EnvelopeError::Malformed);
    }
    let payload_len = u32::from_le_bytes(plaintext[..4].try_into().unwrap()) as usize;
    let body = &plaintext[4..];
    if body.len() != payload_len + SCHNORR_SIG + DSA_SIG {
        return Err(EnvelopeError::Malformed);
    }
    let (payload, sigs) = body.split_at(payload_len);
    let (schnorr, dsa) = sigs.split_at(SCHNORR_SIG);
    let transcript = sig_transcript(b"sovswap/v3/msg", sender, Some(recipient.public()), payload);
    hybrid_verify(sender, &transcript, schnorr, dsa)?;
    Ok(payload.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identities() -> (Identity, Identity) {
        (Identity::from_seed(&[1; 32]), Identity::from_seed(&[2; 32]))
    }

    #[test]
    fn public_identity_round_trips() {
        let id = Identity::from_seed(&[9; 32]);
        let bytes = id.public().to_bytes();
        let back = PublicIdentity::from_bytes(&bytes).unwrap();
        assert_eq!(back.to_bytes(), bytes);
    }

    #[test]
    fn seal_open_round_trip() {
        let (alice, bob) = identities();
        let sealed = seal(&alice, bob.public(), b"a bid for 0.5 xBTC", &[4; 96]);
        assert_eq!(
            open(&bob, alice.public(), &sealed).unwrap(),
            b"a bid for 0.5 xBTC"
        );
    }

    #[test]
    fn a_tampered_byte_anywhere_is_rejected() {
        let (alice, bob) = identities();
        let sealed = seal(&alice, bob.public(), b"swap step", &[4; 96]);
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert!(
                open(&bob, alice.public(), &bad).is_err(),
                "byte {i} flipped but accepted"
            );
        }
    }

    #[test]
    fn the_wrong_recipient_cannot_open_it() {
        let (alice, bob) = identities();
        let eve = Identity::from_seed(&[3; 32]);
        let sealed = seal(&alice, bob.public(), b"secret", &[4; 96]);
        assert_eq!(
            open(&eve, alice.public(), &sealed),
            Err(EnvelopeError::Decryption)
        );
    }

    #[test]
    fn a_message_from_a_different_sender_fails_the_signature() {
        let (alice, bob) = identities();
        let mallory = Identity::from_seed(&[7; 32]);
        let sealed = seal(&alice, bob.public(), b"swap step", &[4; 96]);
        // Decrypts (encrypted to bob) but the signature is checked against mallory's keys.
        assert_eq!(
            open(&bob, mallory.public(), &sealed),
            Err(EnvelopeError::BadClassicalSignature)
        );
    }

    #[test]
    fn broadcast_sign_and_verify() {
        let alice = Identity::from_seed(&[1; 32]);
        let signed = sign_broadcast(&alice, b"an offer: 0.5 xBTC for 0.15 BTC", [8; 32]);
        assert_eq!(
            verify_broadcast(alice.public(), &signed).unwrap(),
            b"an offer: 0.5 xBTC for 0.15 BTC"
        );
        let mut bad = signed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(verify_broadcast(alice.public(), &bad).is_err());
        let bob = Identity::from_seed(&[2; 32]);
        assert!(
            verify_broadcast(bob.public(), &signed).is_err(),
            "another signer's key must not verify"
        );
    }

    #[test]
    fn read_broadcast_payload_returns_the_payload_without_verifying() {
        let alice = Identity::from_seed(&[1; 32]);
        let payload = b"an offer: 0.5 xBTC for 0.15 BTC";
        let signed = sign_broadcast(&alice, payload, [8; 32]);

        // The unverified read returns exactly the payload verify_broadcast authenticates.
        assert_eq!(read_broadcast_payload(&signed), Some(&payload[..]));

        // It does NOT verify: a broadcast whose signatures are corrupted (but whose layout is intact)
        // still yields the payload, while verify_broadcast rejects it. This is the relay's fast path;
        // authenticity is enforced by the outer event signature, not here.
        let mut corrupt = signed.clone();
        corrupt[2] ^= 0xff; // flip a Schnorr-signature byte
        *corrupt.last_mut().unwrap() ^= 0xff; // and a payload-trailing byte stays in the payload
        assert!(verify_broadcast(alice.public(), &corrupt).is_err());
        assert!(
            read_broadcast_payload(&corrupt).is_some(),
            "the unverified read must still decode a broadcast with a bad signature"
        );

        // A truncated frame (shorter than the two fixed-size signatures) is rejected, not panicked on.
        assert_eq!(read_broadcast_payload(&signed[..10]), None);
        assert_eq!(read_broadcast_payload(&[]), None);
        assert_eq!(read_broadcast_payload(&[VERSION, SUITE]), None);
    }

    #[test]
    fn hybrid_both_halves_are_required() {
        // On a broadcast (version|suite|schnorr(64)|ml-dsa(4627)|payload) corrupt each signature
        // half on its own: a valid envelope must need both.
        let alice = Identity::from_seed(&[1; 32]);
        let signed = sign_broadcast(&alice, b"offer", [8; 32]);
        assert!(verify_broadcast(alice.public(), &signed).is_ok());

        let mut classical = signed.clone();
        classical[2] ^= 1; // first byte of the Schnorr signature
        assert_eq!(
            verify_broadcast(alice.public(), &classical),
            Err(EnvelopeError::BadClassicalSignature)
        );

        let mut pq = signed.clone();
        pq[2 + SCHNORR_SIG] ^= 1; // first byte of the ML-DSA signature
        assert_eq!(
            verify_broadcast(alice.public(), &pq),
            Err(EnvelopeError::BadPostQuantumSignature)
        );
    }
}
