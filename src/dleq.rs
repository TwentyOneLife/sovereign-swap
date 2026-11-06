//! BIP374 discrete-log-equality proofs. The payer proves that its revealed ECDH share `C = a*B`
//! shares the discrete log `a` with its public input sum `A = a*G`, without revealing `a`. The fee
//! counterparty check (design 0010, option A) uses this so a counterparty can derive and verify the
//! fee's silent payment output from the revealed share, and be sure the operator can find it, while
//! learning nothing that lets it or a chain watcher link the fee.
//!
//! In-tree, over the `secp256k1` already in the tree; invents no cryptography, composes audited
//! operations to BIP374 and is gated by that BIP's test vectors (`tests/dleq_vectors.rs`). The
//! generator `G` is a parameter, as in the BIP, though in this crate it is always secp256k1's `G`.

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, Verification};

/// secp256k1 group order n, big-endian, for reducing a hash to a scalar.
const ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// A BIP374 proof: `e || s`, each 32 bytes big-endian.
pub type Proof = [u8; 64];

fn tagged_hash(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut eng = sha256::Hash::engine();
    eng.input(tag_hash.as_ref());
    eng.input(tag_hash.as_ref());
    for p in parts {
        eng.input(p);
    }
    sha256::Hash::from_engine(eng).to_byte_array()
}

fn geq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// Reduce a 32-byte big-endian value mod n. Since any 256-bit value is below 2n, one conditional
/// subtraction suffices.
fn reduce_mod_n(mut v: [u8; 32]) -> [u8; 32] {
    if geq(&v, &ORDER) {
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = v[i] as i16 - ORDER[i] as i16 - borrow;
            if d < 0 {
                v[i] = (d + 256) as u8;
                borrow = 1;
            } else {
                v[i] = d as u8;
                borrow = 0;
            }
        }
    }
    v
}

fn scalar(k: &SecretKey) -> Scalar {
    Scalar::from_be_bytes(k.secret_bytes()).expect("a valid secret key is below n")
}

fn xor32(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// `e = H_challenge(A || B || C || G || R1 || R2 || m) mod n`, as 32 big-endian bytes (< n).
fn challenge(
    a: &PublicKey,
    b: &PublicKey,
    c: &PublicKey,
    g: &PublicKey,
    r1: &PublicKey,
    r2: &PublicKey,
    m: Option<&[u8; 32]>,
) -> [u8; 32] {
    let (as_, bs, cs, gs, r1s, r2s) = (
        a.serialize(),
        b.serialize(),
        c.serialize(),
        g.serialize(),
        r1.serialize(),
        r2.serialize(),
    );
    let empty = [];
    let parts: [&[u8]; 7] = [&as_, &bs, &cs, &gs, &r1s, &r2s, m.map_or(&empty, |m| &m[..])];
    reduce_mod_n(tagged_hash("BIP0374/challenge", &parts))
}

/// Prove that `C = a*B` and `A = a*G` share the discrete log `a`, with generator `g` and auxiliary
/// randomness `aux`. Returns `None` for a degenerate input (BIP374 never produces a proof it would
/// then reject). For the standard generator, pass secp256k1's `G`.
pub fn prove<C: Verification>(
    secp: &Secp256k1<C>,
    g: &PublicKey,
    a: &SecretKey,
    b: &PublicKey,
    aux: &[u8; 32],
    m: Option<&[u8; 32]>,
) -> Option<Proof> {
    let big_a = g.mul_tweak(secp, &scalar(a)).ok()?;
    let big_c = b.mul_tweak(secp, &scalar(a)).ok()?;
    let t = xor32(a.secret_bytes(), tagged_hash("BIP0374/aux", &[aux]));
    let empty = [];
    let rand = tagged_hash(
        "BIP0374/nonce",
        &[&t, &big_a.serialize(), &big_c.serialize(), m.map_or(&empty, |m| &m[..])],
    );
    let k = SecretKey::from_slice(&reduce_mod_n(rand)).ok()?; // k == 0 is rejected here
    let r1 = g.mul_tweak(secp, &scalar(&k)).ok()?;
    let r2 = b.mul_tweak(secp, &scalar(&k)).ok()?;
    let e = challenge(&big_a, b, &big_c, g, &r1, &r2, m);
    // s = k + e*a
    let ea = a.mul_tweak(&Scalar::from_be_bytes(e).ok()?).ok()?;
    let s = ea.add_tweak(&scalar(&k)).ok()?;
    let mut proof = [0u8; 64];
    proof[..32].copy_from_slice(&e);
    proof[32..].copy_from_slice(&s.secret_bytes());
    verify(secp, g, &big_a, b, &big_c, &proof, m).then_some(proof)
}

/// Verify a BIP374 proof that `A`, `B`, `C` share a discrete log under generator `g`.
pub fn verify<V: Verification>(
    secp: &Secp256k1<V>,
    g: &PublicKey,
    a: &PublicKey,
    b: &PublicKey,
    c: &PublicKey,
    proof: &Proof,
    m: Option<&[u8; 32]>,
) -> bool {
    let e_bytes: [u8; 32] = proof[..32].try_into().expect("32");
    let s_bytes: [u8; 32] = proof[32..].try_into().expect("32");
    // e and s must both be below n (this rejects the "equal to curve order" vectors).
    let Ok(e) = Scalar::from_be_bytes(e_bytes) else {
        return false;
    };
    let Ok(s) = SecretKey::from_slice(&s_bytes) else {
        return false;
    };
    // R1 = s*G - e*A, R2 = s*B - e*C; a point at infinity fails the proof.
    let (Ok(sg), Ok(ea)) = (g.mul_tweak(secp, &scalar(&s)), a.mul_tweak(secp, &e)) else {
        return false;
    };
    let (Ok(sb), Ok(ec)) = (b.mul_tweak(secp, &scalar(&s)), c.mul_tweak(secp, &e)) else {
        return false;
    };
    let (Ok(r1), Ok(r2)) = (sg.combine(&ea.negate(secp)), sb.combine(&ec.negate(secp))) else {
        return false;
    };
    challenge(a, b, c, g, &r1, &r2, m) == e_bytes
}
