//! Nostr events (NIP-01) that carry our envelopes, see `docs/design/0006-nostr-client-and-relay.md`.
//!
//! The event's `pubkey` is a throwaway per-swap routing key, not a party's identity; the real
//! identity and all confidentiality live inside the envelope in `content`. So a relay sees only
//! routing keys and opaque bytes.

use bitcoin::hex::{Case, DisplayHex, FromHex};
use bitcoin::secp256k1::{
    schnorr, Keypair, Message, Secp256k1, Signing, Verification, XOnlyPublicKey,
};
use sha2::{Digest, Sha256};

pub const KIND_SWAP: u32 = 4859;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub id: [u8; 32],
    pub pubkey: XOnlyPublicKey,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    /// Hex of the envelope bytes (Nostr content is a JSON string).
    pub content: String,
    pub sig: [u8; 64],
}

#[derive(Debug, PartialEq, Eq)]
pub enum NostrError {
    Malformed,
    BadId,
    BadSignature,
}

/// NIP-01 string escaping: only these seven, everything else (our hex is all of it) passes through.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            _ => out.push(c),
        }
    }
    out
}

fn canonical(
    pubkey: &XOnlyPublicKey,
    created_at: u64,
    kind: u32,
    tags: &[Vec<String>],
    content: &str,
) -> String {
    let tags_json: Vec<String> = tags
        .iter()
        .map(|tag| {
            let items: Vec<String> = tag.iter().map(|s| format!("\"{}\"", escape(s))).collect();
            format!("[{}]", items.join(","))
        })
        .collect();
    format!(
        "[0,\"{}\",{},{},[{}],\"{}\"]",
        pubkey.serialize().to_hex_string(Case::Lower),
        created_at,
        kind,
        tags_json.join(","),
        escape(content),
    )
}

fn event_id(
    pubkey: &XOnlyPublicKey,
    created_at: u64,
    kind: u32,
    tags: &[Vec<String>],
    content: &str,
) -> [u8; 32] {
    Sha256::digest(canonical(pubkey, created_at, kind, tags, content).as_bytes()).into()
}

impl Event {
    /// Builds and signs an event carrying `envelope`, under the per-swap routing `key`.
    pub fn build<C: Signing>(
        secp: &Secp256k1<C>,
        key: &Keypair,
        created_at: u64,
        tags: Vec<Vec<String>>,
        envelope: &[u8],
    ) -> Event {
        let pubkey = key.x_only_public_key().0;
        let content = envelope.to_hex_string(Case::Lower);
        let id = event_id(&pubkey, created_at, KIND_SWAP, &tags, &content);
        let sig = secp
            .sign_schnorr_no_aux_rand(&Message::from_digest(id), key)
            .serialize();
        Event {
            id,
            pubkey,
            created_at,
            kind: KIND_SWAP,
            tags,
            content,
            sig,
        }
    }

    /// The routing key an event is addressed to, if any (`["p", <hex>]`).
    pub fn recipient(&self) -> Option<XOnlyPublicKey> {
        self.tags
            .iter()
            .find(|t| t.len() == 2 && t[0] == "p")
            .and_then(|t| XOnlyPublicKey::from_slice(&Vec::<u8>::from_hex(&t[1]).ok()?).ok())
    }

    pub fn envelope(&self) -> Result<Vec<u8>, NostrError> {
        Vec::<u8>::from_hex(&self.content).map_err(|_| NostrError::Malformed)
    }

    /// Recomputes the id and checks it and the signature. An untrusted relay's event passes only if
    /// it is internally consistent and really signed by `pubkey`.
    pub fn verify<C: Verification>(&self, secp: &Secp256k1<C>) -> Result<(), NostrError> {
        if self.kind != KIND_SWAP {
            return Err(NostrError::Malformed);
        }
        if event_id(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        ) != self.id
        {
            return Err(NostrError::BadId);
        }
        let sig =
            schnorr::Signature::from_slice(&self.sig).map_err(|_| NostrError::BadSignature)?;
        secp.verify_schnorr(&sig, &Message::from_digest(self.id), &self.pubkey)
            .map_err(|_| NostrError::BadSignature)
    }

    pub fn to_json(&self) -> String {
        let tags: Vec<String> = self
            .tags
            .iter()
            .map(|t| {
                format!(
                    "[{}]",
                    t.iter()
                        .map(|s| format!("\"{}\"", escape(s)))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            })
            .collect();
        format!(
            "{{\"id\":\"{}\",\"pubkey\":\"{}\",\"created_at\":{},\"kind\":{},\"tags\":[{}],\"content\":\"{}\",\"sig\":\"{}\"}}",
            self.id.to_hex_string(Case::Lower),
            self.pubkey.serialize().to_hex_string(Case::Lower),
            self.created_at,
            self.kind,
            tags.join(","),
            escape(&self.content),
            self.sig.to_hex_string(Case::Lower),
        )
    }

    pub fn from_json(bytes: &[u8]) -> Result<Event, NostrError> {
        let v: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| NostrError::Malformed)?;
        let hex32 = |k: &str| -> Result<[u8; 32], NostrError> {
            let s = v[k].as_str().ok_or(NostrError::Malformed)?;
            <[u8; 32]>::from_hex(s).map_err(|_| NostrError::Malformed)
        };
        let tags = v["tags"]
            .as_array()
            .ok_or(NostrError::Malformed)?
            .iter()
            .map(|tag| {
                tag.as_array()
                    .ok_or(NostrError::Malformed)?
                    .iter()
                    .map(|s| s.as_str().map(str::to_owned).ok_or(NostrError::Malformed))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let pubkey =
            XOnlyPublicKey::from_slice(&hex32("pubkey")?).map_err(|_| NostrError::Malformed)?;
        let sig = <[u8; 64]>::from_hex(v["sig"].as_str().ok_or(NostrError::Malformed)?)
            .map_err(|_| NostrError::Malformed)?;
        Ok(Event {
            id: hex32("id")?,
            pubkey,
            created_at: v["created_at"].as_u64().ok_or(NostrError::Malformed)?,
            kind: u32::try_from(v["kind"].as_u64().ok_or(NostrError::Malformed)?)
                .map_err(|_| NostrError::Malformed)?,
            tags,
            content: v["content"]
                .as_str()
                .ok_or(NostrError::Malformed)?
                .to_owned(),
            sig,
        })
    }
}

/// The `["p", <hex>]` tag addressing an event to a routing key.
pub fn p_tag(recipient: &XOnlyPublicKey) -> Vec<String> {
    vec![
        "p".to_owned(),
        recipient.serialize().to_hex_string(Case::Lower),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> Keypair {
        Keypair::from_seckey_slice(&Secp256k1::new(), &[byte; 32]).unwrap()
    }

    #[test]
    fn event_round_trips_through_json_and_verifies() {
        let secp = Secp256k1::new();
        let maker = key(1);
        let taker = key(2).x_only_public_key().0;
        let ev = Event::build(
            &secp,
            &maker,
            1_700_000_000,
            vec![p_tag(&taker)],
            &[0xde, 0xad, 0xbe, 0xef],
        );
        ev.verify(&secp).unwrap();
        let back = Event::from_json(ev.to_json().as_bytes()).unwrap();
        assert_eq!(back, ev);
        back.verify(&secp).unwrap();
        assert_eq!(back.envelope().unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(back.recipient(), Some(taker));
    }

    #[test]
    fn a_broadcast_event_has_no_recipient() {
        let secp = Secp256k1::new();
        let ev = Event::build(&secp, &key(1), 1, vec![], &[1, 2, 3]);
        assert_eq!(ev.recipient(), None);
    }

    #[test]
    fn tampering_is_rejected() {
        let secp = Secp256k1::new();
        let ev = Event::build(&secp, &key(1), 1, vec![], &[1, 2, 3]);

        let mut bad_content = ev.clone();
        bad_content.content = [9u8, 9].to_hex_string(Case::Lower);
        assert_eq!(
            bad_content.verify(&secp),
            Err(NostrError::BadId),
            "content changed, id not recomputed"
        );

        // Recompute the id for the new content but keep the old signature: the sig no longer matches.
        let mut forged = bad_content.clone();
        forged.id = event_id(
            &forged.pubkey,
            forged.created_at,
            forged.kind,
            &forged.tags,
            &forged.content,
        );
        assert_eq!(forged.verify(&secp), Err(NostrError::BadSignature));

        let mut wrong_signer = ev.clone();
        wrong_signer.pubkey = key(2).x_only_public_key().0;
        assert!(
            wrong_signer.verify(&secp).is_err(),
            "another pubkey must not verify"
        );
    }

    #[test]
    fn id_matches_an_independent_nip01_hash() {
        // Cross-checked against SHA-256 of the canonical string computed outside Rust, so the
        // serialization interoperates, not merely with itself.
        let secp = Secp256k1::new();
        let ev = Event::build(&secp, &key(1), 1_700_000_000, vec![], &[0xab, 0xcd]);
        assert_eq!(
            ev.id.to_hex_string(Case::Lower),
            "600690271048a707528b18eda52978f843d3f153fe54c6ac43337410c1fdd06f"
        );
    }

    #[test]
    fn canonical_serialization_escapes_per_nip01() {
        let s = "a\"b\\c\nd\te";
        assert_eq!(escape(s), "a\\\"b\\\\c\\nd\\te");
        // A tag with a quote round-trips through our JSON and parses back.
        let secp = Secp256k1::new();
        let ev = Event::build(
            &secp,
            &key(1),
            1,
            vec![vec!["x".into(), "a\"b".into()]],
            &[7],
        );
        let back = Event::from_json(ev.to_json().as_bytes()).unwrap();
        assert_eq!(back.tags, ev.tags);
        back.verify(&secp).unwrap();
    }
}
