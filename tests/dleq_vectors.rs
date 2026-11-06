//! BIP374 DLEQ checked against the official `test_vectors_generate_proof.csv` and
//! `test_vectors_verify_proof.csv`, pinned under `tests/fixtures/` (see the provenance file). This
//! is reference test data from the BIP, the correctness gate for the fee counterparty-check crypto.

use std::str::FromStr;

use bitcoin::hex::FromHex;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

use sovereign_swap::dleq::{prove, verify, Proof};

fn rows(name: &str) -> Vec<Vec<String>> {
    let path = format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name);
    let text = std::fs::read_to_string(path).expect("fixture present");
    text.lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.split(',').map(|f| f.trim().to_owned()).collect())
        .collect()
}

fn opt_msg(s: &str) -> Option<[u8; 32]> {
    if s.is_empty() {
        None
    } else {
        Some(<[u8; 32]>::from_hex(s).expect("32-byte message"))
    }
}

#[test]
fn generate_proof_vectors_match() {
    let secp = Secp256k1::new();
    let rows = rows("bip374_test_vectors_generate_proof.csv");
    assert!(rows.len() >= 11, "expected the full vector set");
    for r in &rows {
        // index, point_G, scalar_a, point_B, auxrand_r, message, result_proof, comment
        let g = PublicKey::from_str(&r[1]).expect("G is a valid point");
        let a = SecretKey::from_str(&r[2]); // a = 0 or n is an invalid key
        let b = PublicKey::from_str(&r[3]); // B at infinity is not a valid compressed point
        let aux = <[u8; 32]>::from_hex(&r[4]).expect("aux");
        let m = opt_msg(&r[5]);
        // Failure vectors mark the result "INVALID" rather than giving a proof.
        let expected: Option<Proof> = if r[6].is_empty() || r[6].eq_ignore_ascii_case("invalid") {
            None
        } else {
            Some(<[u8; 64]>::from_hex(&r[6]).expect("proof"))
        };

        let got = match (a, b) {
            (Ok(a), Ok(b)) => prove(&secp, &g, &a, &b, &aux, m.as_ref()),
            _ => None, // a degenerate scalar or point: no proof, matching the failure vectors
        };
        assert_eq!(got, expected, "generate `{}`", r.last().unwrap());
    }
}

#[test]
fn verify_proof_vectors_match() {
    let secp = Secp256k1::new();
    let rows = rows("bip374_test_vectors_verify_proof.csv");
    assert!(rows.len() >= 17, "expected the full vector set");
    for r in &rows {
        // index, point_G, point_A, point_B, point_C, proof, message, result_success, comment
        let g = PublicKey::from_str(&r[1]).expect("G");
        let a = PublicKey::from_str(&r[2]).expect("A");
        let b = PublicKey::from_str(&r[3]).expect("B");
        let c = PublicKey::from_str(&r[4]).expect("C");
        let proof = <[u8; 64]>::from_hex(&r[5]).expect("proof");
        let m = opt_msg(&r[6]);
        let expected = r[7].eq_ignore_ascii_case("true");
        assert_eq!(
            verify(&secp, &g, &a, &b, &c, &proof, m.as_ref()),
            expected,
            "verify `{}`",
            r.last().unwrap()
        );
    }
}
