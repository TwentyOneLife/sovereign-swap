//! Per-swap keys and secrets, derived from one seed so a restored seed recovers every swap.

use std::path::Path;

use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{All, Secp256k1, SecretKey};
use bitcoin::{NetworkKind, PubkeyHash, PublicKey};

use crate::htlc::PREIMAGE_LEN;
use crate::store::write_atomic;

/// Purpose index for this engine's tree, outside the BIP43 purposes wallets use.
const PURPOSE: u32 = 21_000;

pub struct Keys {
    master: Xpriv,
    secp: Secp256k1<All>,
}

/// Which key of a swap: the contract we refund, the contract we claim, or the secret's source.
#[derive(Clone, Copy)]
pub enum Use {
    Refund = 0,
    Claim = 1,
    Secret = 2,
}

impl Keys {
    /// Loads the seed in `dir`, creating it from the operating system's randomness on first use.
    pub fn open(dir: &Path) -> std::io::Result<Keys> {
        let path = dir.join("seed");
        let seed = match std::fs::read(&path) {
            Ok(seed) => seed,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut seed = vec![0u8; 32];
                std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom")?, &mut seed)?;
                write_atomic(&path, &seed)?;
                seed
            }
            Err(e) => return Err(e),
        };
        let master = Xpriv::new_master(NetworkKind::Main, &seed).expect("32-byte seed");
        Ok(Keys {
            master,
            secp: Secp256k1::new(),
        })
    }

    pub fn secp(&self) -> &Secp256k1<All> {
        &self.secp
    }

    pub fn key(&self, swap_index: u32, use_: Use) -> SecretKey {
        let path = [PURPOSE, swap_index, use_ as u32]
            .map(|i| ChildNumber::from_hardened_idx(i).expect("below 2^31"));
        self.master
            .derive_priv(&self.secp, &path)
            .expect("hardened derivation")
            .private_key
    }

    pub fn pkh(&self, swap_index: u32, use_: Use) -> PubkeyHash {
        PublicKey::new(self.key(swap_index, use_).public_key(&self.secp)).pubkey_hash()
    }

    /// The hash of a private key: no public key or signature ever reveals it.
    pub fn secret(&self, swap_index: u32) -> [u8; PREIMAGE_LEN] {
        sha256::Hash::hash(&self.key(swap_index, Use::Secret).secret_bytes()).to_byte_array()
    }
}
