//! UR (Uniform Resources) encoding of a PSBT as `ur:crypto-psbt` for animated-QR display (#274),
//! per BCR-2020-005 (UR) and BCR-2020-012 (Bytewords).
//!
//! Encode only. A single-part UR when the message fits one fragment, otherwise the "pure" multi-part
//! fragments (`seqNum` 1..=`seqLen`), which any compliant decoder (SeedSigner, Sparrow, Shrike)
//! reassembles by reading each part once (the fixed-rate scheme, BCR-2020-005 ss "UR Encoding"). We
//! never emit the fountain-mixed parts (`seqNum` > `seqLen`); generating and consuming those is a
//! decoder concern, deferred to the scan-back work. The GUI uppercases nothing itself: the public
//! entry point returns upper-case strings so each QR uses the efficient alphanumeric mode.
//!
//! Correctness is pinned to the published Blockchain Commons vectors in the tests (the 256-word
//! Bytewords table, CRC32, the single- and multi-part `ur:seed` examples), not to a round-trip
//! through our own decoder.

/// Minimal Bytewords: the first and last letter of each of the 256 words (BCR-2020-012 word list),
/// indexed by byte value (two chars per byte). Generated from that table; verified by the CRC and
/// `ur:seed` vectors in the tests.
const MINIMAL: &[u8; 512] = b"\
aeadaoaxaaahamatayasbkbdbnbtbabsbebybgbwbbbzcmchcscfcycwcecackct\
cxclcpcndkdadsdidedtdrdndwdpdmdldyeheyeoeeecenemetesftfrfnfsfmfh\
fzfpfwfxfyfefgflfdgagegrgsgtglgwgdgygmgughgohfhghdhkhthphhhlhyhe\
hnhsidiaieihiyioisinimjejzjnjtjljojsjpjkjykpkoktkskkknkgkekikblb\
lalylflslrlplnltloldlelulklgmnmymhmemomumwmdmtmsmknlnyndnsntnnne\
nboyoeotoxonolospdptpkpypspmplpepfpaprqdqzrerprlrorhrdrkrfryrnrs\
rtsesasrssskswstspsosgsbsfsntotktitttdtetytltbtstptatnuyuoutueur\
vtvyvovlvevwvavdvswlwdwmwpwewywswtwnwzwfwkykynylyaytzszoztzczezm\
";

/// IEEE 802.3 (reflected) CRC32, the checksum Bytewords/UR append (BCR-2020-012 ss "Checksum").
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// Minimal-Bytewords-encode `data` followed by its CRC32 (big-endian) - the standard body + checksum
/// - as lower-case ASCII.
fn bytewords(data: &[u8]) -> String {
    let crc = crc32(data).to_be_bytes();
    let mut s = String::with_capacity((data.len() + 4) * 2);
    for &b in data.iter().chain(crc.iter()) {
        let i = b as usize * 2;
        s.push(MINIMAL[i] as char);
        s.push(MINIMAL[i + 1] as char);
    }
    s
}

/// dCBOR unsigned integer, minimal width (BCR-2020-005 uses deterministic CBOR).
fn cbor_uint(n: u64, out: &mut Vec<u8>) {
    match n {
        0..=23 => out.push(n as u8),
        24..=0xff => out.extend_from_slice(&[0x18, n as u8]),
        0x100..=0xffff => {
            out.push(0x19);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0x1a);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(0x1b);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

/// dCBOR byte string: a minimal-width length header, then the bytes.
fn cbor_bytes(data: &[u8], out: &mut Vec<u8>) {
    let n = data.len() as u64;
    match n {
        0..=23 => out.push(0x40 + n as u8),
        24..=0xff => out.extend_from_slice(&[0x58, n as u8]),
        0x100..=0xffff => {
            out.push(0x59);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0x5a);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(0x5b);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
    out.extend_from_slice(data);
}

/// Bytes per fragment we target by default. Each part is roughly `(fragment + ~12 overhead) * 2`
/// alphanumeric chars, so ~100 keeps every QR a low, camera-friendly version for hardware signers
/// like SeedSigner, while large PSBTs animate across several frames.
pub const DEFAULT_MAX_FRAGMENT_LEN: usize = 100;

/// The `ur:crypto-psbt` message: the untagged dCBOR byte string wrapping the PSBT (BCR-2020-006).
fn crypto_psbt_message(psbt: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(psbt.len() + 5);
    cbor_bytes(psbt, &mut m);
    m
}

/// Encode a UR `message` of `ur_type` into canonical lower-case part strings.
fn ur_parts_lower(ur_type: &str, message: &[u8], max_fragment_len: usize) -> Vec<String> {
    let max_fragment_len = max_fragment_len.max(1);
    let message_len = message.len();
    if message_len <= max_fragment_len {
        return vec![format!("ur:{ur_type}/{}", bytewords(message))];
    }
    let seq_len = message_len.div_ceil(max_fragment_len);
    let frag_len = message_len.div_ceil(seq_len); // even split; the last fragment is zero-padded
    let checksum = crc32(message) as u64;
    (0..seq_len)
        .map(|i| {
            let start = i * frag_len;
            let end = (start + frag_len).min(message_len);
            let mut fragment = vec![0u8; frag_len];
            fragment[..end - start].copy_from_slice(&message[start..end]);
            let mut part = vec![0x85]; // CBOR array(5): [seqNum, seqLen, messageLen, checksum, data]
            cbor_uint((i + 1) as u64, &mut part);
            cbor_uint(seq_len as u64, &mut part);
            cbor_uint(message_len as u64, &mut part);
            cbor_uint(checksum, &mut part);
            cbor_bytes(&fragment, &mut part);
            format!("ur:{ur_type}/{}-{seq_len}/{}", i + 1, bytewords(&part))
        })
        .collect()
}

/// Encode `psbt` bytes as `ur:crypto-psbt` QR part strings, UPPER-CASED so each QR uses the efficient
/// alphanumeric mode. One string when the PSBT fits a single fragment, else `seqLen` pure-fragment
/// parts a decoder loops over.
pub fn psbt_to_ur_parts(psbt: &[u8], max_fragment_len: usize) -> Vec<String> {
    ur_parts_lower("crypto-psbt", &crypto_psbt_message(psbt), max_fragment_len)
        .into_iter()
        .map(|s| s.to_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors derived from the published Blockchain Commons specs, BlockchainCommons/Research at
    // commit e4a4fbb186e2e7625ccdf7149aec4f0a5adaf850:
    // - BCR-2020-012 (Bytewords): the "brutal" payload + its CRC32, and the 256-word table.
    // - BCR-2020-005 (UR): the single-part `ur:seed` example, the longer seed, the 1-of-3 multi-part
    //   example part. The longer-seed message and fragment length were recovered by decoding those
    //   published strings with the (verified) word table; the ENCODER must reproduce the strings.
    const SEED_SHORT: &str = "a10150c7098580125e2ab0981253468b2dbc52";
    const SEED_LONG: &str = "a10158329d347f841a4e2ce6bc886e1aee74d82442b2f7649c606daedbad06cf8f0f73c8e834c2ebb7d2868d75820ab4fb4e45a1004c";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn crc32_matches_published_vectors() {
        assert_eq!(crc32(&hex("c7098580125e2ab0981253468b2dbc52")), 0xfeac_0dea);
        assert_eq!(crc32(&hex(SEED_SHORT)), 0x062d_eba4);
        assert_eq!(crc32(&hex(SEED_LONG)), 0x8810_9261);
    }

    #[test]
    fn bytewords_matches_the_brutal_vector() {
        // BCR-2020-012: payload c7..52 + CRC feac0dea encodes to this minimal Bytewords string.
        assert_eq!(
            bytewords(&hex("c7098580125e2ab0981253468b2dbc52")),
            "staslplabghydrpfmkbggufgludprfgmzepsbtwd"
        );
    }

    #[test]
    fn single_part_matches_the_seed_vectors() {
        assert_eq!(
            ur_parts_lower("seed", &hex(SEED_SHORT), 1000),
            vec!["ur:seed/oyadgdstaslplabghydrpfmkbggufgludprfgmamdpwmox"]
        );
        assert_eq!(
            ur_parts_lower("seed", &hex(SEED_LONG), 1000),
            vec!["ur:seed/oyadhdeynteelblrcygldwvarflojtcywyjytpdkfwprylienshnjnpluypmamtkmybsjkspvseesawmrltdlnlgkplfbkqzzoglfeoyaegslobemohs"]
        );
    }

    #[test]
    fn multi_part_pure_fragments_match_the_published_part() {
        // seed_long (54 bytes) with a 18-byte fragment -> 3 pure parts; part 1 is the BCR-2020-005
        // example. Parts 2 and 3 carry the next fragments (the last zero-padded), same seqLen/len/crc.
        let parts = ur_parts_lower("seed", &hex(SEED_LONG), 18);
        assert_eq!(parts.len(), 3);
        assert_eq!(
            parts[0],
            "ur:seed/1-3/lpadaxcsencylobemohsgmoyadhdeynteelblrcygldwvarflojtcywyjydmylgdsa"
        );
        assert!(parts[1].starts_with("ur:seed/2-3/"));
        assert!(parts[2].starts_with("ur:seed/3-3/"));
    }

    #[test]
    fn crypto_psbt_wraps_the_psbt_as_an_untagged_cbor_byte_string() {
        // 50-byte "psbt" -> CBOR byte string header 0x58 0x32, then the bytes (no map, no tag).
        let psbt = vec![0xab; 50];
        let msg = crypto_psbt_message(&psbt);
        assert_eq!(&msg[..2], &[0x58, 0x32]);
        assert_eq!(&msg[2..], &psbt[..]);
    }

    #[test]
    fn every_output_char_is_in_the_qr_alphanumeric_set() {
        // The QR alphanumeric mode (what the GUI asks qrcode.js for) accepts only these 45 chars. If
        // an output char ever fell outside, the encoder would silently drop to byte mode (denser,
        // harder to scan) or throw. Guard it for single-part, multi-part, and a size that forces a
        // 4-byte CBOR length header in the parts.
        const QR_ALNUM: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
        for psbt in [
            vec![0x00; 1],
            vec![0xff; 60],
            vec![0x5a; 400],
            vec![0x11; 70_000],
        ] {
            for part in psbt_to_ur_parts(&psbt, DEFAULT_MAX_FRAGMENT_LEN) {
                assert!(
                    part.chars().all(|c| QR_ALNUM.contains(c)),
                    "non-alphanumeric char in UR part: {part}"
                );
            }
        }
    }

    #[test]
    fn public_parts_are_uppercased_crypto_psbt_and_animate_when_large() {
        let small = psbt_to_ur_parts(&[0x07; 40], DEFAULT_MAX_FRAGMENT_LEN);
        assert_eq!(small.len(), 1);
        assert!(small[0].starts_with("UR:CRYPTO-PSBT/"), "{}", small[0]);

        let big = psbt_to_ur_parts(&[0x07; 500], DEFAULT_MAX_FRAGMENT_LEN);
        assert!(big.len() > 1, "a large PSBT animates across parts");
        assert!(big[0].starts_with(&format!("UR:CRYPTO-PSBT/1-{}/", big.len())));
        assert!(big
            .last()
            .unwrap()
            .starts_with(&format!("UR:CRYPTO-PSBT/{n}-{n}/", n = big.len())));
    }
}
