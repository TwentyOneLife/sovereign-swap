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

// ---- scan-back: multi-part fountain DECODE (#274 PR2, BCR-2024-001) ----

use bitcoin::hashes::{sha256, Hash};

/// Xoshiro256** PRNG (BCR-2024-001 fountain scheme), seeded from the SHA-256 of the seed bytes split
/// into four big-endian u64 words. Deterministic, so the decoder reproduces the exact fragment mixing a
/// compliant signer (SeedSigner, Sparrow, Shrike) used to fountain-code its reply.
struct Xoshiro256 {
    s: [u64; 4],
}

impl Xoshiro256 {
    fn from_digest(d: [u8; 32]) -> Self {
        let mut s = [0u64; 4];
        for (i, w) in s.iter_mut().enumerate() {
            *w = u64::from_be_bytes(d[i * 8..i * 8 + 8].try_into().unwrap());
        }
        Xoshiro256 { s }
    }
    fn from_bytes(seed: &[u8]) -> Self {
        Self::from_digest(sha256::Hash::hash(seed).to_byte_array())
    }
    /// Seed from a CRC32 value, `SHA256(BE(crc))`. Only the "Wolf" vector test exercises this seeding;
    /// the decoder seeds from `BE(seqNum) || BE(checksum)` via `from_bytes`.
    #[cfg(test)]
    fn from_crc32(crc: u32) -> Self {
        Self::from_bytes(&crc.to_be_bytes())
    }
    fn next(&mut self) -> u64 {
        let result = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }
    /// `next() / 2^64`, a Double in [0, 1) (BCR-2024-001).
    fn next_double(&mut self) -> f64 {
        self.next() as f64 / 18_446_744_073_709_551_616.0 // 2^64
    }
    /// `nextInt(lo..<hi)`: `floor(nextDouble * (hi - lo)) + lo`.
    fn next_int(&mut self, lo: usize, hi_exclusive: usize) -> usize {
        (self.next_double() * (hi_exclusive - lo) as f64) as usize + lo
    }
    /// `nextInt(lo...hi)`: inclusive upper bound. Used only by the "Wolf" vector test (the decoder uses
    /// the half-open `next_int` for the Fisher-Yates and degree draws).
    #[cfg(test)]
    fn next_int_closed(&mut self, lo: usize, hi: usize) -> usize {
        (self.next_double() * (hi - lo + 1) as f64) as usize + lo
    }
}

/// Walker-Vose alias sampler over fragment degrees 1..=`seq_len` with probability 1/d (BCR-2024-001
/// ss 5). Built once per decode; `choose_degree` samples from the part's own RNG.
struct DegreeChooser {
    prob: Vec<f64>,
    alias: Vec<usize>,
}

impl DegreeChooser {
    fn new(seq_len: usize) -> Self {
        let n = seq_len;
        let p: Vec<f64> = (1..=n).map(|d| 1.0 / d as f64).collect();
        let sum: f64 = p.iter().sum();
        // Scaled probabilities, partitioned into small (<1) and large (>=1). Indices are pushed from
        // n-1 down to 0 (the source reverses the index order), which the vectors depend on.
        let mut scaled: Vec<f64> = p.iter().map(|x| x * n as f64 / sum).collect();
        let (mut small, mut large): (Vec<usize>, Vec<usize>) = (Vec::new(), Vec::new());
        for i in (0..n).rev() {
            if scaled[i] < 1.0 {
                small.push(i);
            } else {
                large.push(i);
            }
        }
        let mut prob = vec![0.0f64; n];
        let mut alias = vec![0usize; n];
        while let (Some(a), Some(g)) = (small.last().copied(), large.last().copied()) {
            small.pop();
            large.pop();
            prob[a] = scaled[a];
            alias[a] = g;
            scaled[g] = (scaled[g] + scaled[a]) - 1.0;
            if scaled[g] < 1.0 {
                small.push(g);
            } else {
                large.push(g);
            }
        }
        for g in large {
            prob[g] = 1.0;
        }
        for a in small {
            prob[a] = 1.0;
        }
        DegreeChooser { prob, alias }
    }
    /// `chooseDegree = sample(rng) + 1`.
    fn choose_degree(&self, rng: &mut Xoshiro256) -> usize {
        let n = self.prob.len();
        let r1 = rng.next_double();
        let r2 = rng.next_double();
        let i = (n as f64 * r1) as usize;
        let i = i.min(n - 1);
        let chosen = if r2 < self.prob[i] { i } else { self.alias[i] };
        chosen + 1
    }
}

/// The set of fragment indices a part with `seq_num` mixes (BCR-2024-001 ss 6). A part with
/// `seq_num <= seq_len` is PURE (fragment `seq_num - 1`); a later part seeds its RNG from
/// `BE(seq_num) || BE(checksum)`, draws a degree, then partial-Fisher-Yates-picks that many indices.
fn choose_fragments(seq_num: u32, seq_len: usize, checksum: u32) -> Vec<usize> {
    if (seq_num as usize) <= seq_len {
        return vec![seq_num as usize - 1];
    }
    let mut seed = Vec::with_capacity(8);
    seed.extend_from_slice(&seq_num.to_be_bytes());
    seed.extend_from_slice(&checksum.to_be_bytes());
    let mut rng = Xoshiro256::from_bytes(&seed);
    let degree = DegreeChooser::new(seq_len).choose_degree(&mut rng);
    let mut remaining: Vec<usize> = (0..seq_len).collect();
    let mut chosen = Vec::with_capacity(degree);
    while chosen.len() != degree {
        let idx = rng.next_int(0, remaining.len());
        chosen.push(remaining.remove(idx));
    }
    chosen
}

/// A scan-back failure: the UR parts could not be decoded to a PSBT.
#[derive(Debug, PartialEq, Eq)]
pub enum UrError {
    Malformed(String),
}

impl std::fmt::Display for UrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UrError::Malformed(m) => write!(f, "{m}"),
        }
    }
}

/// Minimal-Bytewords-decode `s` (lower-case), verify the trailing 4-byte CRC32, and return the payload
/// without it. The reverse of `bytewords`: two chars per byte via the first+last letter of each word.
fn bytewords_decode(s: &str) -> Result<Vec<u8>, UrError> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) || b.len() < 10 {
        return Err(UrError::Malformed("bytewords: bad length".into()));
    }
    // Reverse lookup from the (verified) MINIMAL table: key = two ASCII chars, value = byte.
    let mut rev = [None; 1 << 16];
    for i in 0..256 {
        let key = ((MINIMAL[i * 2] as usize) << 8) | MINIMAL[i * 2 + 1] as usize;
        rev[key] = Some(i as u8);
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for k in (0..b.len()).step_by(2) {
        let key = ((b[k] as usize) << 8) | b[k + 1] as usize;
        match rev[key] {
            Some(v) => out.push(v),
            None => return Err(UrError::Malformed("bytewords: unknown pair".into())),
        }
    }
    let crc_at = out.len() - 4;
    let want = u32::from_be_bytes(out[crc_at..].try_into().unwrap());
    out.truncate(crc_at);
    if crc32(&out) != want {
        return Err(UrError::Malformed("bytewords: CRC mismatch".into()));
    }
    Ok(out)
}

/// A minimal CBOR cursor for exactly what a UR part uses: unsigned ints and byte strings.
struct CborCursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> CborCursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        CborCursor { b, i: 0 }
    }
    fn byte(&mut self) -> Result<u8, UrError> {
        let v = *self
            .b
            .get(self.i)
            .ok_or_else(|| UrError::Malformed("cbor: truncated".into()))?;
        self.i += 1;
        Ok(v)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], UrError> {
        let end = self
            .i
            .checked_add(n)
            .filter(|&e| e <= self.b.len())
            .ok_or_else(|| UrError::Malformed("cbor: truncated bytes".into()))?;
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }
    /// Read a length/value argument from the low 5 bits of an initial byte.
    fn arg(&mut self, info: u8) -> Result<u64, UrError> {
        match info {
            0..=23 => Ok(info as u64),
            24 => Ok(self.byte()? as u64),
            25 => Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64),
            26 => Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64),
            27 => Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())),
            _ => Err(UrError::Malformed("cbor: bad argument".into())),
        }
    }
    fn uint(&mut self) -> Result<u64, UrError> {
        let b = self.byte()?;
        if b >> 5 != 0 {
            return Err(UrError::Malformed("cbor: expected uint".into()));
        }
        self.arg(b & 0x1f)
    }
    fn bytes(&mut self) -> Result<Vec<u8>, UrError> {
        let b = self.byte()?;
        if b >> 5 != 2 {
            return Err(UrError::Malformed("cbor: expected byte string".into()));
        }
        let n = self.arg(b & 0x1f)? as usize;
        Ok(self.take(n)?.to_vec())
    }
}

/// The untagged `crypto-psbt` message (a CBOR byte string) to the PSBT bytes inside it.
fn message_to_psbt(message: &[u8]) -> Result<Vec<u8>, UrError> {
    CborCursor::new(message).bytes()
}

/// A parsed multi-part UR fragment: `[seqNum, seqLen, messageLen, checksum, data]`.
struct Part {
    seq_num: u32,
    seq_len: usize,
    message_len: usize,
    checksum: u32,
    data: Vec<u8>,
}

/// Decode a set of `ur:crypto-psbt` part strings (any case, pure or fountain-mixed) to the PSBT bytes,
/// or `Ok(None)` if more parts are still needed. A single-part UR decodes directly. This is the stateless
/// decode the scan-back endpoint runs over the growing set of frames the camera has read (#274 PR2).
pub fn decode_ur_psbt(parts: &[&str]) -> Result<Option<Vec<u8>>, UrError> {
    let mut decoder: Option<FountainDecoder> = None;
    for raw in parts {
        let lower = raw.trim().to_lowercase();
        let body = lower
            .strip_prefix("ur:crypto-psbt/")
            .ok_or_else(|| UrError::Malformed("not a ur:crypto-psbt part".into()))?;
        match body.split_once('/') {
            // Single-part: the body IS the message (no seq header).
            None => {
                let message = bytewords_decode(body)?;
                return Ok(Some(message_to_psbt(&message)?));
            }
            Some((_seq, frag)) => {
                let part_cbor = bytewords_decode(frag)?;
                let part = parse_part(&part_cbor)?;
                let dec = decoder.get_or_insert_with(|| FountainDecoder::new(&part));
                if let Some(message) = dec.receive(part)? {
                    return Ok(Some(message_to_psbt(&message)?));
                }
            }
        }
    }
    Ok(None)
}

fn parse_part(cbor: &[u8]) -> Result<Part, UrError> {
    let mut c = CborCursor::new(cbor);
    if c.byte()? != 0x85 {
        return Err(UrError::Malformed(
            "part: expected a 5-element array".into(),
        ));
    }
    let seq_num = c.uint()? as u32;
    let seq_len = c.uint()? as usize;
    let message_len = c.uint()? as usize;
    let checksum = c.uint()? as u32;
    let data = c.bytes()?;
    Ok(Part {
        seq_num,
        seq_len,
        message_len,
        checksum,
        data,
    })
}

/// Fountain decoder (BCR-2024-001 ss 11): accumulates pure and mixed fragments, reducing mixtures against
/// known fragments until every fragment is recovered, then reassembles and CRC-checks the message.
struct FountainDecoder {
    seq_len: usize,
    message_len: usize,
    checksum: u32,
    frag_len: usize,
    pure: Vec<Option<Vec<u8>>>,
    mixed: Vec<(Vec<usize>, Vec<u8>)>,
}

impl FountainDecoder {
    fn new(first: &Part) -> Self {
        FountainDecoder {
            seq_len: first.seq_len,
            message_len: first.message_len,
            checksum: first.checksum,
            frag_len: first.data.len(),
            pure: vec![None; first.seq_len],
            mixed: Vec::new(),
        }
    }

    /// Feed a part; returns the reassembled message once complete.
    fn receive(&mut self, part: Part) -> Result<Option<Vec<u8>>, UrError> {
        // A part that disagrees on the shared header is from a different message; ignore it.
        if part.seq_len != self.seq_len
            || part.message_len != self.message_len
            || part.checksum != self.checksum
            || part.data.len() != self.frag_len
        {
            return Ok(None);
        }
        let mut idx = choose_fragments(part.seq_num, self.seq_len, self.checksum);
        idx.sort_unstable();
        idx.dedup();
        let mut queue = vec![(idx, part.data)];
        while let Some(item) = queue.pop() {
            let reduced = self.reduce_by_pure(item);
            match reduced.0.len() {
                0 => {} // fully reduced away (already have all of it)
                1 => {
                    let i = reduced.0[0];
                    if self.pure[i].is_none() {
                        self.pure[i] = Some(reduced.1);
                        // A new pure fragment can simplify mixed parts; re-queue any that reduce.
                        let mut keep = Vec::new();
                        for m in std::mem::take(&mut self.mixed) {
                            let r = self.reduce_by_pure(m);
                            if r.0.len() <= 1 {
                                queue.push(r);
                            } else {
                                keep.push(r);
                            }
                        }
                        self.mixed = keep;
                    }
                }
                _ => {
                    if !self.mixed.iter().any(|(ix, _)| *ix == reduced.0) {
                        self.mixed.push(reduced);
                    }
                }
            }
        }
        if self.pure.iter().all(Option::is_some) {
            let mut message = Vec::with_capacity(self.seq_len * self.frag_len);
            for frag in self.pure.iter().flatten() {
                message.extend_from_slice(frag);
            }
            message.truncate(self.message_len);
            if crc32(&message) != self.checksum {
                return Err(UrError::Malformed("message CRC mismatch".into()));
            }
            return Ok(Some(message));
        }
        Ok(None)
    }

    /// Remove every already-known pure fragment from a mixture (XOR it out, drop its index).
    fn reduce_by_pure(&self, mut part: (Vec<usize>, Vec<u8>)) -> (Vec<usize>, Vec<u8>) {
        let mut remaining = Vec::with_capacity(part.0.len());
        for i in part.0 {
            match &self.pure[i] {
                Some(frag) => {
                    for (a, b) in part.1.iter_mut().zip(frag) {
                        *a ^= b;
                    }
                }
                None => remaining.push(i),
            }
        }
        part.0 = remaining;
        part
    }
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

#[cfg(test)]
mod fountain_rng_tests {
    use super::*;

    // BCR-2024-001 "Wolf" PRNG vectors: pin Xoshiro256**, the SHA-256 seeding, and nextInt.
    #[test]
    fn xoshiro_wolf_vectors() {
        assert_eq!(crc32(b"Wolf"), 0x598c_84dc);

        let mut r = Xoshiro256::from_bytes(b"Wolf");
        let got: Vec<u64> = (0..10).map(|_| r.next() % 100).collect();
        assert_eq!(got, vec![42, 81, 85, 8, 82, 84, 76, 73, 70, 88]);

        let mut r = Xoshiro256::from_crc32(crc32(b"Wolf"));
        let got: Vec<u64> = (0..10).map(|_| r.next() % 100).collect();
        assert_eq!(got, vec![88, 44, 94, 74, 0, 99, 7, 77, 68, 35]);

        let mut r = Xoshiro256::from_bytes(b"Wolf");
        let got: Vec<usize> = (0..10).map(|_| r.next_int_closed(1, 10)).collect();
        assert_eq!(got, vec![6, 5, 8, 4, 10, 5, 7, 10, 4, 9]);
    }
}

#[cfg(test)]
mod fountain_tests {
    use super::*;

    fn sample_psbt() -> Vec<u8> {
        (0..600u32)
            .map(|i| (i.wrapping_mul(7).wrapping_add(3)) as u8)
            .collect()
    }

    /// Build one UR part string (pure or fountain) from the message, exactly as a compliant encoder /
    /// signer would: the chosen fragments XORed, wrapped in the part CBOR, bytewords-encoded.
    fn part_string(
        msg: &[u8],
        seq_len: usize,
        frag_len: usize,
        checksum: u32,
        seq_num: u32,
    ) -> String {
        let mut data = vec![0u8; frag_len];
        for i in choose_fragments(seq_num, seq_len, checksum) {
            let start = i * frag_len;
            for (j, d) in data.iter_mut().enumerate() {
                if let Some(&mb) = msg.get(start + j) {
                    *d ^= mb;
                }
            }
        }
        let mut part = vec![0x85];
        cbor_uint(seq_num as u64, &mut part);
        cbor_uint(seq_len as u64, &mut part);
        cbor_uint(msg.len() as u64, &mut part);
        cbor_uint(checksum as u64, &mut part);
        cbor_bytes(&data, &mut part);
        format!("ur:crypto-psbt/{seq_num}-{seq_len}/{}", bytewords(&part)).to_uppercase()
    }

    // BCR-2024-001 shuffle vector: a partial Fisher-Yates draw with the Wolf RNG picks positions that,
    // over the published 1..=10 array, yield [6, 4, 9]. (choose_fragments draws the same positions over
    // its own 0-indexed fragment array; the round-trip tests below exercise that path end to end.)
    #[test]
    fn fisher_yates_matches_wolf_vector() {
        let mut rng = Xoshiro256::from_bytes(b"Wolf");
        let mut remaining: Vec<usize> = (1..=10).collect();
        let picks: Vec<usize> = (0..3)
            .map(|_| {
                let k = rng.next_int(0, remaining.len());
                remaining.remove(k)
            })
            .collect();
        assert_eq!(picks, vec![6, 4, 9]);
    }

    #[test]
    fn single_part_round_trips() {
        let psbt = vec![1u8, 2, 3, 4, 5];
        let parts = psbt_to_ur_parts(&psbt, 100);
        assert_eq!(parts.len(), 1);
        let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
        assert_eq!(decode_ur_psbt(&refs).unwrap(), Some(psbt));
    }

    #[test]
    fn pure_multipart_round_trips() {
        let psbt = sample_psbt();
        let parts = psbt_to_ur_parts(&psbt, 100);
        assert!(parts.len() > 1);
        let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
        assert_eq!(decode_ur_psbt(&refs).unwrap(), Some(psbt));
    }

    #[test]
    fn fountain_parts_reconstruct_omitted_pure_fragments() {
        let psbt = sample_psbt();
        let msg = crypto_psbt_message(&psbt);
        let max = 100usize;
        let seq_len = msg.len().div_ceil(max);
        let frag_len = msg.len().div_ceil(seq_len);
        let checksum = crc32(&msg);
        assert!(seq_len >= 3, "need several fragments to omit some");
        // All pure parts EXCEPT the last two, then many fountain parts to recover the omitted fragments.
        let mut strs: Vec<String> = (1..=(seq_len as u32 - 2))
            .map(|s| part_string(&msg, seq_len, frag_len, checksum, s))
            .collect();
        for s in (seq_len as u32 + 1)..=(seq_len as u32 + 60) {
            strs.push(part_string(&msg, seq_len, frag_len, checksum, s));
        }
        let refs: Vec<&str> = strs.iter().map(String::as_str).collect();
        assert_eq!(
            decode_ur_psbt(&refs).unwrap(),
            Some(psbt),
            "fountain reduction must recover the omitted pure fragments"
        );
    }

    #[test]
    fn incomplete_set_returns_none() {
        let psbt = sample_psbt();
        let parts = psbt_to_ur_parts(&psbt, 100);
        let one = [parts[0].as_str()]; // a single fragment of several is not enough
        assert_eq!(decode_ur_psbt(&one).unwrap(), None);
    }
}
