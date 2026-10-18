//! Ed25519 signatures (RFC 8032), `no_std` and allocation-free.
//!
//! Field and group arithmetic follow TweetNaCl (16 x 16-bit limbs, a
//! uniform Montgomery-ladder-style double-and-add). Curve constants were
//! derived from their definitions (`d = -121665/121666`, base point
//! `y = 4/5`, `sqrt(-1)`), not copied. Verification is stricter than
//! TweetNaCl: it rejects non-canonical `S` (`S >= L`) and public keys that
//! do not decode to a curve point.
//!
//! Not hardened against side channels beyond TweetNaCl's design (no
//! secret-dependent branches or indices in scalar multiplication).

use crate::sha512::Sha512;

type Gf = [i64; 16];

const GF0: Gf = [0; 16];
const GF1: Gf = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const D: Gf = [0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203];
const D2: Gf = [0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406];
const X: Gf = [0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169];
const Y: Gf = [0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666];
const I: Gf = [0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83];
/// Group order L = 2^252 + 27742317777372353535851937790883648493, little-endian bytes.
const L: [i64; 32] = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

fn car25519(o: &mut Gf) {
    for i in 0..16 {
        o[i] += 1 << 16;
        let c = o[i] >> 16;
        if i < 15 {
            o[i + 1] += c - 1;
        } else {
            o[0] += 38 * (c - 1);
        }
        o[i] -= c << 16;
    }
}

/// Swap `p` and `q` when `b == 1` (no branch on `b`).
fn sel25519(p: &mut Gf, q: &mut Gf, b: i64) {
    let c = !(b - 1);
    for i in 0..16 {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

fn pack25519(n: &Gf) -> [u8; 32] {
    let mut t = *n;
    car25519(&mut t);
    car25519(&mut t);
    car25519(&mut t);
    let mut m = GF0;
    for _ in 0..2 {
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(&mut t, &mut m, 1 - b);
    }
    let mut o = [0u8; 32];
    for i in 0..16 {
        o[2 * i] = (t[i] & 0xff) as u8;
        o[2 * i + 1] = (t[i] >> 8) as u8;
    }
    o
}

fn neq25519(a: &Gf, b: &Gf) -> bool {
    pack25519(a) != pack25519(b)
}

fn par25519(a: &Gf) -> u8 {
    pack25519(a)[0] & 1
}

fn unpack25519(n: &[u8; 32]) -> Gf {
    let mut o = GF0;
    for i in 0..16 {
        o[i] = n[2 * i] as i64 + ((n[2 * i + 1] as i64) << 8);
    }
    o[15] &= 0x7fff;
    o
}

fn add_gf(a: &Gf, b: &Gf) -> Gf {
    core::array::from_fn(|i| a[i] + b[i])
}

fn sub_gf(a: &Gf, b: &Gf) -> Gf {
    core::array::from_fn(|i| a[i] - b[i])
}

fn mul_gf(a: &Gf, b: &Gf) -> Gf {
    let mut t = [0i64; 31];
    for i in 0..16 {
        for j in 0..16 {
            t[i + j] += a[i] * b[j];
        }
    }
    for i in 0..15 {
        t[i] += 38 * t[i + 16];
    }
    let mut o: Gf = core::array::from_fn(|i| t[i]);
    car25519(&mut o);
    car25519(&mut o);
    o
}

fn sq_gf(a: &Gf) -> Gf {
    mul_gf(a, a)
}

fn inv25519(i: &Gf) -> Gf {
    let mut c = *i;
    for a in (0..=253).rev() {
        c = sq_gf(&c);
        if a != 2 && a != 4 {
            c = mul_gf(&c, i);
        }
    }
    c
}

fn pow2523(i: &Gf) -> Gf {
    let mut c = *i;
    for a in (0..=250).rev() {
        c = sq_gf(&c);
        if a != 1 {
            c = mul_gf(&c, i);
        }
    }
    c
}

/// Extended coordinates (X, Y, Z, T).
type Point = [Gf; 4];

fn point_add(p: &mut Point, q: &Point) {
    let a = mul_gf(&sub_gf(&p[1], &p[0]), &sub_gf(&q[1], &q[0]));
    let b = mul_gf(&add_gf(&p[0], &p[1]), &add_gf(&q[0], &q[1]));
    let c = mul_gf(&mul_gf(&p[3], &q[3]), &D2);
    let d = mul_gf(&p[2], &q[2]);
    let d = add_gf(&d, &d);
    let e = sub_gf(&b, &a);
    let f = sub_gf(&d, &c);
    let g = add_gf(&d, &c);
    let h = add_gf(&b, &a);
    p[0] = mul_gf(&e, &f);
    p[1] = mul_gf(&h, &g);
    p[2] = mul_gf(&g, &f);
    p[3] = mul_gf(&e, &h);
}

fn cswap(p: &mut Point, q: &mut Point, b: u8) {
    for i in 0..4 {
        sel25519(&mut p[i], &mut q[i], b as i64);
    }
}

fn pack_point(p: &Point) -> [u8; 32] {
    let zi = inv25519(&p[2]);
    let tx = mul_gf(&p[0], &zi);
    let ty = mul_gf(&p[1], &zi);
    let mut r = pack25519(&ty);
    r[31] ^= par25519(&tx) << 7;
    r
}

fn scalarmult(q: &mut Point, s: &[u8; 32]) -> Point {
    let mut p: Point = [GF0, GF1, GF1, GF0];
    for i in (0..256).rev() {
        let b = (s[i / 8] >> (i & 7)) & 1;
        cswap(&mut p, q, b);
        let pc = p;
        point_add(q, &pc);
        let pc = p;
        point_add(&mut p, &pc);
        cswap(&mut p, q, b);
    }
    p
}

fn scalarbase(s: &[u8; 32]) -> Point {
    let mut q: Point = [X, Y, GF1, mul_gf(&X, &Y)];
    scalarmult(&mut q, s)
}

/// Reduce a 64-byte little-endian integer modulo L.
fn mod_l(x: &mut [i64; 64]) -> [u8; 32] {
    for i in (32..64).rev() {
        let mut carry = 0;
        let mut j = i - 32;
        while j < i - 12 {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
            j += 1;
        }
        x[j] += carry;
        x[i] = 0;
    }
    let mut carry = 0;
    for j in 0..32 {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for j in 0..32 {
        x[j] -= carry * L[j];
    }
    let mut r = [0u8; 32];
    for i in 0..32 {
        x[i + 1] += x[i] >> 8;
        r[i] = (x[i] & 255) as u8;
    }
    r
}

fn reduce(h: &[u8; 64]) -> [u8; 32] {
    let mut x: [i64; 64] = core::array::from_fn(|i| h[i] as i64);
    mod_l(&mut x)
}

fn hash_to_scalar(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    reduce(&h.finalize())
}

/// An Ed25519 key pair derived from a 32-byte secret seed.
#[derive(Clone)]
pub struct Keypair {
    /// Clamped secret scalar `a` and the hash prefix used for nonces.
    scalar: [u8; 32],
    prefix: [u8; 32],
    pub public: [u8; PUBLIC_KEY_LEN],
}

impl Keypair {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut h = Sha512::new();
        h.update(seed);
        let d = h.finalize();
        let mut scalar: [u8; 32] = d[..32].try_into().unwrap();
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
        let prefix: [u8; 32] = d[32..].try_into().unwrap();
        let public = pack_point(&scalarbase(&scalar));
        Self { scalar, prefix, public }
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
        let r = hash_to_scalar(&[&self.prefix, msg]);
        let big_r = pack_point(&scalarbase(&r));
        let h = hash_to_scalar(&[&big_r, &self.public, msg]);
        let mut x = [0i64; 64];
        for i in 0..32 {
            x[i] = r[i] as i64;
        }
        for i in 0..32 {
            for j in 0..32 {
                x[i + j] += h[i] as i64 * self.scalar[j] as i64;
            }
        }
        let s = mod_l(&mut x);
        let mut sig = [0u8; SIGNATURE_LEN];
        sig[..32].copy_from_slice(&big_r);
        sig[32..].copy_from_slice(&s);
        sig
    }
}

impl Drop for Keypair {
    fn drop(&mut self) {
        // Best-effort wipe of secret material.
        for b in self.scalar.iter_mut().chain(self.prefix.iter_mut()) {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
    }
}

/// Decode `-A` from an encoded public key (None if not on the curve).
fn unpack_neg(p: &[u8; 32]) -> Option<Point> {
    let mut r: Point = [GF0, GF0, GF1, GF0];
    r[1] = unpack25519(p);
    let num = sq_gf(&r[1]);
    let den = mul_gf(&num, &D);
    let num = sub_gf(&num, &r[2]);
    let den = add_gf(&r[2], &den);
    let den2 = sq_gf(&den);
    let den4 = sq_gf(&den2);
    let den6 = mul_gf(&den4, &den2);
    let mut t = mul_gf(&mul_gf(&den6, &num), &den);
    t = pow2523(&t);
    t = mul_gf(&mul_gf(&mul_gf(&t, &num), &den), &den);
    r[0] = mul_gf(&t, &den);
    let chk = mul_gf(&sq_gf(&r[0]), &den);
    if neq25519(&chk, &num) {
        r[0] = mul_gf(&r[0], &I);
    }
    let chk = mul_gf(&sq_gf(&r[0]), &den);
    if neq25519(&chk, &num) {
        return None;
    }
    if par25519(&r[0]) == p[31] >> 7 {
        r[0] = sub_gf(&GF0, &r[0]);
    }
    r[3] = mul_gf(&r[0], &r[1]);
    Some(r)
}

/// True when `S` (little-endian) is below the group order L.
fn scalar_is_canonical(s: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        let (a, b) = (s[i] as i64, L[i]);
        if a != b {
            return a < b;
        }
    }
    false // equal to L
}

/// Verify `sig` over `msg` under `public`.
pub fn verify(public: &[u8; PUBLIC_KEY_LEN], msg: &[u8], sig: &[u8; SIGNATURE_LEN]) -> bool {
    let s: [u8; 32] = sig[32..].try_into().unwrap();
    if !scalar_is_canonical(&s) {
        return false;
    }
    let Some(mut neg_a) = unpack_neg(public) else {
        return false;
    };
    let h = hash_to_scalar(&[&sig[..32], public, msg]);
    // R' = [h](-A) + [S]B must equal R.
    let mut p = scalarmult(&mut neg_a, &h);
    let sb = scalarbase(&s);
    point_add(&mut p, &sb);
    pack_point(&p) == sig[..32]
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let v: std::vec::Vec<u8> = (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }

    fn unhex_vec(s: &str) -> std::vec::Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    /// RFC 8032 section 7.1, tests 1-3: (secret seed, public key, message, signature).
    const VECTORS: [(&str, &str, &str, &str); 3] = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ];

    #[test]
    fn rfc8032_public_keys_and_signatures() {
        for (seed, public, msg, sig) in VECTORS {
            let kp = Keypair::from_seed(&unhex::<32>(seed));
            assert_eq!(kp.public, unhex::<32>(public), "public key for seed {seed}");
            let m = unhex_vec(msg);
            let s = kp.sign(&m);
            assert_eq!(s, unhex::<64>(sig), "signature for seed {seed}");
            assert!(verify(&kp.public, &m, &s));
        }
    }

    #[test]
    fn rejects_modified_message_signature_and_key() {
        let (seed, _, msg, sig) = VECTORS[2];
        let kp = Keypair::from_seed(&unhex::<32>(seed));
        let m = unhex_vec(msg);
        let s = unhex::<64>(sig);
        assert!(verify(&kp.public, &m, &s));
        let mut m2 = m.clone();
        m2[0] ^= 1;
        assert!(!verify(&kp.public, &m2, &s), "modified message");
        for i in [0, 31, 32, 63] {
            let mut s2 = s;
            s2[i] ^= 1;
            assert!(!verify(&kp.public, &m, &s2), "modified signature byte {i}");
        }
        let other = Keypair::from_seed(&[7; 32]);
        assert!(!verify(&other.public, &m, &s), "wrong key");
    }

    #[test]
    fn rejects_non_canonical_s() {
        let (seed, _, msg, sig) = VECTORS[0];
        let kp = Keypair::from_seed(&unhex::<32>(seed));
        let m = unhex_vec(msg);
        let mut s = unhex::<64>(sig);
        // S + L is the same scalar mod L but must be rejected (malleability).
        let mut carry = 0i64;
        for i in 0..32 {
            let v = s[32 + i] as i64 + L[i] + carry;
            s[32 + i] = (v & 0xff) as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0);
        assert!(!verify(&kp.public, &m, &s));
    }

    #[test]
    fn sign_verify_roundtrip_longer_message() {
        let kp = Keypair::from_seed(&[42; 32]);
        let msg: std::vec::Vec<u8> = (0..1000u32).map(|i| (i * 13) as u8).collect();
        let s = kp.sign(&msg);
        assert!(verify(&kp.public, &msg, &s));
    }
}
