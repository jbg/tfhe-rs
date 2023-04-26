#![feature(iter_array_chunks)]

use std::{array, io::{Read, stdin}, iter};

use tfhe::{
    ConfigBuilder, FheUint32, generate_keys, set_server_key,
    prelude::{FheDecrypt, FheTryEncrypt, FheTrivialEncrypt},
};

fn main() -> Result<(), std::io::Error> {
    let mut buf = vec![];
    stdin().read_to_end(&mut buf)?;
    let hash = sha256_fhe(buf);
    println!("{}", hex::encode(&hash));
    Ok(())
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
    0x5be0cd19,
];

fn rotr(x: &FheUint32, n: u32) -> FheUint32 {
    (x >> n) | (x << (32u32 - n))
}

fn sha256_fhe<T: AsRef<[u8]>>(input: T) -> [u8; 32] {
    let config = ConfigBuilder::all_disabled()
        .enable_default_uint32()
        .build();
    let (client_key, server_key) = generate_keys(config);

    let len = input.as_ref().len();
    let remainder = (len + 9) % 64;
    let mut input: Vec<_> = input
        .as_ref()
        .into_iter()
        .copied()
        .chain(iter::once(0x80))
        .chain(iter::repeat(0x00).take(if remainder == 0 { 0 } else { 64 - remainder }))
        .chain(((len * 8) as u64).to_be_bytes())
        .array_chunks::<4>()
        .map(|bytes| FheUint32::try_encrypt(u32::from_be_bytes(bytes), &client_key).unwrap())
        .collect();

    set_server_key(server_key);

    let k = K.map(|x: u32| FheUint32::encrypt_trivial(x));
    let mut hash = INIT.map(|x: u32| FheUint32::encrypt_trivial(x));

    let all_ones = FheUint32::encrypt_trivial(0xffffffff_u32);
    let mut w: [_; 64] = array::from_fn(|_| FheUint32::encrypt_trivial(0_u32));

    for mut chunk in input.drain(..).array_chunks::<16>() {
        w[0..16].swap_with_slice(&mut chunk);

        for i in 16..64 {
            let s0 = rotr(&w[i - 15], 7) ^ rotr(&w[i - 15], 18) ^ (&w[i - 15] >> 3u32);
            let s1 = rotr(&w[i - 2], 17) ^ rotr(&w[i - 2], 19) ^ (&w[i - 2] >> 10u32);
            w[i] = &w[i - 16] + s0 + &w[i - 7] + s1;
        }

        let mut a = hash[0].clone();
        let mut b = hash[1].clone();
        let mut c = hash[2].clone();
        let mut d = hash[3].clone();
        let mut e = hash[4].clone();
        let mut f = hash[5].clone();
        let mut g = hash[6].clone();
        let mut h = hash[7].clone();

        for i in 0..64 {
            let s1 = rotr(&e, 6) ^ rotr(&e, 11) ^ rotr(&e, 25);
            let ch = (&e & &f) ^ ((&e ^ &all_ones) & &g);
            let t1 = h + s1 + ch + &k[i] + &w[i];
            let s0 = rotr(&a, 2) ^ rotr(&a, 13) ^ rotr(&a, 22);
            let maj = (&a & &b) ^ (&a & &c) ^ (&b & &c);
            let t2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + &t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }

    let decrypted_hash: Vec<u32> = hash
        .iter()
        .map(|ciphertext| FheUint32::decrypt(ciphertext, &client_key))
        .collect();
    
    let mut out = [0u8; 32];
    out[0..4].copy_from_slice(&decrypted_hash[0].to_be_bytes());
    out[4..8].copy_from_slice(&decrypted_hash[1].to_be_bytes());
    out[8..12].copy_from_slice(&decrypted_hash[2].to_be_bytes());
    out[12..16].copy_from_slice(&decrypted_hash[3].to_be_bytes());
    out[16..20].copy_from_slice(&decrypted_hash[4].to_be_bytes());
    out[20..24].copy_from_slice(&decrypted_hash[5].to_be_bytes());
    out[24..28].copy_from_slice(&decrypted_hash[6].to_be_bytes());
    out[28..32].copy_from_slice(&decrypted_hash[7].to_be_bytes());
    out
}
