use itertools::Itertools;
use std::collections::HashMap;
use std::io::read_to_string;
use std::ops::Fn;

fn from_str_hex_to_u32(s: &str) -> u32 {
    u32::from_str_radix(s.strip_prefix("0X").unwrap(), 16).expect("Unable to parse integer")
}
fn from_str_hex_to_u8(s: &str) -> u8 {
    u8::from_str_radix(s.strip_prefix("0X").unwrap(), 16).expect("Unable to parse integer")
}

// Function that computes the most likely plaintext byte given a map of (iv, cipher) pairs
// and a function f(iv, cipher) -> plaintext
fn rc4_guess_m_for_iv(c: &HashMap<u32, u8>, f: impl Fn(u8, u8) -> u8) -> u8 {
    let freq = c
        .into_iter()
        .map(|(iv, c)| {
            let iv: u8 = (iv & 0xFF) as u8;
            let m = f(iv, *c);
            m
        })
        .into_group_map_by(|x| *x);

    freq.into_iter()
        .max_by(|x, y| x.1.len().cmp(&y.1.len()))
        .unwrap()
        .0
}

fn load_file(path: &str) -> HashMap<u32, u8> {
    let file = std::fs::File::open(path).expect("Unable to open file");
    let s = read_to_string(file).expect("Unable to read file");
    s.lines()
        .map(|x| {
            let line = x.split(" ").collect::<Vec<&str>>();
            let iv = from_str_hex_to_u32(line.get(0).unwrap());
            let cipher = from_str_hex_to_u8(line.get(1).unwrap());
            (iv, cipher)
        })
        .collect()
}

// Main attack function
fn attack_rc4(data: Vec<HashMap<u32, u8>>) -> (u8, Vec<u8>) {
    let iv01 = data.get(0).unwrap();
    let m0 = rc4_guess_m_for_iv(iv01, |iv, c| c ^ (iv.wrapping_add(2)));

    let mut key = vec![];

    for n in 3..16 {
        let d = n * (n + 1) / 2;
        let iv_map = data.get((n - 2) as usize).unwrap();
        let kn = rc4_guess_m_for_iv(&iv_map, |x, c| {
            let k_acc = key.iter().fold(0u8, |acc, &k| acc.wrapping_sub(k));
            (c ^ m0).wrapping_sub(x).wrapping_sub(d).wrapping_add(k_acc)
        });

        key.push(kn);
    }

    (m0, key)
}

fn rc4_encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = (0..=255).collect();
    let key_len = key.len();

    let mut j = 0;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key_len] as usize) % 256;
        s.swap(i, j);
    }

    let mut i = 0;
    j = 0;
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    for &byte in plaintext {
        i = (i + 1) % 256;
        j = (j + s[i] as usize) % 256;
        s.swap(i, j);
        let k = s[(s[i] as usize + s[j] as usize) % 256];
        ciphertext.push(byte ^ k);
    }

    ciphertext
}

// Generate a key with the given IV format: (z, 0xFF, x, 3, 4, ..., 15)
fn generate_key_with_iv(z: u8, x: u8) -> (u32, [u8; 16]) {
    let mut key = [0u8; 16];

    // 3 byte IV
    key[0] = z;
    key[1] = 0xFF;
    key[2] = x;

    for i in 3..16 {
        key[i] = i as u8;
    }

    (((z as u32) << 16) | 0x00FF00 | (x as u32), key)
}

// Generate synthetic data for a given z value
fn generate_iv_z_ff_x(z: u8) -> HashMap<u32, u8> {
    (0x00..=0xFF)
        .map(|x| {
            let (iv, key) = generate_key_with_iv(z, x);
            let plaintext = b"my super secret message";
            let ciphertext = rc4_encrypt(&key, plaintext);
            (iv, ciphertext[0])
        })
        .collect::<HashMap<_, _>>()
}

fn main() {
    assert_eq!(
        rc4_encrypt(b"Key", b"Plaintext"),
        vec![0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]
    );

    let lab_data: Vec<HashMap<u32, u8>> = (1..=1)
        .chain(3..16)
        .map(|z| load_file(&format!("data/bytes_{:02X}FFxx.dat", z)))
        .collect();

    println!(
        "Generate synthetic rc4 encrypted data with key [3, 4, 5, 6, 7, 8, 9, a, b, c, d, e, f]"
    );
    let synthetic_data = (1..=1)
        .chain(3..16)
        .map(|z| generate_iv_z_ff_x(z as u8))
        .collect::<Vec<_>>();

    assert_eq!(lab_data.len(), 14);
    assert_eq!(synthetic_data.len(), 14);

    let (m0, k) = attack_rc4(synthetic_data);
    println!("RC4 key for synthetic data: {:02x?}, {:02x?}", m0, k);
    let (m0, k) = attack_rc4(lab_data);
    println!("RC4 key for lab data: {:02x?}, {:02x?}", m0, k);
}
