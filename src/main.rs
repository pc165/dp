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

fn max_value_for_freq_map(freq: HashMap<u8, Vec<u8>>) -> u8 {
    freq.into_iter()
        .max_by(|x, y| x.1.len().cmp(&y.1.len()))
        .unwrap()
        .0
}

fn rc4_guess_m_for_iv(c: HashMap<u32, u8>, f: impl Fn(u8, u8) -> u8) -> u8 {
    let freq = c
        .into_iter()
        .map(|(iv, c)| {
            let iv: u8 = (iv & 0xFF) as u8;
            let m = f(iv, c);
            m
        })
        .into_group_map_by(|x| *x);

    let m = max_value_for_freq_map(freq);
    m
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

fn calc_d(i: u8) -> u8 {
    i * (i + 1) / 2
}

fn attack_rc4() -> (u8, Vec<u8>) {
    let iv01 = load_file("data/bytes_01FFxx.dat");
    let m0 = rc4_guess_m_for_iv(iv01, |iv, c| c ^ (iv.wrapping_add(2)));

    let mut key = vec![];
    println!("m[0] = {}\n", m0);
    for n in 3..16 {
        let d = calc_d(n);
        let iv_map = load_file(&format!("data/bytes_{:02X}FFxx.dat", n));
        let kn = rc4_guess_m_for_iv(iv_map, |x, c| {
            let k_acc = key.iter().fold(0u8, |acc, &k| acc.wrapping_sub(k));
            (c ^ m0).wrapping_sub(x).wrapping_sub(d).wrapping_add(k_acc)
        });

        println!("key[{}] = {}", n - 3, kn);
        key.push(kn);
    }

    (m0, key)
}

// KEY = 3 byte counter IV || 13 byte random
// for iv 0x01 -> c[0] = x + 2
// for iv 0x03 -> c[0] = x + 6 + k[0]
// for iv 0x04 -> c[0] = x + 10 + k[0] + k[1]
// for iv 0x0z -> c[0] = x + d[i] + k[0] + ... + k[i]

fn main() {
    assert_eq!(calc_d(3), 6);
    assert_eq!(calc_d(4), 10);

    let iv01 = load_file("data/bytes_01FFxx.dat");
    let m0 = rc4_guess_m_for_iv(iv01, |iv, c| c ^ iv.wrapping_add(2));

    let iv03 = load_file("data/bytes_03FFxx.dat");
    let k0 = rc4_guess_m_for_iv(iv03, |iv, c| (c ^ m0).wrapping_sub(iv).wrapping_sub(6));

    let iv04 = load_file("data/bytes_04FFxx.dat");
    let k1 = rc4_guess_m_for_iv(iv04, |iv, c| {
        (c ^ m0).wrapping_sub(iv).wrapping_sub(10).wrapping_sub(k0)
    });

    let (m0b, k) = attack_rc4();

    assert_eq!(m0b, m0);
    assert_eq!(k[0], k0);
    assert_eq!(k[1], k1);
}
