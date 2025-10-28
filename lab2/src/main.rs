const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

#[derive(Debug)]
struct MD5 {
    pub state: [u32; 4],
    pub count: u64,
    pub buffer: Vec<u8>,
}

impl MD5 {
    fn new() -> Self {
        MD5 {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            count: 0,
            buffer: Vec::new(),
        }
    }

    fn process_block(&mut self, block: &[u8]) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];

        for i in 0..64 {
            let (mut f, g);

            match i {
                0..=15 => {
                    f = (b & c) | (!b & d);
                    g = i;
                }
                16..=31 => {
                    f = (b & d) | (!d & c);
                    g = (5 * i + 1) % 16;
                }
                32..=47 => {
                    f = b ^ c ^ d;
                    g = (3 * i + 5) % 16;
                }
                48..=63 => {
                    f = c ^ (b | !d);
                    g = (7 * i) % 16
                }
                _ => panic!("Invalid index"),
            };

            f = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }

    fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
        self.count += data.len() as u64;

        while self.buffer.len() >= 64 {
            let block: Vec<u8> = self.buffer.drain(..64).collect();
            self.process_block(&block);
        }
    }

    fn finalize(&mut self) -> [u8; 16] {
        let bit_len = self.count * 8;

        self.buffer.push(0x80);

        // Pad to 56 bytes mod 64
        while self.buffer.len() % 64 != 56 {
            self.buffer.push(0x00);
        }

        // Append length in bits as 64-bit little-endian
        self.buffer.extend_from_slice(&bit_len.to_le_bytes());

        // Process remaining blocks
        while self.buffer.len() >= 64 {
            let block: Vec<u8> = self.buffer.drain(..64).collect();
            self.process_block(&block);
        }

        // Produce final hash
        let mut result = [0u8; 16];
        for i in 0..4 {
            let bytes = self.state[i].to_le_bytes();
            result[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }

        // self.debug();

        result
    }

    fn digest_hex(data: &[u8]) -> String {
        let mut md5 = MD5::new();
        md5.update(data);
        let hash = md5.finalize();

        hash.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }

    fn debug(&self) {
        println!("{:?}", self);
    }

    fn hmac(key: &[u8], data: &[u8]) -> [u8; 16] {
        let mut key_clone = key.to_vec();
        key_clone.extend_from_slice(data);
        let mut md5 = MD5::new();
        md5.update(&key_clone);
        let hash = md5.finalize();
        hash
    }
}

#[test]
fn test_md5() {
    vec![
        ("", "d41d8cd98f00b204e9800998ecf8427e"),
        ("a", "0cc175b9c0f1b6a831c399e269772661"),
        ("abc", "900150983cd24fb0d6963f7d28e17f72"),
        ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (
            "abcdefghijklmnopqrstuvwxyz",
            "c3fcd3d76192e4007dfb496cca67e13b",
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "d174ab98d277d9f5a5611c2c9f419d9f",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "57edf4a22be3c955ac49da2e2107b67a",
        ),
    ]
    .into_iter()
    .for_each(|(input, expected)| {
        let result = MD5::digest_hex(input.as_bytes());
        assert_eq!(result, expected);
    });
}

fn prolongation_attack(
    tag: [u8; 16],
    key_length: usize,
    msg: &[u8],
    new_msg: &[u8],
) -> ([u8; 16], Vec<u8>) {
    // calculate padding for original message
    let mut msg_padded = msg.to_vec();
    msg_padded.extend_from_slice(&[0x80]);

    while (msg_padded.len() + key_length) % 64 != 56 {
        msg_padded.push(0x00);
    }

    let original_len = (msg.len() + key_length) as u64 * 8;
    msg_padded.extend_from_slice(&original_len.to_le_bytes());

    // reconstruct internal state from tag
    let mut md5 = MD5::new();
    md5.state[0] = u32::from_le_bytes([tag[0], tag[1], tag[2], tag[3]]);
    md5.state[1] = u32::from_le_bytes([tag[4], tag[5], tag[6], tag[7]]);
    md5.state[2] = u32::from_le_bytes([tag[8], tag[9], tag[10], tag[11]]);
    md5.state[3] = u32::from_le_bytes([tag[12], tag[13], tag[14], tag[15]]);

    // calculate total for padded message
    md5.count = (msg_padded.len() + key_length) as u64;

    // md5.debug();

    // process new message
    md5.update(&new_msg);

    let hash = md5.finalize();
    msg_padded.extend_from_slice(&new_msg);

    (hash, msg_padded)
}

fn to_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let key = "Aaaaaa";
    let msg = [b'A', b'A'];
    let msg2 = [b'B', b'B'];
    println!("key 0x{}", to_hex_string(key.as_bytes()));
    println!("original message 0x{}", to_hex_string(&msg));
    println!("message to append 0x{}", to_hex_string(&msg2));

    let tag = MD5::hmac(key.as_bytes(), &msg);
    println!("original tag 0x{}", to_hex_string(&tag));

    let (forged_tag, msg_forged) = prolongation_attack(tag, key.len(), &msg, &msg2);
    println!("forged tag 0x{}", to_hex_string(&forged_tag));
    println!("forged msg 0x{}", to_hex_string(&msg_forged));

    let actual_tag = MD5::hmac(key.as_bytes(), &msg_forged);
    println!("actual tag 0x{}", to_hex_string(&actual_tag));

    assert_eq!(forged_tag, actual_tag);
}
