use core::fmt::Write;

pub struct Sha256 {
    pub constants: [u32; 64],
    pub h: [u32; 8],
    pub hashes: [u32; 8],
    pub hash_string: String,
    pub blocks: Vec<Vec<u8>>,
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 {
            constants: [
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
                0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
                0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
                0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
                0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
                0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
                0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
                0xc67178f2,
            ],
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            hashes: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            hash_string: String::new(),
            blocks: vec![vec![]],
        }
    }
    pub fn hash(&mut self, message: &[u8]) {
        self.pad_and_segment_message(message);
        for i in &self.blocks {
            let mut w: [u32; 64] = [0; 64];
            for t in 0..16 {
                // Convert every 4 bytes into a u32 word
                let pos = t * 4; // Position in the byte array
                w[t] = u32::from_be_bytes([
                    i[pos],     // Byte 0
                    i[pos + 1], // Byte 1
                    i[pos + 2], // Byte 2
                    i[pos + 3], // Byte 3
                ]);
            }
            // Generate the remaining words of `W`
            for t in 16..64 {
                w[t] = self
                    .s_sig1(w[t - 2])
                    .wrapping_add(w[t - 7])
                    .wrapping_add(self.s_sig0(w[t - 15]))
                    .wrapping_add(w[t - 16]);
            }

            let mut a = self.hashes[0];
            let mut b = self.hashes[1];
            let mut c = self.hashes[2];
            let mut d = self.hashes[3];
            let mut e = self.hashes[4];
            let mut f = self.hashes[5];
            let mut g = self.hashes[6];
            let mut h = self.hashes[7];

            for t in 0..64 {
                let t1 = h
                    .wrapping_add(self.b_sig1(e))
                    .wrapping_add(self.ch(e, f, g))
                    .wrapping_add(self.constants[t])
                    .wrapping_add(w[t]);
                let t2 = self.b_sig0(a).wrapping_add(self.maj(a, b, c));
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
            self.hashes[0] = self.hashes[0].wrapping_add(a);
            self.hashes[1] = self.hashes[1].wrapping_add(b);
            self.hashes[2] = self.hashes[2].wrapping_add(c);
            self.hashes[3] = self.hashes[3].wrapping_add(d);
            self.hashes[4] = self.hashes[4].wrapping_add(e);
            self.hashes[5] = self.hashes[5].wrapping_add(f);
            self.hashes[6] = self.hashes[6].wrapping_add(g);
            self.hashes[7] = self.hashes[7].wrapping_add(h);
        }
        self.hash_string.clear();
        for num in &self.hashes {
            write!(self.hash_string, "{:08x}", num)
                .expect("Unable to write hashes to hash string.");
        }
    }
    pub fn pad_and_segment_message(&mut self, message: &[u8]) {
        let message_bit_length = message.len() as u64 * 8;
        let mut padded_message = Vec::from(message);

        // Step 1: Append "1" bit followed by "0" bits in byte form
        padded_message.push(0x80);

        // Calculate how many more zeros to add, excluding the final 64-bit length
        let total_length = padded_message.len() + 8; // +8 for the 64-bit length
        let padding_length = if total_length % 64 > 0 {
            64 - total_length % 64
        } else {
            0
        };
        padded_message.extend(vec![0x00; padding_length]);

        // Step 4: Append original length as 64-bit big-endian
        let message_length_bits = message_bit_length.to_be_bytes();
        padded_message.extend_from_slice(&message_length_bits);

        // Now segment into 512-bit (64-byte) blocks
        self.blocks = padded_message
            .chunks(64)
            .map(|chunk| chunk.to_vec())
            .collect();
    }
    fn ch(&self, x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    fn maj(&self, x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    fn b_sig0(&self, x: u32) -> u32 {
        let rotr_2 = x.rotate_right(2);
        let rotr_13 = x.rotate_right(13);
        let rotr_22 = x.rotate_right(22);
        rotr_2 ^ rotr_13 ^ rotr_22
    }

    fn b_sig1(&self, x: u32) -> u32 {
        let rotr_6 = x.rotate_right(6);
        let rotr_11 = x.rotate_right(11);
        let rotr_25 = x.rotate_right(25);
        rotr_6 ^ rotr_11 ^ rotr_25
    }

    fn s_sig0(&self, x: u32) -> u32 {
        let rotr_7 = x.rotate_right(7);
        let rotr_18 = x.rotate_right(18);
        let shr_3 = x >> 3;
        rotr_7 ^ rotr_18 ^ shr_3
    }

    fn s_sig1(&self, x: u32) -> u32 {
        let rotr_17 = x.rotate_right(17);
        let rotr_19 = x.rotate_right(19);
        let shr_10 = x >> 10;
        rotr_17 ^ rotr_19 ^ shr_10
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;
    use std::process::Command;
    #[test]
    fn test_pad_and_segment_message() {
        let mut sha256 = Sha256::new();

        let input = b"hello world"; // 11 bytes
        sha256.pad_and_segment_message(input);

        let total_padded_len =
            (input.len() as u64 + 1 /* for 0x80 */ + 8/* for the message length in bits */) * 8;
        let remaining_padding = (512 - total_padded_len % 512) % 512;
        let expected_block_size = 1 + 8 + 11 + (remaining_padding as usize) / 8; // Convert bits to bytes

        assert_eq!(
            sha256.blocks.len(),
            1,
            "There should be exactly one block for this input."
        );
        assert_eq!(
            sha256.blocks[0].len(),
            64,
            "Each block should be exactly 64 bytes."
        );
        assert_eq!(
            sha256.blocks[0].len() * 8,
            512,
            "Each block should be exactly 512 bits."
        );
        assert_eq!(
            sha256.blocks[0][0], 0x68,
            "First byte of the block should match 'h' in 'hello world'."
        );
        assert_eq!(
            sha256.blocks[0][1], 0x65,
            "Second byte of the block should match 'e' in 'hello world'."
        );
        assert_eq!(
            sha256.blocks[0][sha256.blocks[0].len() - 1],
            (input.len() as u64 * 8) as u8,
            "The last byte should represent the bit length of the original message."
        );
        let last_block = sha256.blocks.last().expect("Expected at least one block");
        // Convert the last 64 bits of the last block to a big-endian u64
        let last_64_bits = &last_block[last_block.len() - 8..];
        let message_len_bits = u64::from_be_bytes(
            last_64_bits
                .try_into()
                .expect("Slice with incorrect length"),
        );

        // Calculate the expected length in bits
        let expected_len_bits = (input.len() * 8) as u64;

        // Check that the first byte after the message is 0x80
        let padding_start_index = input.len(); // Index where padding starts
        assert_eq!(
            last_block[padding_start_index], 0x80,
            "Padding did not start with 0x80"
        );

        // Check that the last 64 bits correctly represent the message length
        assert_eq!(
            message_len_bits, expected_len_bits,
            "Incorrect message length encoding in the last block"
        );
    }
    #[test]
    fn success() {
        let input = "hello world";
        let mut sha256 = Sha256::new();

        sha256.hash(input.as_bytes());
        println!("Rust    hash: {}", &sha256.hash_string);

        let output = Command::new("sh")
            .arg("-c")
            .arg(format!("echo -n '{}' | openssl dgst -sha256", input))
            .output()
            .expect("Failed to execute command");

        let openssl_output = String::from_utf8_lossy(&output.stdout);
        let openssl_hash = openssl_output
            .split_whitespace()
            .last()
            .expect("Failed to parse OpenSSL output")
            .to_lowercase();

        println!("OpenSSL hash: {}", openssl_hash);

        assert_eq!(
            sha256.hash_string, openssl_hash,
            "Hashes do not match: Rust vs OpenSSL"
        );
    }
    #[test]
    fn test_sha256_known_vector() {
        let input = b"abc";
        let mut hasher = Sha256::new();
        hasher.hash(input);
        let hash_hex = hasher.hash_string;
        assert_eq!(
            hash_hex.as_str(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
