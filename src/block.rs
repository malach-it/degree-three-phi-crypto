use crate::did::DidKeyRecord;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct Block {
    pub index: u64,
    pub timestamp: u64,
    pub data: BlockData,
    pub previous_hash: String,
    pub nonce: u64,
    pub hash: String,
    pub proof_square: u128,
}

#[derive(Debug, Clone)]
pub enum BlockData {
    Genesis,
    PublicKey(DidKeyRecord),
}

impl BlockData {
    fn canonical_bytes(&self) -> Vec<u8> {
        match self {
            Self::Genesis => b"type=genesis".to_vec(),
            Self::PublicKey(record) => record.canonical_bytes(),
        }
    }
}

impl Block {
    pub fn genesis(difficulty_bits: u8) -> Self {
        Self::mine(0, BlockData::Genesis, "0".repeat(64), difficulty_bits)
    }

    pub fn mine(index: u64, data: BlockData, previous_hash: String, difficulty_bits: u8) -> Self {
        assert!(
            (1..=128).contains(&difficulty_bits),
            "difficulty_bits must be between 1 and 128"
        );

        let timestamp = unix_timestamp();
        let mut nonce = 0;

        loop {
            let hash_bytes = calculate_hash_bytes(index, timestamp, &data, &previous_hash, nonce);
            let proof_square = leading_bits_as_u128(&hash_bytes, difficulty_bits);

            if is_perfect_square(proof_square) {
                return Self {
                    index,
                    timestamp,
                    data,
                    previous_hash,
                    nonce,
                    hash: bytes_to_hex(&hash_bytes),
                    proof_square,
                };
            }

            nonce += 1;
        }
    }

    pub fn is_valid_after(&self, previous: &Block, difficulty_bits: u8) -> bool {
        self.index == previous.index + 1
            && self.previous_hash == previous.hash
            && self.hash == self.recalculate_hash()
            && self.proves_square(difficulty_bits)
    }

    pub fn recalculate_hash(&self) -> String {
        bytes_to_hex(&calculate_hash_bytes(
            self.index,
            self.timestamp,
            &self.data,
            &self.previous_hash,
            self.nonce,
        ))
    }

    pub fn proves_square(&self, difficulty_bits: u8) -> bool {
        let hash_bytes = calculate_hash_bytes(
            self.index,
            self.timestamp,
            &self.data,
            &self.previous_hash,
            self.nonce,
        );
        let proof_square = leading_bits_as_u128(&hash_bytes, difficulty_bits);

        self.proof_square == proof_square && is_perfect_square(proof_square)
    }
}

fn calculate_hash_bytes(
    index: u64,
    timestamp: u64,
    data: &BlockData,
    previous_hash: &str,
    nonce: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    hasher.update(index.to_be_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.update(data.canonical_bytes());
    hasher.update(previous_hash.as_bytes());
    hasher.update(nonce.to_be_bytes());

    hasher.finalize().into()
}

fn leading_bits_as_u128(bytes: &[u8; 32], bit_count: u8) -> u128 {
    let mut value = 0u128;

    for bit_index in 0..bit_count {
        let byte = bytes[(bit_index / 8) as usize];
        let bit = (byte >> (7 - (bit_index % 8))) & 1;
        value = (value << 1) | u128::from(bit);
    }

    value
}

pub fn is_perfect_square(value: u128) -> bool {
    let root = (value as f64).sqrt() as u128;

    root * root == value || (root + 1) * (root + 1) == value
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 0x0f) as usize] as char);
    }

    hex
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs()
}
