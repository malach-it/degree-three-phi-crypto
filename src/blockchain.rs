use crate::block::{Block, BlockData};
use crate::did::{DidKeyRecord, OwnershipProof, OwnershipProofError, PublicJwk};

#[derive(Debug)]
pub struct Blockchain {
    pub chain: Vec<Block>,
    difficulty_bits: u8,
}

impl Blockchain {
    pub fn new(difficulty_bits: u8) -> Self {
        Self {
            chain: vec![Block::genesis(difficulty_bits)],
            difficulty_bits,
        }
    }

    pub fn add_public_key_block(
        &mut self,
        did_key: impl Into<String>,
        public_jwk: PublicJwk,
        proof: OwnershipProof,
    ) -> Result<(), OwnershipProofError> {
        let record = DidKeyRecord::new(did_key, public_jwk);

        record.verify_did_matches_public_key()?;
        record.public_jwk.verify_ownership(&proof)?;
        self.add_block(BlockData::PublicKey(record));
        Ok(())
    }

    pub fn public_key_blocks_match_dids(&self) -> bool {
        self.chain.iter().all(|block| match &block.data {
            BlockData::Genesis => true,
            BlockData::PublicKey(record) => record.verify_did_matches_public_key().is_ok(),
        })
    }

    fn add_block(&mut self, data: BlockData) {
        let previous = self.chain.last().expect("blockchain has a genesis block");
        let block = Block::mine(
            previous.index + 1,
            data,
            previous.hash.clone(),
            self.difficulty_bits,
        );

        self.chain.push(block);
    }

    pub fn is_valid(&self) -> bool {
        let Some(genesis) = self.chain.first() else {
            return false;
        };

        genesis.index == 0
            && genesis.previous_hash == "0".repeat(64)
            && genesis.hash == genesis.recalculate_hash()
            && genesis.proves_square(self.difficulty_bits)
            && self.public_key_blocks_match_dids()
            && self
                .chain
                .windows(2)
                .all(|blocks| blocks[1].is_valid_after(&blocks[0], self.difficulty_bits))
    }
}
