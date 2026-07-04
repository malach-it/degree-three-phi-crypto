use crate::block::{Block, BlockData};
use crate::did::{DidKeyBlock, DidKeySubmission, OwnershipProof, OwnershipProofError};
use blst::min_pk::SecretKey;

#[derive(Debug)]
pub struct Blockchain {
    pub chain: Vec<Block>,
    difficulty_bits: u8,
    amount_authority_key: SecretKey,
    amount_authority_did_key: String,
}

impl Blockchain {
    pub fn new(difficulty_bits: u8, amount_authority_key: SecretKey) -> Self {
        let amount_authority_did_key = crate::did::did_key_from_bls12_381_public_key(
            &amount_authority_key.sk_to_pk().compress(),
        );

        Self {
            chain: vec![Block::genesis(difficulty_bits)],
            difficulty_bits,
            amount_authority_key,
            amount_authority_did_key,
        }
    }

    pub fn add_public_key_block(
        &mut self,
        submissions: Vec<DidKeySubmission>,
        amount: u8,
        amount_authority_proof: OwnershipProof,
    ) -> Result<(), OwnershipProofError> {
        let records = submissions
            .into_iter()
            .map(DidKeySubmission::into_verified_record)
            .collect::<Result<Vec<_>, _>>()?;
        let previous_participant = self
            .chain
            .last()
            .and_then(|block| public_key_block(block))
            .and_then(|block| block.participant_did_key().ok())
            .map(str::to_string);
        let block = DidKeyBlock::new(
            records,
            amount,
            amount_authority_proof,
            &self.amount_authority_key,
            previous_participant.as_deref(),
        )?;

        self.add_block(BlockData::PublicKeys(block));
        Ok(())
    }

    pub fn public_key_blocks_are_valid(&self) -> bool {
        let mut previous_participant: Option<String> = None;

        for block in &self.chain {
            let BlockData::PublicKeys(block) = &block.data else {
                continue;
            };

            if block.verify_roles().is_err()
                || block.verify_supported_did_keys().is_err()
                || block
                    .verify_mining_proof(
                        &self.amount_authority_did_key,
                        previous_participant.as_deref(),
                    )
                    .is_err()
            {
                return false;
            }

            previous_participant = block.participant_did_key().ok().map(str::to_string);
        }

        true
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
            && self.public_key_blocks_are_valid()
            && self
                .chain
                .windows(2)
                .all(|blocks| blocks[1].is_valid_after(&blocks[0], self.difficulty_bits))
    }
}

fn public_key_block(block: &Block) -> Option<&DidKeyBlock> {
    match &block.data {
        BlockData::Genesis => None,
        BlockData::PublicKeys(block) => Some(block),
    }
}
