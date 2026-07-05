use crate::block::{Block, BlockData};
use crate::did::{DidKeyBlock, DidKeySubmission, OwnershipProofError};
use blst::min_pk::SecretKey;

#[derive(Debug)]
pub struct Blockchain {
    pub chain: Vec<Block>,
    difficulty_bits: u8,
    amount_authority_key: SecretKey,
    amount_authority_did_key: String,
    public_key_state: PublicKeyState,
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
            public_key_state: PublicKeyState::default(),
        }
    }

    pub fn add_public_key_block(
        &mut self,
        submissions: Vec<DidKeySubmission>,
        amount: u8,
        degree_three_phi_token: String,
    ) -> Result<(), OwnershipProofError> {
        let records = submissions
            .into_iter()
            .map(DidKeySubmission::into_verified_record)
            .collect::<Result<Vec<_>, _>>()?;
        let previous_state = self.public_key_state.clone();
        let amount_tokens = crate::did::amount_tokens_for_records(
            &records,
            amount,
            &crate::did::amount_token_group_for_block(
                &records,
                amount,
                &self.amount_authority_did_key,
                previous_state.participant_did_key.as_deref(),
                previous_state.amount,
                previous_state.participant_amount_token.as_deref(),
            )?,
        )?;
        let participant_did_key = participant_did_key_for_records(&records)?.to_string();
        let block = DidKeyBlock::new(
            records,
            amount,
            degree_three_phi_token,
            &self.amount_authority_key,
            previous_state.participant_did_key.as_deref(),
            previous_state.amount,
            previous_state.participant_amount_token.as_deref(),
        )?;

        self.add_block(BlockData::PublicKeys(block));
        self.public_key_state = PublicKeyState {
            participant_did_key: Some(participant_did_key),
            amount: Some(amount),
            participant_amount_token: Some(amount_tokens.participant),
        };
        Ok(())
    }

    pub fn public_key_blocks_are_valid(&self) -> bool {
        for block in &self.chain {
            let BlockData::PublicKeys(block) = &block.data else {
                continue;
            };

            if block
                .verify_mining_proof(&self.amount_authority_did_key)
                .is_err()
            {
                return false;
            }
        }

        true
    }

    #[allow(dead_code)]
    pub fn current_participant_did_key(&self) -> Option<&str> {
        self.public_key_state.participant_did_key.as_deref()
    }

    #[allow(dead_code)]
    pub fn current_amount(&self) -> Option<u8> {
        self.public_key_state.amount
    }

    #[allow(dead_code)]
    pub fn current_participant_amount_token(&self) -> Option<&str> {
        self.public_key_state.participant_amount_token.as_deref()
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

#[derive(Debug, Clone, Default)]
struct PublicKeyState {
    participant_did_key: Option<String>,
    amount: Option<u8>,
    participant_amount_token: Option<String>,
}

fn participant_did_key_for_records(
    records: &[crate::did::DidKeyRecord],
) -> Result<&str, OwnershipProofError> {
    records
        .iter()
        .find(|record| record.role == crate::did::DidRole::Participant)
        .map(|record| record.did_key.as_str())
        .ok_or(OwnershipProofError::WrongParticipantCount {
            expected: 1,
            actual: 0,
        })
}
