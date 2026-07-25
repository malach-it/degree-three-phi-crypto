use crate::block::{Block, BlockData};
use crate::did::{DidKeyBlock, DidKeySubmission, OwnershipProofError};
use blst::min_pk::SecretKey;
use std::collections::HashMap;

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

    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    pub fn add_public_key_block_with_disclosure(
        &mut self,
        submissions: Vec<DidKeySubmission>,
        amount: u8,
        degree_three_phi_token: String,
        disclosure_commitment: &str,
        disclosure_group_id: &str,
        disclosure_hop: u8,
        disclosure_max_depth: u8,
        previous_participant_did_key: Option<&str>,
        previous_participant_amount: Option<u8>,
        previous_participant_amount_token: Option<&str>,
    ) -> Result<(), OwnershipProofError> {
        let records = submissions
            .into_iter()
            .map(DidKeySubmission::into_verified_record)
            .collect::<Result<Vec<_>, _>>()?;
        let block = DidKeyBlock::new_with_disclosure_commitment(
            records,
            amount,
            degree_three_phi_token,
            &self.amount_authority_key,
            previous_participant_did_key,
            previous_participant_amount,
            previous_participant_amount_token,
            Some(disclosure_commitment),
            Some(disclosure_group_id),
            Some(disclosure_hop),
            Some(disclosure_max_depth),
        )?;
        self.add_block(BlockData::PublicKeys(block));
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

        disclosure_transitions_are_valid(self.chain.iter().filter_map(|block| match &block.data {
            BlockData::PublicKeys(block) => Some(block),
            _ => None,
        }))
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

#[derive(Debug, Clone, Copy)]
struct DisclosureGroupState<'a> {
    commitment: &'a str,
    hop: u8,
    max_depth: u8,
}

fn disclosure_transitions_are_valid<'a>(blocks: impl IntoIterator<Item = &'a DidKeyBlock>) -> bool {
    let mut groups: HashMap<&str, DisclosureGroupState<'_>> = HashMap::new();

    for block in blocks {
        let (commitment, group_id, hop, max_depth) = match (
            block.disclosure_commitment.as_deref(),
            block.disclosure_group_id.as_deref(),
            block.disclosure_hop,
            block.disclosure_max_depth,
        ) {
            (None, None, None, None) => continue,
            (Some(commitment), Some(group_id), Some(hop), Some(max_depth)) => {
                (commitment, group_id, hop, max_depth)
            }
            _ => return false,
        };

        if hop > max_depth {
            return false;
        }

        match groups.get_mut(group_id) {
            Some(previous) => {
                if previous.commitment != commitment
                    || previous.max_depth != max_depth
                    || previous.hop.checked_add(1) != Some(hop)
                {
                    return false;
                }
                previous.hop = hop;
            }
            None => {
                if hop != 0 {
                    return false;
                }
                groups.insert(
                    group_id,
                    DisclosureGroupState {
                        commitment,
                        hop,
                        max_depth,
                    },
                );
            }
        }
    }

    true
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

#[cfg(test)]
mod tests {
    use super::disclosure_transitions_are_valid;
    use crate::did::{DidKeyBlock, OwnershipProof};

    fn disclosure_block(group_id: &str, commitment: &str, hop: u8, max_depth: u8) -> DidKeyBlock {
        DidKeyBlock {
            degree_three_phi_token: String::new(),
            degree_three_phi_token_authority_proof: OwnershipProof::new("", ""),
            disclosure_commitment: Some(commitment.to_string()),
            disclosure_group_id: Some(group_id.to_string()),
            disclosure_hop: Some(hop),
            disclosure_max_depth: Some(max_depth),
        }
    }

    #[test]
    fn disclosure_hops_advance_independently_by_group() {
        let blocks = [
            disclosure_block("identity", "φtrait_01", 0, 2),
            disclosure_block("address", "φtrait_02", 0, 1),
            disclosure_block("identity", "φtrait_01", 1, 2),
            disclosure_block("address", "φtrait_02", 1, 1),
            disclosure_block("identity", "φtrait_01", 2, 2),
        ];

        assert!(disclosure_transitions_are_valid(&blocks));
    }

    #[test]
    fn disclosure_group_must_start_at_zero_and_increment_exactly_once() {
        let starts_at_one = [disclosure_block("identity", "φtrait_01", 1, 2)];
        let skips_hop = [
            disclosure_block("identity", "φtrait_01", 0, 2),
            disclosure_block("identity", "φtrait_01", 2, 2),
        ];
        let repeats_hop = [
            disclosure_block("identity", "φtrait_01", 0, 2),
            disclosure_block("identity", "φtrait_01", 0, 2),
        ];

        assert!(!disclosure_transitions_are_valid(&starts_at_one));
        assert!(!disclosure_transitions_are_valid(&skips_hop));
        assert!(!disclosure_transitions_are_valid(&repeats_hop));
    }

    #[test]
    fn disclosure_group_preserves_commitment_and_depth() {
        let changed_commitment = [
            disclosure_block("identity", "φtrait_01", 0, 2),
            disclosure_block("identity", "φtrait_02", 1, 2),
        ];
        let changed_depth = [
            disclosure_block("identity", "φtrait_01", 0, 2),
            disclosure_block("identity", "φtrait_01", 1, 3),
        ];
        let exceeds_depth = [
            disclosure_block("identity", "φtrait_01", 0, 0),
            disclosure_block("identity", "φtrait_01", 1, 0),
        ];

        assert!(!disclosure_transitions_are_valid(&changed_commitment));
        assert!(!disclosure_transitions_are_valid(&changed_depth));
        assert!(!disclosure_transitions_are_valid(&exceeds_depth));
    }

    #[test]
    fn legacy_blocks_cannot_have_partial_disclosure_context() {
        let legacy = DidKeyBlock {
            degree_three_phi_token: String::new(),
            degree_three_phi_token_authority_proof: OwnershipProof::new("", ""),
            disclosure_commitment: None,
            disclosure_group_id: None,
            disclosure_hop: None,
            disclosure_max_depth: None,
        };
        let partial = DidKeyBlock {
            disclosure_commitment: Some("φtrait_01".to_string()),
            ..legacy.clone()
        };

        assert!(disclosure_transitions_are_valid([&legacy]));
        assert!(!disclosure_transitions_are_valid([&partial]));
    }
}
