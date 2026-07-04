mod block;
mod blockchain;
mod did;

use block::{Block, BlockData};
use blockchain::Blockchain;
use blst::min_pk::SecretKey;
use did::{
    AmountTokens, BLS_SIGNATURE_DST, DidKeyBlock, DidKeyRecord, DidKeySubmission, DidRole,
    OwnershipProof, amount_authority_challenge, amount_proof_key_for_records,
    amount_token_for_block, amount_tokens_for_records, did_key_from_bls12_381_public_key,
    verify_did_key_ownership,
};

const DEFAULT_DIFFICULTY_BITS: u8 = 16;

fn main() {
    let amount_authority_key = bls_secret_key(42);
    let amount_authority = did_key_for_secret_key(&amount_authority_key);
    let mut blockchain = Blockchain::new(DEFAULT_DIFFICULTY_BITS, amount_authority_key.clone());

    let first_amount = 7;
    let first_signing_keys = [bls_secret_key(7), bls_secret_key(8), bls_secret_key(9)];
    let first_amount_authority_signature =
        amount_authority_signature(&amount_authority_key, first_amount);
    let first_amount_token = amount_token_for_demo_block(
        &blockchain,
        &first_signing_keys,
        first_amount,
        &first_amount_authority_signature,
        &amount_authority,
    );
    add_demo_public_key_block(
        &mut blockchain,
        first_signing_keys,
        first_amount,
        first_amount_token,
        &amount_authority,
    );

    let second_amount =
        last_participant_amount(&blockchain).expect("first block has a participant amount");
    let second_signing_keys = [bls_secret_key(9), bls_secret_key(11), bls_secret_key(12)];
    let second_amount_token = last_participant_amount_token(&blockchain)
        .expect("first block has a participant amount token");
    add_demo_public_key_block(
        &mut blockchain,
        second_signing_keys,
        second_amount,
        second_amount_token,
        &amount_authority,
    );

    let mut previous_participant: Option<String> = None;
    for block in &blockchain.chain {
        print_block(block, &amount_authority, previous_participant.as_deref());

        if let BlockData::PublicKeys(did_block) = &block.data {
            previous_participant = did_key_for_role(did_block, DidRole::Participant).cloned();
        }
    }

    println!("chain valid: {}", blockchain.is_valid());
}

fn print_block(
    block: &Block,
    amount_authority_did_key: &str,
    previous_participant_did_key: Option<&str>,
) {
    println!(
        "block #{}, nonce {}, square-proof {}, hash {}",
        block.index, block.nonce, block.proof_square, block.hash
    );

    match &block.data {
        BlockData::Genesis => println!("  genesis"),
        BlockData::PublicKeys(did_block) => {
            print_operations(
                did_block,
                amount_authority_did_key,
                previous_participant_did_key,
            );
            println!("  amount {}", did_block.amount);
            println!("  amount_token {}", did_block.amount_token);
            println!("  amount_token_subject {}", did_block.amount_tokens.subject);
            println!("  amount_token_witness {}", did_block.amount_tokens.witness);
            println!(
                "  amount_token_participant {}",
                did_block.amount_tokens.participant
            );
            println!("  amount_proof_key {}", did_block.amount_proof_key);
            println!(
                "  amount_proof_key_authority_signature {}",
                did_block.amount_proof_key_authority_proof.signature
            );

            for record in &did_block.records {
                println!("  {:?}: {}", record.role, record.did_key);
            }
        }
    }

    println!();
}

fn print_operations(
    did_block: &DidKeyBlock,
    amount_authority_did_key: &str,
    previous_participant_did_key: Option<&str>,
) {
    let subject = did_key_for_role(did_block, DidRole::Subject).expect("block has a subject");
    let witness = did_key_for_role(did_block, DidRole::Witness).expect("block has a witness");
    let participant =
        did_key_for_role(did_block, DidRole::Participant).expect("block has a participant");
    if previous_participant_did_key == Some(subject) {
        println!("  operation amount_token = previous_participant_amount_token");
    } else {
        println!("  operation amount_token = authority_signature");
    }

    println!(
        "  operation subject computes amount_token_subject = amount_token_group + {} * subject_key",
        did_block.amount
    );
    println!(
        "  operation witness computes amount_token_witness = amount_token_group + {} * witness_key",
        did_block.amount
    );
    println!(
        "  operation participant computes amount_token_participant = amount_token_group + {} * participant_key",
        did_block.amount
    );
    println!("  operation subject_challenge = amount_token_subject");
    println!("  operation witness_challenge = amount_token_witness");
    println!("  operation participant_challenge = amount_token_participant");
    println!(
        "  operation return amount_proof_key = aggregate_signature(subject_signature, witness_signature, participant_signature)"
    );
    println!("  operation authority signs amount_proof_key");
    println!("  operation authority_key = {amount_authority_did_key}");
    println!("  operation subject_key = {subject}");
    println!("  operation witness_key = {witness}");
    println!("  operation participant_key = {participant}");

    for record in &did_block.records {
        println!(
            "  operation {} signs role_challenge = verify_signature({}, \"{}\", {})",
            record.role.as_str(),
            record.did_key,
            record.proof.challenge,
            record.proof.signature
        );
    }

    print_two_party_block_result_verifications(did_block);
}

fn print_two_party_block_result_verifications(did_block: &DidKeyBlock) {
    for target_role in [DidRole::Subject, DidRole::Witness, DidRole::Participant] {
        let verifier_roles = [DidRole::Subject, DidRole::Witness, DidRole::Participant]
            .into_iter()
            .filter(|role| *role != target_role)
            .map(DidRole::as_str)
            .collect::<Vec<_>>()
            .join("+");
        let target_record = record_for_role(did_block, target_role).expect("block has target role");
        let expected_challenge = amount_token_for_role(&did_block.amount_tokens, target_role);
        let challenge_matches_block = target_record.proof.challenge == expected_challenge;
        let target_signature_valid =
            verify_did_key_ownership(&target_record.did_key, &target_record.proof).is_ok();
        let block_result_matches = amount_proof_key_for_records(&did_block.records)
            .map(|amount_proof_key| amount_proof_key == did_block.amount_proof_key)
            .unwrap_or(false);

        println!(
            "  operation {verifier_roles} verify {} from block_result = challenge:{challenge_matches_block}, signature:{target_signature_valid}, aggregate:{block_result_matches}",
            target_role.as_str()
        );
    }
}

fn record_for_role(did_block: &DidKeyBlock, role: DidRole) -> Option<&DidKeyRecord> {
    did_block.records.iter().find(|record| record.role == role)
}

fn did_key_for_role(did_block: &DidKeyBlock, role: DidRole) -> Option<&String> {
    did_block
        .records
        .iter()
        .find(|record| record.role == role)
        .map(|record| &record.did_key)
}

fn last_participant_amount(blockchain: &Blockchain) -> Option<u8> {
    blockchain
        .chain
        .iter()
        .rev()
        .find_map(|block| match &block.data {
            BlockData::Genesis => None,
            BlockData::PublicKeys(did_block) => {
                did_key_for_role(did_block, DidRole::Participant).map(|_| did_block.amount)
            }
        })
}

fn last_participant_amount_token(blockchain: &Blockchain) -> Option<String> {
    blockchain
        .chain
        .iter()
        .rev()
        .find_map(|block| match &block.data {
            BlockData::Genesis => None,
            BlockData::PublicKeys(did_block) => did_key_for_role(did_block, DidRole::Participant)
                .map(|_| did_block.amount_tokens.participant.clone()),
        })
}

fn add_demo_public_key_block(
    blockchain: &mut Blockchain,
    signing_keys: [SecretKey; 3],
    amount: u8,
    amount_token: String,
    amount_authority_did_key: &str,
) {
    let records = records_without_proofs(&signing_keys);
    let amount_token_group = amount_token_group_for_demo(&amount_token, amount_authority_did_key);
    let amount_tokens = amount_tokens_for_records(&records, amount, &amount_token_group)
        .expect("demo amount tokens should compute");
    let submissions = signing_keys
        .iter()
        .enumerate()
        .map(|(index, signing_key)| {
            let role = match index {
                0 => DidRole::Subject,
                1 => DidRole::Witness,
                _ => DidRole::Participant,
            };
            did_submission_for_key_with_challenge(
                signing_key,
                role,
                amount_token_for_role(&amount_tokens, role),
            )
        })
        .collect::<Vec<_>>();
    let amount_proof_key = amount_proof_key_for_submissions(&submissions);

    blockchain
        .add_public_key_block(submissions, amount, amount_proof_key)
        .expect("public key ownership proofs should verify");
}

fn records_without_proofs(signing_keys: &[SecretKey; 3]) -> Vec<DidKeyRecord> {
    signing_keys
        .iter()
        .enumerate()
        .map(|(index, signing_key)| {
            let role = match index {
                0 => DidRole::Subject,
                1 => DidRole::Witness,
                _ => DidRole::Participant,
            };
            DidKeyRecord::new(
                did_key_for_secret_key(signing_key),
                role,
                OwnershipProof::new("", ""),
            )
        })
        .collect()
}

fn amount_token_group_for_demo(amount_token: &str, amount_authority_did_key: &str) -> String {
    if amount_token.starts_with("did:key:") {
        amount_token.to_string()
    } else {
        amount_authority_did_key.to_string()
    }
}

fn amount_token_for_role(amount_tokens: &AmountTokens, role: DidRole) -> &str {
    match role {
        DidRole::Subject => &amount_tokens.subject,
        DidRole::Witness => &amount_tokens.witness,
        DidRole::Participant => &amount_tokens.participant,
    }
}

#[cfg(test)]
fn did_submission_for_key(signing_key: &SecretKey, role: DidRole) -> DidKeySubmission {
    let did_key = did_key_for_secret_key(signing_key);
    let challenge = format!("add {did_key} to phi-crypto");

    did_submission_for_key_with_challenge(signing_key, role, &challenge)
}

fn did_submission_for_key_with_challenge(
    signing_key: &SecretKey,
    role: DidRole,
    challenge: &str,
) -> DidKeySubmission {
    let did_key = did_key_for_secret_key(signing_key);
    let signature = signing_key.sign(challenge.as_bytes(), BLS_SIGNATURE_DST, &[]);

    DidKeySubmission::with_role(
        did_key,
        role,
        OwnershipProof::new(challenge, base64url(&signature.compress())),
    )
}

fn did_key_for_secret_key(signing_key: &SecretKey) -> String {
    did_key_from_bls12_381_public_key(&signing_key.sk_to_pk().compress())
}

fn amount_authority_signature(signing_key: &SecretKey, amount: u8) -> String {
    let challenge = amount_authority_challenge(amount).expect("demo amount should be valid");
    let signature = signing_key.sign(challenge.as_bytes(), BLS_SIGNATURE_DST, &[]);

    base64url(&signature.compress())
}

fn amount_proof_key_for_submissions(submissions: &[DidKeySubmission]) -> String {
    let records = submissions
        .iter()
        .map(|submission| {
            DidKeyRecord::new(
                submission.did_key.clone(),
                submission.role,
                submission.proof.clone(),
            )
        })
        .collect::<Vec<_>>();

    amount_proof_key_for_records(&records).expect("signatures should aggregate")
}

fn amount_token_for_demo_block(
    blockchain: &Blockchain,
    signing_keys: &[SecretKey; 3],
    amount: u8,
    amount_authority_signature: &str,
    amount_authority_did_key: &str,
) -> String {
    let records = signing_keys
        .iter()
        .enumerate()
        .map(|(index, signing_key)| {
            let role = match index {
                0 => DidRole::Subject,
                1 => DidRole::Witness,
                _ => DidRole::Participant,
            };
            DidKeyRecord::new(
                did_key_for_secret_key(signing_key),
                role,
                OwnershipProof::new("", ""),
            )
        })
        .collect::<Vec<_>>();
    let previous_participant = blockchain
        .chain
        .last()
        .and_then(|block| match &block.data {
            BlockData::Genesis => None,
            BlockData::PublicKeys(did_block) => did_key_for_role(did_block, DidRole::Participant),
        })
        .map(String::as_str);
    let previous_participant_amount = blockchain.chain.last().and_then(|block| match &block.data {
        BlockData::Genesis => None,
        BlockData::PublicKeys(did_block) => Some(did_block.amount),
    });
    let previous_participant_amount_token =
        blockchain.chain.last().and_then(|block| match &block.data {
            BlockData::Genesis => None,
            BlockData::PublicKeys(did_block) => Some(did_block.amount_tokens.participant.as_str()),
        });

    amount_token_for_block(
        &records,
        amount,
        amount_authority_signature,
        amount_authority_did_key,
        previous_participant,
        previous_participant_amount,
        previous_participant_amount_token,
    )
    .expect("demo amount token should compute")
}

fn bls_secret_key(seed: u8) -> SecretKey {
    let ikm = [seed; 32];

    SecretKey::key_gen(&ikm, &[]).expect("test BLS key material should be valid")
}

fn base64url(bytes: &[u8]) -> String {
    use base64::Engine;

    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Block, BlockData, is_perfect_square};
    use crate::did::{DidKeyBlock, amount_proof_key_for_records, amount_tokens_for_records};

    #[test]
    fn mined_genesis_blocks_prove_a_square() {
        let block = Block::genesis(12);

        assert!(block.proves_square(12));
        assert!(is_perfect_square(block.proof_square));
    }

    #[test]
    fn public_key_blocks_use_amount_token_as_mining_proof() {
        let block = Block::mine(
            1,
            BlockData::PublicKeys(test_did_key_block([1, 2, 3])),
            "abc".to_string(),
            12,
        );

        assert_eq!(block.nonce, 0);
        assert_eq!(block.hash, block.recalculate_hash());
    }

    #[test]
    fn blockchain_validates_linked_blocks() {
        let mut blockchain = test_blockchain();

        add_test_public_key_block(&mut blockchain, [1, 2, 3]);
        add_test_public_key_block(&mut blockchain, [3, 5, 6]);

        assert!(blockchain.is_valid());

        let BlockData::PublicKeys(first_block) = &blockchain.chain[1].data else {
            panic!("expected first public keys block");
        };
        let BlockData::PublicKeys(second_block) = &blockchain.chain[2].data else {
            panic!("expected second public keys block");
        };

        assert_eq!(
            second_block.records[0].did_key,
            first_block.records[2].did_key
        );
        assert_eq!(second_block.records[0].role, DidRole::Subject);
        assert_eq!(first_block.records[2].role, DidRole::Participant);

        assert_eq!(
            second_block.amount_token,
            first_block.amount_tokens.participant
        );
    }

    #[test]
    fn rejects_linked_block_with_amount_that_does_not_match_amount_token() {
        let mut blockchain = test_blockchain();

        add_test_public_key_block(&mut blockchain, [1, 2, 3]);

        let BlockData::PublicKeys(first_block) = &blockchain.chain[1].data else {
            panic!("expected first public keys block");
        };
        let amount_token = first_block.amount_tokens.participant.clone();
        let submissions = test_submissions_with_challenge([3, 5, 6], &amount_token);
        let amount_proof_key = amount_proof_key_for_submissions(&submissions);
        let result = blockchain.add_public_key_block(submissions, 8, amount_proof_key);

        assert!(matches!(
            result,
            Err(crate::did::OwnershipProofError::AmountDoesNotMatchToken {
                expected: 7,
                actual: 8
            })
        ));
        assert_eq!(blockchain.chain.len(), 2);
    }

    #[test]
    fn blockchain_can_store_three_dids_with_witness_tags() {
        let mut blockchain = test_blockchain();
        let amount_authority_signature = test_amount_authority_signature(7);
        let submissions =
            test_submissions_for_next_block(&blockchain, [3, 4, 5], 7, &amount_authority_signature);
        let amount_proof_key = amount_proof_key_for_submissions(&submissions);
        let expected_did = submissions[0].did_key.clone();

        blockchain
            .add_public_key_block(submissions, 7, amount_proof_key)
            .expect("ownership proof should verify");

        assert!(blockchain.is_valid());

        let BlockData::PublicKeys(records) = &blockchain.chain[1].data else {
            panic!("expected public keys block");
        };
        let record = &records.records[0];
        let amount_authority_did_key = test_amount_authority_did_key();
        let expected_amount_tokens =
            amount_tokens_for_records(&records.records, records.amount, &amount_authority_did_key)
                .expect("amount token should aggregate");
        let expected_amount_proof_key =
            amount_proof_key_for_records(&records.records).expect("signatures should aggregate");

        assert_eq!(records.amount, 7);
        assert_eq!(records.amount_token, test_amount_authority_signature(7));
        assert!(
            !records
                .records
                .iter()
                .any(|record| record.did_key == amount_authority_did_key)
        );
        assert_eq!(records.records.len(), 3);
        assert_eq!(records.records[0].role, DidRole::Subject);
        assert_eq!(records.records[1].role, DidRole::Witness);
        assert_eq!(records.records[2].role, DidRole::Participant);
        assert_ne!(records.records[0].did_key, records.records[1].did_key);
        assert_eq!(record.did_key, expected_did);
        assert_eq!(records.amount_tokens, expected_amount_tokens);
        assert_eq!(records.amount_proof_key, expected_amount_proof_key);
        assert_ne!(records.amount_tokens.subject, records.amount_tokens.witness);
        assert_ne!(
            records.amount_tokens.subject,
            records.amount_tokens.participant
        );
    }

    #[test]
    fn rejects_public_key_block_without_valid_ownership_proof() {
        let mut blockchain = test_blockchain();
        let wrong_signing_key = bls_secret_key(5);
        let mut submissions = test_submissions([4, 5, 6]);
        let challenge = format!("prove ownership for {}", submissions[0].did_key);
        let signature = wrong_signing_key.sign(challenge.as_bytes(), BLS_SIGNATURE_DST, &[]);
        submissions[0].proof = OwnershipProof::new(challenge, base64url(&signature.compress()));

        let result = blockchain.add_public_key_block_with_authority_proofs(submissions, 7);

        assert!(result.is_err());
        assert_eq!(blockchain.chain.len(), 1);
    }

    #[test]
    fn rejects_public_key_block_without_exactly_three_dids() {
        let mut blockchain = test_blockchain();
        let submissions = test_submissions([1, 2, 3])[0..2].to_vec();
        let amount_proof_key = amount_proof_key_for_submissions(&submissions);
        let result = blockchain.add_public_key_block(submissions, 7, amount_proof_key);

        assert!(result.is_err());
        assert_eq!(blockchain.chain.len(), 1);
    }

    #[test]
    fn rejects_public_key_block_without_exactly_one_witness() {
        let mut blockchain = test_blockchain();
        let submissions = vec![
            did_submission_for_key(&bls_secret_key(1), DidRole::Subject),
            did_submission_for_key(&bls_secret_key(2), DidRole::Subject),
            did_submission_for_key(&bls_secret_key(3), DidRole::Subject),
        ];
        let amount_proof_key = amount_proof_key_for_submissions(&submissions);
        let result = blockchain.add_public_key_block(submissions, 7, amount_proof_key);

        assert!(result.is_err());
        assert_eq!(blockchain.chain.len(), 1);
    }

    #[test]
    fn rejects_public_key_block_with_two_witnesses() {
        let mut blockchain = test_blockchain();
        let submissions = vec![
            did_submission_for_key(&bls_secret_key(1), DidRole::Subject),
            did_submission_for_key(&bls_secret_key(2), DidRole::Witness),
            did_submission_for_key(&bls_secret_key(3), DidRole::Witness),
        ];
        let amount_proof_key = amount_proof_key_for_submissions(&submissions);
        let result = blockchain.add_public_key_block(submissions, 7, amount_proof_key);

        assert!(result.is_err());
        assert_eq!(blockchain.chain.len(), 1);
    }

    #[test]
    fn rejects_public_key_block_with_unsupported_did_key() {
        let mut blockchain = test_blockchain();
        let mut submissions = test_submissions([8, 9, 10]);
        submissions[0].did_key = "did:key:z6MkiTBzInvalidExample".to_string();

        let result = blockchain.add_public_key_block_with_authority_proofs(submissions, 7);

        assert!(result.is_err());
        assert_eq!(blockchain.chain.len(), 1);
    }

    #[test]
    fn rejects_non_did_key_identifier() {
        let mut blockchain = test_blockchain();
        let signing_key = bls_secret_key(11);
        let mut submissions = test_submissions([11, 12, 13]);
        let challenge = "prove ownership for non did:key identifier";
        let signature = signing_key.sign(challenge.as_bytes(), BLS_SIGNATURE_DST, &[]);
        submissions[0] = DidKeySubmission::with_role(
            "did:web:example.com",
            DidRole::Subject,
            OwnershipProof::new(challenge, base64url(&signature.compress())),
        );

        let result = blockchain.add_public_key_block_with_authority_proofs(submissions, 7);

        assert!(result.is_err());
        assert_eq!(blockchain.chain.len(), 1);
    }

    #[test]
    fn validation_rejects_public_key_block_with_unsupported_did_key() {
        let mut blockchain = test_blockchain();

        add_test_public_key_block(&mut blockchain, [9, 10, 11]);

        let BlockData::PublicKeys(records) = &mut blockchain.chain[1].data else {
            panic!("expected public keys block");
        };
        records.records[0].did_key = "did:key:z6MkiTBzTamperedDid".to_string();

        blockchain.chain[1].hash = blockchain.chain[1].recalculate_hash();

        assert!(!blockchain.is_valid());
    }

    #[test]
    fn validation_rejects_public_key_block_with_tampered_role_amount_token() {
        let mut blockchain = test_blockchain();

        add_test_public_key_block(&mut blockchain, [9, 10, 11]);

        let BlockData::PublicKeys(records) = &mut blockchain.chain[1].data else {
            panic!("expected public keys block");
        };
        records.amount_tokens.participant =
            did_key_from_bls12_381_public_key(&bls_secret_key(12).sk_to_pk().compress());

        blockchain.chain[1].hash = blockchain.chain[1].recalculate_hash();

        assert!(!blockchain.is_valid());
    }

    #[test]
    fn validation_rejects_public_key_block_with_tampered_amount_proof_key() {
        let mut blockchain = test_blockchain();

        add_test_public_key_block(&mut blockchain, [9, 10, 11]);

        let BlockData::PublicKeys(records) = &mut blockchain.chain[1].data else {
            panic!("expected public keys block");
        };
        records.amount_proof_key =
            did_key_from_bls12_381_public_key(&bls_secret_key(12).sk_to_pk().compress());

        blockchain.chain[1].hash = blockchain.chain[1].recalculate_hash();

        assert!(!blockchain.is_valid());
    }

    #[test]
    fn rejects_public_key_block_with_wrong_amount_proof_key_argument() {
        let mut blockchain = test_blockchain();
        let amount_authority_signature = test_amount_authority_signature(7);
        let submissions = test_submissions_for_next_block(
            &blockchain,
            [9, 10, 11],
            7,
            &amount_authority_signature,
        );

        let result =
            blockchain.add_public_key_block(submissions, 7, "wrong amount proof key".to_string());

        assert!(result.is_err());
        assert_eq!(blockchain.chain.len(), 1);
    }

    #[test]
    fn validation_rejects_public_key_block_with_tampered_amount_proof_key_authority_signature() {
        let mut blockchain = test_blockchain();

        add_test_public_key_block(&mut blockchain, [9, 10, 11]);

        let BlockData::PublicKeys(records) = &mut blockchain.chain[1].data else {
            panic!("expected public keys block");
        };
        records.amount_proof_key_authority_proof.signature =
            amount_authority_signature(&bls_secret_key(41), 7);

        blockchain.chain[1].hash = blockchain.chain[1].recalculate_hash();

        assert!(!blockchain.is_valid());
    }

    #[test]
    fn validation_rejects_role_amount_tokens_with_wrong_duplication_count() {
        let mut blockchain = test_blockchain();

        add_test_public_key_block(&mut blockchain, [9, 10, 11]);

        let BlockData::PublicKeys(records) = &mut blockchain.chain[1].data else {
            panic!("expected public keys block");
        };
        records.amount_tokens = amount_tokens_for_records(
            &records.records,
            records.amount - 1,
            &test_amount_authority_did_key(),
        )
        .expect("wrong duplication count should still aggregate");

        blockchain.chain[1].hash = blockchain.chain[1].recalculate_hash();

        assert!(!blockchain.is_valid());
    }

    #[test]
    fn validation_rejects_public_key_block_with_tampered_amount_token() {
        let mut blockchain = test_blockchain();

        add_test_public_key_block(&mut blockchain, [9, 10, 11]);

        let BlockData::PublicKeys(records) = &mut blockchain.chain[1].data else {
            panic!("expected public keys block");
        };
        records.amount_token =
            did_key_from_bls12_381_public_key(&bls_secret_key(12).sk_to_pk().compress());

        blockchain.chain[1].hash = blockchain.chain[1].recalculate_hash();

        assert!(!blockchain.is_valid());
    }

    #[test]
    fn validation_rejects_public_key_block_with_wrong_amount_authority_signature() {
        let mut blockchain = test_blockchain();

        add_test_public_key_block(&mut blockchain, [9, 10, 11]);

        let BlockData::PublicKeys(records) = &mut blockchain.chain[1].data else {
            panic!("expected public keys block");
        };
        records.amount_token = amount_authority_signature(&bls_secret_key(41), 7);

        blockchain.chain[1].hash = blockchain.chain[1].recalculate_hash();

        assert!(!blockchain.is_valid());
    }

    #[test]
    fn validation_rejects_public_key_block_with_tampered_challenge_proof() {
        let mut blockchain = test_blockchain();

        add_test_public_key_block(&mut blockchain, [9, 10, 11]);

        let BlockData::PublicKeys(records) = &mut blockchain.chain[1].data else {
            panic!("expected public keys block");
        };
        records.records[0].proof.challenge = "tampered mining challenge".to_string();

        blockchain.chain[1].hash = blockchain.chain[1].recalculate_hash();

        assert!(!blockchain.is_valid());
    }

    #[test]
    fn rejects_public_key_block_with_amount_that_is_not_small() {
        let mut blockchain = test_blockchain();
        let submissions = test_submissions([1, 2, 3]);
        let amount_proof_key = amount_proof_key_for_submissions(&submissions);

        let result = blockchain.add_public_key_block(submissions, 100, amount_proof_key);

        assert!(result.is_err());
        assert_eq!(blockchain.chain.len(), 1);
    }

    #[test]
    fn tampering_breaks_validation() {
        let mut blockchain = test_blockchain();

        add_test_public_key_block(&mut blockchain, [6, 7, 8]);
        blockchain.chain[1].data = BlockData::PublicKeys(test_did_key_block([7, 8, 9]));

        assert!(!blockchain.is_valid());
    }

    #[test]
    fn detects_square_values() {
        assert!(is_perfect_square(0));
        assert!(is_perfect_square(1));
        assert!(is_perfect_square(144));
        assert!(!is_perfect_square(145));
    }

    fn add_test_public_key_block(blockchain: &mut Blockchain, key_bytes: [u8; 3]) {
        let amount_authority_signature = test_amount_authority_signature(7);
        let submissions =
            test_submissions_for_next_block(blockchain, key_bytes, 7, &amount_authority_signature);
        let amount_proof_key = amount_proof_key_for_submissions(&submissions);

        blockchain
            .add_public_key_block(submissions, 7, amount_proof_key)
            .expect("ownership proofs should verify");
    }

    fn test_blockchain() -> Blockchain {
        Blockchain::new(12, bls_secret_key(42))
    }

    fn test_amount_authority_did_key() -> String {
        did_key_for_secret_key(&bls_secret_key(42))
    }

    fn test_amount_authority_signature(amount: u8) -> String {
        amount_authority_signature(&bls_secret_key(42), amount)
    }

    trait TestBlockchainExt {
        fn add_public_key_block_with_authority_proofs(
            &mut self,
            submissions: Vec<DidKeySubmission>,
            amount: u8,
        ) -> Result<(), crate::did::OwnershipProofError>;
    }

    impl TestBlockchainExt for Blockchain {
        fn add_public_key_block_with_authority_proofs(
            &mut self,
            submissions: Vec<DidKeySubmission>,
            amount: u8,
        ) -> Result<(), crate::did::OwnershipProofError> {
            let amount_proof_key = amount_proof_key_for_submissions(&submissions);

            self.add_public_key_block(submissions, amount, amount_proof_key)
        }
    }

    fn test_submissions(key_bytes: [u8; 3]) -> Vec<DidKeySubmission> {
        key_bytes
            .into_iter()
            .enumerate()
            .map(|(index, byte)| {
                let signing_key = bls_secret_key(byte);
                let role = match index {
                    0 => DidRole::Subject,
                    1 => DidRole::Witness,
                    _ => DidRole::Participant,
                };
                did_submission_for_key(&signing_key, role)
            })
            .collect()
    }

    fn test_submissions_for_next_block(
        blockchain: &Blockchain,
        key_bytes: [u8; 3],
        amount: u8,
        amount_authority_signature: &str,
    ) -> Vec<DidKeySubmission> {
        let amount_token = test_amount_token_for_next_block(
            blockchain,
            key_bytes,
            amount,
            amount_authority_signature,
        );
        let amount_token_group =
            amount_token_group_for_demo(&amount_token, &test_amount_authority_did_key());
        let records = test_records_without_proofs(key_bytes);
        let amount_tokens = amount_tokens_for_records(&records, amount, &amount_token_group)
            .expect("test amount tokens should compute");

        test_submissions_with_amount_tokens(key_bytes, &amount_tokens)
    }

    fn test_submissions_with_amount_tokens(
        key_bytes: [u8; 3],
        amount_tokens: &AmountTokens,
    ) -> Vec<DidKeySubmission> {
        key_bytes
            .into_iter()
            .enumerate()
            .map(|(index, byte)| {
                let signing_key = bls_secret_key(byte);
                let role = match index {
                    0 => DidRole::Subject,
                    1 => DidRole::Witness,
                    _ => DidRole::Participant,
                };
                did_submission_for_key_with_challenge(
                    &signing_key,
                    role,
                    amount_token_for_role(amount_tokens, role),
                )
            })
            .collect()
    }

    fn test_submissions_with_challenge(
        key_bytes: [u8; 3],
        challenge: &str,
    ) -> Vec<DidKeySubmission> {
        key_bytes
            .into_iter()
            .enumerate()
            .map(|(index, byte)| {
                let signing_key = bls_secret_key(byte);
                let role = match index {
                    0 => DidRole::Subject,
                    1 => DidRole::Witness,
                    _ => DidRole::Participant,
                };
                did_submission_for_key_with_challenge(&signing_key, role, challenge)
            })
            .collect()
    }

    fn test_amount_token_for_next_block(
        blockchain: &Blockchain,
        key_bytes: [u8; 3],
        amount: u8,
        amount_authority_signature: &str,
    ) -> String {
        let records = test_records_without_proofs(key_bytes);
        let previous_participant = blockchain
            .chain
            .last()
            .and_then(|block| match &block.data {
                BlockData::Genesis => None,
                BlockData::PublicKeys(did_block) => {
                    did_key_for_role(did_block, DidRole::Participant)
                }
            })
            .map(String::as_str);
        let previous_participant_amount =
            blockchain.chain.last().and_then(|block| match &block.data {
                BlockData::Genesis => None,
                BlockData::PublicKeys(did_block) => Some(did_block.amount),
            });
        let previous_participant_amount_token =
            blockchain.chain.last().and_then(|block| match &block.data {
                BlockData::Genesis => None,
                BlockData::PublicKeys(did_block) => {
                    Some(did_block.amount_tokens.participant.as_str())
                }
            });

        amount_token_for_block(
            &records,
            amount,
            amount_authority_signature,
            &test_amount_authority_did_key(),
            previous_participant,
            previous_participant_amount,
            previous_participant_amount_token,
        )
        .expect("test amount token should compute")
    }

    fn test_records_without_proofs(key_bytes: [u8; 3]) -> Vec<DidKeyRecord> {
        key_bytes
            .into_iter()
            .enumerate()
            .map(|(index, byte)| {
                let role = match index {
                    0 => DidRole::Subject,
                    1 => DidRole::Witness,
                    _ => DidRole::Participant,
                };

                DidKeyRecord::new(
                    did_key_for_secret_key(&bls_secret_key(byte)),
                    role,
                    OwnershipProof::new("", ""),
                )
            })
            .collect()
    }

    fn test_did_key_block(key_bytes: [u8; 3]) -> DidKeyBlock {
        let blockchain = test_blockchain();
        let amount_authority_signature = test_amount_authority_signature(7);
        let submissions =
            test_submissions_for_next_block(&blockchain, key_bytes, 7, &amount_authority_signature);
        let records = submissions
            .into_iter()
            .map(|submission| {
                DidKeyRecord::new(submission.did_key, submission.role, submission.proof)
            })
            .collect::<Vec<_>>();
        let amount_proof_key =
            amount_proof_key_for_records(&records).expect("signatures should aggregate");
        let authority_key = bls_secret_key(42);

        DidKeyBlock::new(
            records,
            7,
            amount_proof_key,
            &authority_key,
            None,
            None,
            None,
        )
        .expect("test records should build a valid DID block")
    }
}
