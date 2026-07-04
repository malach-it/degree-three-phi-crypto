mod block;
mod blockchain;
mod did;

use block::{Block, BlockData};
use blockchain::Blockchain;
use blst::min_pk::SecretKey;
use did::{
    BLS_SIGNATURE_DST, DidKeyBlock, DidKeyRecord, DidKeySubmission, DidRole, OwnershipProof,
    amount_authority_challenge, amount_key_for_block, amount_proof_key_for_records,
    did_key_from_bls12_381_public_key,
};

const DEFAULT_DIFFICULTY_BITS: u8 = 16;

fn main() {
    let amount_authority_key = bls_secret_key(42);
    let amount_authority = did_key_for_secret_key(&amount_authority_key);
    let mut blockchain = Blockchain::new(DEFAULT_DIFFICULTY_BITS, amount_authority_key.clone());

    let first_amount = 7;
    let first_signing_keys = [bls_secret_key(7), bls_secret_key(8), bls_secret_key(9)];
    let first_amount_authority_proof = amount_authority_proof(&amount_authority_key, first_amount);
    let first_amount_key = amount_key_for_demo_block(
        &blockchain,
        &first_signing_keys,
        first_amount,
        &first_amount_authority_proof,
        &amount_authority,
    );
    add_demo_public_key_block(
        &mut blockchain,
        first_signing_keys,
        first_amount,
        first_amount_authority_proof,
        first_amount_key,
    );

    let second_amount =
        last_participant_amount(&blockchain).expect("first block has a participant amount");
    let second_signing_keys = [bls_secret_key(9), bls_secret_key(11), bls_secret_key(12)];
    let second_amount_authority_proof =
        amount_authority_proof(&amount_authority_key, second_amount);
    let second_amount_key =
        last_participant_amount_key(&blockchain).expect("first block has a participant amount key");
    add_demo_public_key_block(
        &mut blockchain,
        second_signing_keys,
        second_amount,
        second_amount_authority_proof,
        second_amount_key,
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
            println!("  amount_key {}", did_block.amount_key);
            println!("  amount_key_subject {}", did_block.amount_keys.subject);
            println!("  amount_key_witness {}", did_block.amount_keys.witness);
            println!(
                "  amount_key_participant {}",
                did_block.amount_keys.participant
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
    let common_challenge = did_block
        .records
        .first()
        .map(|record| record.proof.challenge.as_str())
        .expect("block has DID records");

    if previous_participant_did_key == Some(subject) {
        println!("  operation amount_key = previous_participant_amount_key");
    } else {
        println!("  operation amount_key = authority_signature");
    }

    println!("  operation common_challenge = amount_key");
    println!("  operation common_challenge_value = \"{common_challenge}\"");
    println!(
        "  operation subject computes amount_key_subject = amount_key_group + {} * subject_key",
        did_block.amount
    );
    println!(
        "  operation witness computes amount_key_witness = amount_key_group + {} * witness_key",
        did_block.amount
    );
    println!(
        "  operation participant computes amount_key_participant = amount_key_group + {} * participant_key",
        did_block.amount
    );
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
            "  operation {} signs common_challenge = verify_signature({}, \"{}\", {})",
            record.role.as_str(),
            record.did_key,
            record.proof.challenge,
            record.proof.signature
        );
    }
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

fn last_participant_amount_key(blockchain: &Blockchain) -> Option<String> {
    blockchain
        .chain
        .iter()
        .rev()
        .find_map(|block| match &block.data {
            BlockData::Genesis => None,
            BlockData::PublicKeys(did_block) => did_key_for_role(did_block, DidRole::Participant)
                .map(|_| did_block.amount_keys.participant.clone()),
        })
}

fn add_demo_public_key_block(
    blockchain: &mut Blockchain,
    signing_keys: [SecretKey; 3],
    amount: u8,
    amount_authority_proof: OwnershipProof,
    amount_key: String,
) {
    let submissions = signing_keys
        .iter()
        .enumerate()
        .map(|(index, signing_key)| {
            let role = match index {
                0 => DidRole::Subject,
                1 => DidRole::Witness,
                _ => DidRole::Participant,
            };
            did_submission_for_key_with_challenge(signing_key, role, &amount_key)
        })
        .collect::<Vec<_>>();
    let amount_proof_key = amount_proof_key_for_submissions(&submissions);

    blockchain
        .add_public_key_block(
            submissions,
            amount,
            amount_authority_proof,
            amount_proof_key,
        )
        .expect("public key ownership proofs should verify");
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

fn amount_authority_proof(signing_key: &SecretKey, amount: u8) -> OwnershipProof {
    let challenge = amount_authority_challenge(amount).expect("demo amount should be valid");
    let signature = signing_key.sign(challenge.as_bytes(), BLS_SIGNATURE_DST, &[]);

    OwnershipProof::new(challenge, base64url(&signature.compress()))
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

fn amount_key_for_demo_block(
    blockchain: &Blockchain,
    signing_keys: &[SecretKey; 3],
    amount: u8,
    amount_authority_proof: &OwnershipProof,
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
    let previous_participant_amount_key =
        blockchain.chain.last().and_then(|block| match &block.data {
            BlockData::Genesis => None,
            BlockData::PublicKeys(did_block) => Some(did_block.amount_keys.participant.as_str()),
        });

    amount_key_for_block(
        &records,
        amount,
        &amount_authority_proof.signature,
        amount_authority_did_key,
        previous_participant,
        previous_participant_amount_key,
    )
    .expect("demo amount key should compute")
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
    use crate::did::{DidKeyBlock, amount_keys_for_records, amount_proof_key_for_records};

    #[test]
    fn mined_genesis_blocks_prove_a_square() {
        let block = Block::genesis(12);

        assert!(block.proves_square(12));
        assert!(is_perfect_square(block.proof_square));
    }

    #[test]
    fn public_key_blocks_use_amount_key_as_mining_proof() {
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

        assert_eq!(second_block.amount_key, first_block.amount_keys.participant);
    }

    #[test]
    fn blockchain_can_store_three_dids_with_witness_tags() {
        let mut blockchain = test_blockchain();
        let amount_authority_proof = test_amount_authority_proof(7);
        let submissions =
            test_submissions_for_next_block(&blockchain, [3, 4, 5], 7, &amount_authority_proof);
        let amount_proof_key = amount_proof_key_for_submissions(&submissions);
        let expected_did = submissions[0].did_key.clone();

        blockchain
            .add_public_key_block(submissions, 7, amount_authority_proof, amount_proof_key)
            .expect("ownership proof should verify");

        assert!(blockchain.is_valid());

        let BlockData::PublicKeys(records) = &blockchain.chain[1].data else {
            panic!("expected public keys block");
        };
        let record = &records.records[0];
        let amount_authority_did_key = test_amount_authority_did_key();
        let expected_amount_keys =
            amount_keys_for_records(&records.records, records.amount, &amount_authority_did_key)
                .expect("amount key should aggregate");
        let expected_amount_proof_key =
            amount_proof_key_for_records(&records.records).expect("signatures should aggregate");

        assert_eq!(records.amount, 7);
        assert_eq!(records.amount_key, test_amount_authority_proof(7).signature);
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
        assert_eq!(records.amount_keys, expected_amount_keys);
        assert_eq!(records.amount_proof_key, expected_amount_proof_key);
        assert_ne!(records.amount_keys.subject, records.amount_keys.witness);
        assert_ne!(records.amount_keys.subject, records.amount_keys.participant);
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
        let result = blockchain.add_public_key_block(
            submissions,
            7,
            test_amount_authority_proof(7),
            amount_proof_key,
        );

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
        let result = blockchain.add_public_key_block(
            submissions,
            7,
            test_amount_authority_proof(7),
            amount_proof_key,
        );

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
        let result = blockchain.add_public_key_block(
            submissions,
            7,
            test_amount_authority_proof(7),
            amount_proof_key,
        );

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
    fn validation_rejects_public_key_block_with_tampered_role_amount_key() {
        let mut blockchain = test_blockchain();

        add_test_public_key_block(&mut blockchain, [9, 10, 11]);

        let BlockData::PublicKeys(records) = &mut blockchain.chain[1].data else {
            panic!("expected public keys block");
        };
        records.amount_keys.participant =
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
        let amount_authority_proof = test_amount_authority_proof(7);
        let submissions =
            test_submissions_for_next_block(&blockchain, [9, 10, 11], 7, &amount_authority_proof);

        let result = blockchain.add_public_key_block(
            submissions,
            7,
            amount_authority_proof,
            "wrong amount proof key".to_string(),
        );

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
            amount_authority_proof(&bls_secret_key(41), 7).signature;

        blockchain.chain[1].hash = blockchain.chain[1].recalculate_hash();

        assert!(!blockchain.is_valid());
    }

    #[test]
    fn validation_rejects_role_amount_keys_with_wrong_duplication_count() {
        let mut blockchain = test_blockchain();

        add_test_public_key_block(&mut blockchain, [9, 10, 11]);

        let BlockData::PublicKeys(records) = &mut blockchain.chain[1].data else {
            panic!("expected public keys block");
        };
        records.amount_keys = amount_keys_for_records(
            &records.records,
            records.amount - 1,
            &test_amount_authority_did_key(),
        )
        .expect("wrong duplication count should still aggregate");

        blockchain.chain[1].hash = blockchain.chain[1].recalculate_hash();

        assert!(!blockchain.is_valid());
    }

    #[test]
    fn validation_rejects_public_key_block_with_tampered_amount_key() {
        let mut blockchain = test_blockchain();

        add_test_public_key_block(&mut blockchain, [9, 10, 11]);

        let BlockData::PublicKeys(records) = &mut blockchain.chain[1].data else {
            panic!("expected public keys block");
        };
        records.amount_key =
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
        records.amount_key = amount_authority_proof(&bls_secret_key(41), 7).signature;

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

        let result = blockchain.add_public_key_block(
            submissions,
            100,
            OwnershipProof::new("invalid amount", ""),
            amount_proof_key,
        );

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
        let amount_authority_proof = test_amount_authority_proof(7);
        let submissions =
            test_submissions_for_next_block(blockchain, key_bytes, 7, &amount_authority_proof);
        let amount_proof_key = amount_proof_key_for_submissions(&submissions);

        blockchain
            .add_public_key_block(submissions, 7, amount_authority_proof, amount_proof_key)
            .expect("ownership proofs should verify");
    }

    fn test_blockchain() -> Blockchain {
        Blockchain::new(12, bls_secret_key(42))
    }

    fn test_amount_authority_did_key() -> String {
        did_key_for_secret_key(&bls_secret_key(42))
    }

    fn test_amount_authority_proof(amount: u8) -> OwnershipProof {
        amount_authority_proof(&bls_secret_key(42), amount)
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
            let amount_authority_proof = test_amount_authority_proof(amount);
            let amount_proof_key = amount_proof_key_for_submissions(&submissions);

            self.add_public_key_block(
                submissions,
                amount,
                amount_authority_proof,
                amount_proof_key,
            )
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
        amount_authority_proof: &OwnershipProof,
    ) -> Vec<DidKeySubmission> {
        let amount_key =
            test_amount_key_for_next_block(blockchain, key_bytes, amount, amount_authority_proof);

        test_submissions_with_challenge(key_bytes, &amount_key)
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

    fn test_amount_key_for_next_block(
        blockchain: &Blockchain,
        key_bytes: [u8; 3],
        amount: u8,
        amount_authority_proof: &OwnershipProof,
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
        let previous_participant_amount_key =
            blockchain.chain.last().and_then(|block| match &block.data {
                BlockData::Genesis => None,
                BlockData::PublicKeys(did_block) => {
                    Some(did_block.amount_keys.participant.as_str())
                }
            });

        amount_key_for_block(
            &records,
            amount,
            &amount_authority_proof.signature,
            &test_amount_authority_did_key(),
            previous_participant,
            previous_participant_amount_key,
        )
        .expect("test amount key should compute")
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
        let amount_authority_proof = test_amount_authority_proof(7);
        let submissions =
            test_submissions_for_next_block(&blockchain, key_bytes, 7, &amount_authority_proof);
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
            amount_authority_proof,
            amount_proof_key,
            &authority_key,
            None,
            None,
        )
        .expect("test records should build a valid DID block")
    }
}
