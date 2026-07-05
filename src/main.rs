mod block;
mod blockchain;
mod did;

use block::BlockData;
use blockchain::Blockchain;
use blst::min_pk::SecretKey;
use did::{
    AmountTokens, BLS_SIGNATURE_DST, DidKeyRecord, DidKeySubmission, DidRole, OwnershipProof,
    amount_token_group_for_block, amount_tokens_for_records, did_key_from_bls12_381_public_key,
    three_degree_phi_token_for_records, verify_did_key_ownership,
};

const DEFAULT_DIFFICULTY_BITS: u8 = 16;

#[derive(Debug)]
struct DemoReceipt {
    block_index: u64,
    block_hash: String,
    amount: u8,
    records: Vec<DidKeyRecord>,
    amount_tokens: AmountTokens,
    three_degree_phi_token: String,
}

fn main() {
    let amount_authority_key = bls_secret_key(42);
    let amount_authority = did_key_for_secret_key(&amount_authority_key);
    let mut blockchain = Blockchain::new(DEFAULT_DIFFICULTY_BITS, amount_authority_key);

    let mut receipts = Vec::new();
    let first = add_demo_public_key_block(
        &mut blockchain,
        [bls_secret_key(7), bls_secret_key(8), bls_secret_key(9)],
        7,
        &amount_authority,
        None,
        None,
        None,
    );
    let first_participant = did_key_for_role(&first.records, DidRole::Participant).to_string();
    let first_participant_token = first.amount_tokens.participant.clone();
    let first_amount = first.amount;
    receipts.push(first);

    receipts.push(add_demo_public_key_block(
        &mut blockchain,
        [bls_secret_key(9), bls_secret_key(11), bls_secret_key(12)],
        first_amount,
        &amount_authority,
        Some(&first_participant),
        Some(first_amount),
        Some(&first_participant_token),
    ));

    print_chain(&blockchain);
    for receipt in &receipts {
        print_receipt(receipt, &amount_authority);
    }
    println!("chain valid: {}", blockchain.is_valid());
}

fn add_demo_public_key_block(
    blockchain: &mut Blockchain,
    signing_keys: [SecretKey; 3],
    amount: u8,
    amount_authority_did_key: &str,
    previous_participant_did_key: Option<&str>,
    previous_participant_amount: Option<u8>,
    previous_participant_amount_token: Option<&str>,
) -> DemoReceipt {
    let records = records_without_proofs(&signing_keys);
    let amount_token_group = amount_token_group_for_block(
        &records,
        amount,
        amount_authority_did_key,
        previous_participant_did_key,
        previous_participant_amount,
        previous_participant_amount_token,
    )
    .expect("demo amount token group should derive");
    let amount_tokens = amount_tokens_for_records(&records, amount, &amount_token_group)
        .expect("demo amount tokens should compute");
    let submissions = signing_keys
        .iter()
        .enumerate()
        .map(|(index, signing_key)| {
            let role = role_for_index(index);
            did_submission_for_key_with_challenge(
                signing_key,
                role,
                amount_token_for_role(&amount_tokens, role),
            )
        })
        .collect::<Vec<_>>();
    let three_degree_phi_token = three_degree_phi_token_for_submissions(&submissions);

    blockchain
        .add_public_key_block(submissions, amount, three_degree_phi_token.clone())
        .expect("public key ownership proofs should verify at block creation");
    let block = blockchain
        .chain
        .last()
        .expect("accepted public key block should be appended");

    DemoReceipt {
        block_index: block.index,
        block_hash: block.hash.clone(),
        amount,
        records: records_with_proofs(&signing_keys, &amount_tokens),
        amount_tokens,
        three_degree_phi_token,
    }
}

fn print_chain(blockchain: &Blockchain) {
    for block in &blockchain.chain {
        match &block.data {
            BlockData::Genesis => println!(
                "block #{}, type genesis, nonce {}, square-proof {}, hash {}",
                block.index, block.nonce, block.proof_square, block.hash
            ),
            BlockData::PublicKeys(did_block) => println!(
                "block #{}, type amount-proof-receipt, nonce {}, square-proof {}, hash {}, three_degree_phi_token {}",
                block.index,
                block.nonce,
                block.proof_square,
                block.hash,
                did_block.three_degree_phi_token
            ),
        }
    }
}

fn print_receipt(receipt: &DemoReceipt, amount_authority_did_key: &str) {
    println!(
        "receipt block #{}, hash {}, amount {}, three_degree_phi_token {}",
        receipt.block_index, receipt.block_hash, receipt.amount, receipt.three_degree_phi_token
    );
    println!("  amount_token_subject {}", receipt.amount_tokens.subject);
    println!("  amount_token_witness {}", receipt.amount_tokens.witness);
    println!(
        "  amount_token_participant {}",
        receipt.amount_tokens.participant
    );
    println!("  operation amount_token_group is derived before block creation");
    println!("  operation authority signs three_degree_phi_token");
    println!("  operation authority_key = {amount_authority_did_key}");

    for record in &receipt.records {
        println!(
            "  operation {} signs role_challenge = verify_signature({}, \"{}\", {})",
            record.role.as_str(),
            record.did_key,
            record.proof.challenge,
            record.proof.signature
        );
    }

    print_two_party_block_result_verifications(
        &receipt.records,
        &receipt.amount_tokens,
        &receipt.three_degree_phi_token,
    );
}

fn print_two_party_block_result_verifications(
    records: &[DidKeyRecord],
    amount_tokens: &AmountTokens,
    three_degree_phi_token: &str,
) {
    for target_role in [DidRole::Subject, DidRole::Witness, DidRole::Participant] {
        let verifier_roles = [DidRole::Subject, DidRole::Witness, DidRole::Participant]
            .into_iter()
            .filter(|role| *role != target_role)
            .map(DidRole::as_str)
            .collect::<Vec<_>>()
            .join("+");
        let target_record = record_for_role(records, target_role).expect("record has target role");
        let expected_challenge = amount_token_for_role(amount_tokens, target_role);
        let challenge_matches_block = target_record.proof.challenge == expected_challenge;
        let target_signature_valid =
            verify_did_key_ownership(&target_record.did_key, &target_record.proof).is_ok();
        let block_result_matches = three_degree_phi_token_for_records(records)
            .map(|actual| actual == three_degree_phi_token)
            .unwrap_or(false);

        println!(
            "  operation {verifier_roles} verify {} from block_result = challenge:{challenge_matches_block}, signature:{target_signature_valid}, aggregate:{block_result_matches}",
            target_role.as_str()
        );
    }
}

fn records_without_proofs(signing_keys: &[SecretKey; 3]) -> Vec<DidKeyRecord> {
    signing_keys
        .iter()
        .enumerate()
        .map(|(index, signing_key)| {
            DidKeyRecord::new(
                did_key_for_secret_key(signing_key),
                role_for_index(index),
                OwnershipProof::new("", ""),
            )
        })
        .collect()
}

fn records_with_proofs(
    signing_keys: &[SecretKey; 3],
    amount_tokens: &AmountTokens,
) -> Vec<DidKeyRecord> {
    signing_keys
        .iter()
        .enumerate()
        .map(|(index, signing_key)| {
            let role = role_for_index(index);
            let submission = did_submission_for_key_with_challenge(
                signing_key,
                role,
                amount_token_for_role(amount_tokens, role),
            );

            DidKeyRecord::new(submission.did_key, submission.role, submission.proof)
        })
        .collect()
}

fn amount_token_for_role(amount_tokens: &AmountTokens, role: DidRole) -> &str {
    match role {
        DidRole::Subject => &amount_tokens.subject,
        DidRole::Witness => &amount_tokens.witness,
        DidRole::Participant => &amount_tokens.participant,
    }
}

fn role_for_index(index: usize) -> DidRole {
    match index {
        0 => DidRole::Subject,
        1 => DidRole::Witness,
        _ => DidRole::Participant,
    }
}

fn record_for_role(records: &[DidKeyRecord], role: DidRole) -> Option<&DidKeyRecord> {
    records.iter().find(|record| record.role == role)
}

fn did_key_for_role(records: &[DidKeyRecord], role: DidRole) -> &str {
    record_for_role(records, role)
        .map(|record| record.did_key.as_str())
        .expect("records contain requested role")
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

fn three_degree_phi_token_for_submissions(submissions: &[DidKeySubmission]) -> String {
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

    three_degree_phi_token_for_records(&records).expect("signatures should aggregate")
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
    use crate::did::DidKeyBlock;

    #[test]
    fn mined_genesis_blocks_prove_a_square() {
        let block = Block::genesis(12);

        assert!(block.proves_square(12));
        assert!(is_perfect_square(block.proof_square));
    }

    #[test]
    fn public_key_blocks_store_only_amount_proof_receipts() {
        let authority_key = bls_secret_key(42);
        let authority_did = did_key_for_secret_key(&authority_key);
        let mut blockchain = Blockchain::new(12, authority_key);

        let receipt = add_demo_public_key_block(
            &mut blockchain,
            [bls_secret_key(1), bls_secret_key(2), bls_secret_key(3)],
            7,
            &authority_did,
            None,
            None,
            None,
        );

        let BlockData::PublicKeys(block) = &blockchain.chain[1].data else {
            panic!("expected public key block");
        };

        assert_eq!(block.three_degree_phi_token, receipt.three_degree_phi_token);
        assert!(blockchain.is_valid());
    }

    #[test]
    fn rejects_wrong_three_degree_phi_token_at_creation() {
        let authority_key = bls_secret_key(42);
        let authority_did = did_key_for_secret_key(&authority_key);
        let mut blockchain = Blockchain::new(12, authority_key);
        let keys = [bls_secret_key(1), bls_secret_key(2), bls_secret_key(3)];
        let records = records_without_proofs(&keys);
        let amount_tokens = amount_tokens_for_records(&records, 7, &authority_did)
            .expect("amount tokens should derive");
        let submissions = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let role = role_for_index(index);
                did_submission_for_key_with_challenge(
                    key,
                    role,
                    amount_token_for_role(&amount_tokens, role),
                )
            })
            .collect::<Vec<_>>();

        let result = blockchain.add_public_key_block(submissions, 7, "wrong".to_string());

        assert!(result.is_err());
        assert_eq!(blockchain.chain.len(), 1);
    }

    #[test]
    fn rejects_linked_block_with_wrong_amount_at_creation() {
        let authority_key = bls_secret_key(42);
        let authority_did = did_key_for_secret_key(&authority_key);
        let mut blockchain = Blockchain::new(12, authority_key);
        let first = add_demo_public_key_block(
            &mut blockchain,
            [bls_secret_key(1), bls_secret_key(2), bls_secret_key(3)],
            7,
            &authority_did,
            None,
            None,
            None,
        );
        let second_keys = [bls_secret_key(3), bls_secret_key(4), bls_secret_key(5)];
        let second_records = records_without_proofs(&second_keys);
        let token_group = amount_token_group_for_block(
            &second_records,
            7,
            &authority_did,
            Some(did_key_for_role(&first.records, DidRole::Participant)),
            Some(first.amount),
            Some(&first.amount_tokens.participant),
        )
        .expect("linked token group should derive");
        let amount_tokens = amount_tokens_for_records(&second_records, 7, &token_group)
            .expect("linked amount tokens should derive");
        let submissions = second_keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let role = role_for_index(index);
                did_submission_for_key_with_challenge(
                    key,
                    role,
                    amount_token_for_role(&amount_tokens, role),
                )
            })
            .collect::<Vec<_>>();
        let three_degree_phi_token = three_degree_phi_token_for_submissions(&submissions);

        let result = blockchain.add_public_key_block(submissions, 8, three_degree_phi_token);

        assert!(matches!(
            result,
            Err(crate::did::OwnershipProofError::AmountDoesNotMatchToken {
                expected: 7,
                actual: 8
            })
        ));
    }

    #[test]
    fn tampering_receipt_authority_proof_breaks_validation() {
        let authority_key = bls_secret_key(42);
        let authority_did = did_key_for_secret_key(&authority_key);
        let mut blockchain = Blockchain::new(12, authority_key);
        add_demo_public_key_block(
            &mut blockchain,
            [bls_secret_key(1), bls_secret_key(2), bls_secret_key(3)],
            7,
            &authority_did,
            None,
            None,
            None,
        );

        let BlockData::PublicKeys(block) = &mut blockchain.chain[1].data else {
            panic!("expected public key block");
        };
        block.three_degree_phi_token_authority_proof.signature = "bad".to_string();
        blockchain.chain[1].hash = blockchain.chain[1].recalculate_hash();

        assert!(!blockchain.is_valid());
    }

    #[test]
    fn public_key_block_accepts_optional_witness() {
        let authority_key = bls_secret_key(42);
        let authority_did = did_key_for_secret_key(&authority_key);
        let mut blockchain = Blockchain::new(12, authority_key);
        let subject_key = bls_secret_key(1);
        let participant_key = bls_secret_key(3);
        let records = vec![
            DidKeyRecord::new(
                did_key_for_secret_key(&subject_key),
                DidRole::Subject,
                OwnershipProof::new("", ""),
            ),
            DidKeyRecord::new(
                did_key_for_secret_key(&participant_key),
                DidRole::Participant,
                OwnershipProof::new("", ""),
            ),
        ];
        let amount_tokens = amount_tokens_for_records(&records, 7, &authority_did)
            .expect("amount tokens should derive without witness");
        let submissions = vec![
            did_submission_for_key_with_challenge(
                &subject_key,
                DidRole::Subject,
                &amount_tokens.subject,
            ),
            did_submission_for_key_with_challenge(
                &participant_key,
                DidRole::Participant,
                &amount_tokens.participant,
            ),
        ];
        let three_degree_phi_token = three_degree_phi_token_for_submissions(&submissions);

        blockchain
            .add_public_key_block(submissions, 7, three_degree_phi_token)
            .expect("witness should be optional");

        assert_eq!(blockchain.chain.len(), 2);
        assert!(blockchain.is_valid());
    }

    #[test]
    fn receipt_block_creation_verifies_records_without_storing_them() {
        let authority_key = bls_secret_key(42);
        let authority_did = did_key_for_secret_key(&authority_key);
        let keys = [bls_secret_key(1), bls_secret_key(2), bls_secret_key(3)];
        let records = records_without_proofs(&keys);
        let amount_tokens = amount_tokens_for_records(&records, 7, &authority_did)
            .expect("amount tokens should derive");
        let submissions = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let role = role_for_index(index);
                did_submission_for_key_with_challenge(
                    key,
                    role,
                    amount_token_for_role(&amount_tokens, role),
                )
            })
            .collect::<Vec<_>>();
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
        let three_degree_phi_token = three_degree_phi_token_for_records(&records).unwrap();

        let block = DidKeyBlock::new(
            records,
            7,
            three_degree_phi_token,
            &bls_secret_key(42),
            None,
            None,
            None,
        )
        .expect("creation-time records should verify");

        assert!(!block.three_degree_phi_token.is_empty());
    }
}
