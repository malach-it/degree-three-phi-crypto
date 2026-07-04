mod block;
mod blockchain;
mod did;

use blockchain::Blockchain;
use blst::min_pk::SecretKey;
use did::{
    BLS_SIGNATURE_DST, DidKeySubmission, DidRole, OwnershipProof, did_key_from_bls12_381_public_key,
};

const DEFAULT_DIFFICULTY_BITS: u8 = 16;

fn main() {
    let mut blockchain = Blockchain::new(DEFAULT_DIFFICULTY_BITS);

    add_demo_public_key_block(
        &mut blockchain,
        [bls_secret_key(7), bls_secret_key(8), bls_secret_key(9)],
    );
    add_demo_public_key_block(
        &mut blockchain,
        [bls_secret_key(10), bls_secret_key(11), bls_secret_key(12)],
    );

    for block in &blockchain.chain {
        println!(
            "block #{}, nonce {}, square-proof {}, hash {}, data {:?}\n",
            block.index, block.nonce, block.proof_square, block.hash, block.data
        );
    }

    println!("chain valid: {}", blockchain.is_valid());
}

fn add_demo_public_key_block(blockchain: &mut Blockchain, signing_keys: [SecretKey; 3]) {
    let submissions = signing_keys
        .iter()
        .enumerate()
        .map(|(index, signing_key)| {
            let role = match index {
                0 => DidRole::Subject,
                1 => DidRole::Witness,
                _ => DidRole::Participant,
            };
            did_submission_for_key(signing_key, role)
        })
        .collect::<Vec<_>>();

    blockchain
        .add_public_key_block(submissions)
        .expect("public key ownership proofs should verify");
}

fn did_submission_for_key(signing_key: &SecretKey, role: DidRole) -> DidKeySubmission {
    let public_key = signing_key.sk_to_pk().compress();
    let did_key = did_key_from_bls12_381_public_key(&public_key);
    let challenge = format!("add {did_key} to phi-crypto");
    let signature = signing_key.sign(challenge.as_bytes(), BLS_SIGNATURE_DST, &[]);

    DidKeySubmission::with_role(
        did_key,
        role,
        OwnershipProof::new(challenge, base64url(&signature.compress())),
    )
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
    use crate::did::{DidKeyBlock, DidKeyRecord};

    #[test]
    fn mined_blocks_prove_a_square() {
        let block = Block::mine(
            1,
            BlockData::PublicKeys(test_did_key_block([1, 2, 3])),
            "abc".to_string(),
            12,
        );

        assert!(block.proves_square(12));
        assert!(is_perfect_square(block.proof_square));
    }

    #[test]
    fn blockchain_validates_linked_blocks() {
        let mut blockchain = Blockchain::new(12);

        add_test_public_key_block(&mut blockchain, [1, 2, 3]);
        add_test_public_key_block(&mut blockchain, [4, 5, 6]);

        assert!(blockchain.is_valid());
    }

    #[test]
    fn blockchain_can_store_three_dids_with_witness_tags() {
        let mut blockchain = Blockchain::new(12);
        let submissions = test_submissions([3, 4, 5]);
        let expected_did = submissions[0].did_key.clone();

        blockchain
            .add_public_key_block(submissions)
            .expect("ownership proof should verify");

        assert!(blockchain.is_valid());

        let BlockData::PublicKeys(records) = &blockchain.chain[1].data else {
            panic!("expected public keys block");
        };
        let record = &records.records[0];

        assert_eq!(records.records.len(), 3);
        assert_eq!(records.records[0].role, DidRole::Subject);
        assert_eq!(records.records[1].role, DidRole::Witness);
        assert_eq!(records.records[2].role, DidRole::Participant);
        assert_ne!(records.records[0].did_key, records.records[1].did_key);
        assert_eq!(record.did_key, expected_did);
    }

    #[test]
    fn rejects_public_key_block_without_valid_ownership_proof() {
        let mut blockchain = Blockchain::new(12);
        let wrong_signing_key = bls_secret_key(5);
        let mut submissions = test_submissions([4, 5, 6]);
        let challenge = format!("prove ownership for {}", submissions[0].did_key);
        let signature = wrong_signing_key.sign(challenge.as_bytes(), BLS_SIGNATURE_DST, &[]);
        submissions[0].proof = OwnershipProof::new(challenge, base64url(&signature.compress()));

        let result = blockchain.add_public_key_block(submissions);

        assert!(result.is_err());
        assert_eq!(blockchain.chain.len(), 1);
    }

    #[test]
    fn rejects_public_key_block_without_exactly_three_dids() {
        let mut blockchain = Blockchain::new(12);
        let result = blockchain.add_public_key_block(test_submissions([1, 2, 3])[0..2].to_vec());

        assert!(result.is_err());
        assert_eq!(blockchain.chain.len(), 1);
    }

    #[test]
    fn rejects_public_key_block_without_exactly_one_witness() {
        let mut blockchain = Blockchain::new(12);
        let result = blockchain.add_public_key_block(vec![
            did_submission_for_key(&bls_secret_key(1), DidRole::Subject),
            did_submission_for_key(&bls_secret_key(2), DidRole::Subject),
            did_submission_for_key(&bls_secret_key(3), DidRole::Subject),
        ]);

        assert!(result.is_err());
        assert_eq!(blockchain.chain.len(), 1);
    }

    #[test]
    fn rejects_public_key_block_with_two_witnesses() {
        let mut blockchain = Blockchain::new(12);
        let result = blockchain.add_public_key_block(vec![
            did_submission_for_key(&bls_secret_key(1), DidRole::Subject),
            did_submission_for_key(&bls_secret_key(2), DidRole::Witness),
            did_submission_for_key(&bls_secret_key(3), DidRole::Witness),
        ]);

        assert!(result.is_err());
        assert_eq!(blockchain.chain.len(), 1);
    }

    #[test]
    fn rejects_public_key_block_with_unsupported_did_key() {
        let mut blockchain = Blockchain::new(12);
        let mut submissions = test_submissions([8, 9, 10]);
        submissions[0].did_key = "did:key:z6MkiTBzInvalidExample".to_string();

        let result = blockchain.add_public_key_block(submissions);

        assert!(result.is_err());
        assert_eq!(blockchain.chain.len(), 1);
    }

    #[test]
    fn rejects_non_did_key_identifier() {
        let mut blockchain = Blockchain::new(12);
        let signing_key = bls_secret_key(11);
        let mut submissions = test_submissions([11, 12, 13]);
        let challenge = "prove ownership for non did:key identifier";
        let signature = signing_key.sign(challenge.as_bytes(), BLS_SIGNATURE_DST, &[]);
        submissions[0] = DidKeySubmission::with_role(
            "did:web:example.com",
            DidRole::Subject,
            OwnershipProof::new(challenge, base64url(&signature.compress())),
        );

        let result = blockchain.add_public_key_block(submissions);

        assert!(result.is_err());
        assert_eq!(blockchain.chain.len(), 1);
    }

    #[test]
    fn validation_rejects_public_key_block_with_unsupported_did_key() {
        let mut blockchain = Blockchain::new(12);

        add_test_public_key_block(&mut blockchain, [9, 10, 11]);

        let BlockData::PublicKeys(records) = &mut blockchain.chain[1].data else {
            panic!("expected public keys block");
        };
        records.records[0].did_key = "did:key:z6MkiTBzTamperedDid".to_string();

        blockchain.chain[1].hash = blockchain.chain[1].recalculate_hash();

        assert!(!blockchain.is_valid());
    }

    #[test]
    fn tampering_breaks_validation() {
        let mut blockchain = Blockchain::new(12);

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
        blockchain
            .add_public_key_block(test_submissions(key_bytes))
            .expect("ownership proofs should verify");
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

    fn test_did_key_block(key_bytes: [u8; 3]) -> DidKeyBlock {
        let records = key_bytes
            .into_iter()
            .enumerate()
            .map(|(index, byte)| {
                let role = match index {
                    0 => DidRole::Subject,
                    1 => DidRole::Witness,
                    _ => DidRole::Participant,
                };
                test_did_key_record(&bls_secret_key(byte), role)
            })
            .collect();

        DidKeyBlock::new(records).expect("test records should build a valid DID block")
    }

    fn test_did_key_record(signing_key: &SecretKey, role: DidRole) -> DidKeyRecord {
        let did_key = did_key_from_bls12_381_public_key(&signing_key.sk_to_pk().compress());

        DidKeyRecord::new(did_key, role)
    }
}
