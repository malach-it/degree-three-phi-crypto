mod block;
mod blockchain;
mod did;

use blockchain::Blockchain;
use did::{OwnershipProof, PublicJwk};
use ed25519_dalek::{Signer, SigningKey};

const DEFAULT_DIFFICULTY_BITS: u8 = 16;

fn main() {
    let mut blockchain = Blockchain::new(DEFAULT_DIFFICULTY_BITS);

    add_demo_public_key_block(&mut blockchain, SigningKey::from_bytes(&[7; 32]));
    add_demo_public_key_block(&mut blockchain, SigningKey::from_bytes(&[8; 32]));

    for block in &blockchain.chain {
        println!(
            "block #{}, nonce {}, square-proof {}, hash {}, data {:?}\n",
            block.index, block.nonce, block.proof_square, block.hash, block.data
        );
    }

    println!("chain valid: {}", blockchain.is_valid());
}

fn add_demo_public_key_block(blockchain: &mut Blockchain, signing_key: SigningKey) {
    let public_jwk = PublicJwk::ed25519_public(base64url(&signing_key.verifying_key().to_bytes()));
    let did_key = public_jwk
        .to_did_key()
        .expect("demo public key should produce a did:key");
    let challenge = format!("add {did_key} to phi-crypto");
    let signature = signing_key.sign(challenge.as_bytes());

    blockchain
        .add_public_key_block(
            did_key,
            public_jwk,
            OwnershipProof::new(challenge, base64url(&signature.to_bytes())),
        )
        .expect("public key ownership proof should verify");
}

fn base64url(bytes: &[u8]) -> String {
    use base64::Engine;

    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Block, BlockData, is_perfect_square};
    use crate::did::DidKeyRecord;
    use ed25519_dalek::SigningKey;

    #[test]
    fn mined_blocks_prove_a_square() {
        let block = Block::mine(
            1,
            BlockData::PublicKey(test_did_key_record(&SigningKey::from_bytes(&[1; 32]))),
            "abc".to_string(),
            12,
        );

        assert!(block.proves_square(12));
        assert!(is_perfect_square(block.proof_square));
    }

    #[test]
    fn blockchain_validates_linked_blocks() {
        let mut blockchain = Blockchain::new(12);
        let first_key = SigningKey::from_bytes(&[1; 32]);
        let second_key = SigningKey::from_bytes(&[2; 32]);

        add_test_public_key_block(&mut blockchain, &first_key);
        add_test_public_key_block(&mut blockchain, &second_key);

        assert!(blockchain.is_valid());
    }

    #[test]
    fn blockchain_can_store_did_key_public_jwk() {
        let mut blockchain = Blockchain::new(12);
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let public_jwk =
            PublicJwk::ed25519_public(base64url(&signing_key.verifying_key().to_bytes()));
        let did_key = public_jwk.to_did_key().expect("test key should make a DID");
        let challenge = format!("prove ownership for {did_key}");
        let signature = signing_key.sign(challenge.as_bytes());

        blockchain
            .add_public_key_block(
                &did_key,
                public_jwk,
                OwnershipProof::new(challenge, base64url(&signature.to_bytes())),
            )
            .expect("ownership proof should verify");

        assert!(blockchain.is_valid());

        let BlockData::PublicKey(record) = &blockchain.chain[1].data else {
            panic!("expected public key block");
        };

        assert_eq!(record.did_key, did_key);
        assert_eq!(record.public_jwk.kty, "OKP");
        assert_eq!(record.public_jwk.crv.as_deref(), Some("Ed25519"));
    }

    #[test]
    fn rejects_public_key_block_without_valid_ownership_proof() {
        let mut blockchain = Blockchain::new(12);
        let signing_key = SigningKey::from_bytes(&[4; 32]);
        let wrong_signing_key = SigningKey::from_bytes(&[5; 32]);
        let public_jwk =
            PublicJwk::ed25519_public(base64url(&signing_key.verifying_key().to_bytes()));
        let did_key = public_jwk.to_did_key().expect("test key should make a DID");
        let challenge = format!("prove ownership for {did_key}");
        let signature = wrong_signing_key.sign(challenge.as_bytes());

        let result = blockchain.add_public_key_block(
            did_key,
            public_jwk,
            OwnershipProof::new(challenge, base64url(&signature.to_bytes())),
        );

        assert!(result.is_err());
        assert_eq!(blockchain.chain.len(), 1);
    }

    #[test]
    fn rejects_public_key_block_when_did_does_not_match_jwk() {
        let mut blockchain = Blockchain::new(12);
        let signing_key = SigningKey::from_bytes(&[8; 32]);
        let public_jwk =
            PublicJwk::ed25519_public(base64url(&signing_key.verifying_key().to_bytes()));
        let challenge = "prove ownership for mismatched did:key";
        let signature = signing_key.sign(challenge.as_bytes());

        let result = blockchain.add_public_key_block(
            "did:key:z6MkiTBzMismatchedExample",
            public_jwk,
            OwnershipProof::new(challenge, base64url(&signature.to_bytes())),
        );

        assert!(result.is_err());
        assert_eq!(blockchain.chain.len(), 1);
    }

    #[test]
    fn rejects_symmetric_jwk() {
        let mut blockchain = Blockchain::new(12);
        let signing_key = SigningKey::from_bytes(&[10; 32]);
        let challenge = "prove ownership for symmetric jwk";
        let signature = signing_key.sign(challenge.as_bytes());

        let result = blockchain.add_public_key_block(
            "did:key:z6MkiTBzSymmetricExample",
            PublicJwk {
                kty: "oct".to_string(),
                crv: None,
                x: None,
                y: None,
                e: None,
                n: None,
                d: None,
                k: Some("not-public-asymmetric-key-material".to_string()),
            },
            OwnershipProof::new(challenge, base64url(&signature.to_bytes())),
        );

        assert!(result.is_err());
        assert_eq!(blockchain.chain.len(), 1);
    }

    #[test]
    fn rejects_jwk_with_private_key_material() {
        let mut blockchain = Blockchain::new(12);
        let signing_key = SigningKey::from_bytes(&[11; 32]);
        let mut public_jwk =
            PublicJwk::ed25519_public(base64url(&signing_key.verifying_key().to_bytes()));
        let did_key = public_jwk.to_did_key().expect("test key should make a DID");
        public_jwk.d = Some("private-key-material-must-not-be-stored".to_string());
        let challenge = format!("prove ownership for {did_key}");
        let signature = signing_key.sign(challenge.as_bytes());

        let result = blockchain.add_public_key_block(
            did_key,
            public_jwk,
            OwnershipProof::new(challenge, base64url(&signature.to_bytes())),
        );

        assert!(result.is_err());
        assert_eq!(blockchain.chain.len(), 1);
    }

    #[test]
    fn validation_rejects_public_key_block_when_did_does_not_match_jwk() {
        let mut blockchain = Blockchain::new(12);
        let signing_key = SigningKey::from_bytes(&[9; 32]);

        add_test_public_key_block(&mut blockchain, &signing_key);

        let BlockData::PublicKey(record) = &mut blockchain.chain[1].data else {
            panic!("expected public key block");
        };
        record.did_key = "did:key:z6MkiTBzTamperedDid".to_string();

        blockchain.chain[1].hash = blockchain.chain[1].recalculate_hash();

        assert!(!blockchain.is_valid());
    }

    #[test]
    fn tampering_breaks_validation() {
        let mut blockchain = Blockchain::new(12);
        let signing_key = SigningKey::from_bytes(&[6; 32]);

        add_test_public_key_block(&mut blockchain, &signing_key);
        blockchain.chain[1].data =
            BlockData::PublicKey(test_did_key_record(&SigningKey::from_bytes(&[7; 32])));

        assert!(!blockchain.is_valid());
    }

    #[test]
    fn detects_square_values() {
        assert!(is_perfect_square(0));
        assert!(is_perfect_square(1));
        assert!(is_perfect_square(144));
        assert!(!is_perfect_square(145));
    }

    fn add_test_public_key_block(blockchain: &mut Blockchain, signing_key: &SigningKey) {
        let public_jwk =
            PublicJwk::ed25519_public(base64url(&signing_key.verifying_key().to_bytes()));
        let did_key = public_jwk.to_did_key().expect("test key should make a DID");
        let challenge = format!("prove ownership for {did_key}");
        let signature = signing_key.sign(challenge.as_bytes());

        blockchain
            .add_public_key_block(
                did_key,
                public_jwk,
                OwnershipProof::new(challenge, base64url(&signature.to_bytes())),
            )
            .expect("ownership proof should verify");
    }

    fn test_did_key_record(signing_key: &SigningKey) -> DidKeyRecord {
        let public_jwk =
            PublicJwk::ed25519_public(base64url(&signing_key.verifying_key().to_bytes()));
        let did_key = public_jwk.to_did_key().expect("test key should make a DID");

        DidKeyRecord::new(did_key, public_jwk)
    }
}
