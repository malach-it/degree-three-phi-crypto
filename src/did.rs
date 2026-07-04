use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use blst::BLST_ERROR;
use blst::min_pk::{PublicKey, Signature};
use std::array::TryFromSliceError;
use std::error::Error;
use std::fmt;

const DID_KEY_PREFIX: &str = "did:key:z";
const BLS12_381_G1_DID_KEY_PREFIX: [u8; 2] = [0xea, 0x01];
const BLS12_381_G1_PUBLIC_KEY_LENGTH: usize = 48;
const BLS12_381_G1_DID_KEY_LENGTH: usize =
    BLS12_381_G1_DID_KEY_PREFIX.len() + BLS12_381_G1_PUBLIC_KEY_LENGTH;
pub const BLS_SIGNATURE_DST: &[u8] = b"PHI_CRYPTO_BLS12_381_PROOF_V1";
pub const DIDS_PER_BLOCK: usize = 3;

#[derive(Debug, Clone)]
pub struct DidKeyRecord {
    pub did_key: String,
    pub role: DidRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DidRole {
    Subject,
    Witness,
    Participant,
}

#[derive(Debug, Clone)]
pub struct DidKeyBlock {
    pub records: Vec<DidKeyRecord>,
}

#[derive(Debug, Clone)]
pub struct DidKeySubmission {
    pub did_key: String,
    pub role: DidRole,
    pub proof: OwnershipProof,
}

#[derive(Debug, Clone)]
pub struct OwnershipProof {
    pub challenge: String,
    pub signature: String,
}

#[derive(Debug)]
pub enum OwnershipProofError {
    WrongDidCount { expected: usize, actual: usize },
    WrongSubjectCount { expected: usize, actual: usize },
    WrongWitnessCount { expected: usize, actual: usize },
    UnsupportedDidKey,
    InvalidDidKeyEncoding(bs58::decode::Error),
    InvalidDidKeyLength { expected: usize, actual: usize },
    InvalidPublicKeyLength(TryFromSliceError),
    InvalidSignatureEncoding(base64::DecodeError),
    InvalidPublicKey(BLST_ERROR),
    InvalidSignature(BLST_ERROR),
}

impl fmt::Display for OwnershipProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongDidCount { expected, actual } => {
                write!(f, "expected {expected} DIDs in block, got {actual}")
            }
            Self::WrongSubjectCount { expected, actual } => {
                write!(f, "expected {expected} subject DID in block, got {actual}")
            }
            Self::WrongWitnessCount { expected, actual } => {
                write!(f, "expected {expected} witness DID in block, got {actual}")
            }
            Self::UnsupportedDidKey => write!(f, "only did:key BLS12-381 G1 keys are supported"),
            Self::InvalidDidKeyEncoding(error) => {
                write!(f, "did:key is not valid base58btc: {error}")
            }
            Self::InvalidDidKeyLength { expected, actual } => {
                write!(
                    f,
                    "expected did:key payload length {expected}, got {actual}"
                )
            }
            Self::InvalidPublicKeyLength(error) => {
                write!(f, "public key has invalid length: {error}")
            }
            Self::InvalidSignatureEncoding(error) => {
                write!(f, "signature is not valid base64url: {error}")
            }
            Self::InvalidPublicKey(error) => write!(f, "public key is invalid: {error:?}"),
            Self::InvalidSignature(error) => {
                write!(f, "signature does not match challenge: {error:?}")
            }
        }
    }
}

impl Error for OwnershipProofError {}

impl DidKeyRecord {
    pub fn new(did_key: impl Into<String>, role: DidRole) -> Self {
        Self {
            did_key: did_key.into(),
            role,
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "type=did-key;did_key={};role={}",
            self.did_key,
            self.role.as_str()
        )
        .into_bytes()
    }

    pub fn verify_supported_did_key(&self) -> Result<(), OwnershipProofError> {
        bls12_381_public_key_from_did_key(&self.did_key).map(|_| ())
    }
}

impl DidKeyBlock {
    pub fn new(records: Vec<DidKeyRecord>) -> Result<Self, OwnershipProofError> {
        if records.len() != DIDS_PER_BLOCK {
            return Err(OwnershipProofError::WrongDidCount {
                expected: DIDS_PER_BLOCK,
                actual: records.len(),
            });
        }

        let block = Self { records };
        block.verify_roles()?;
        block.verify_supported_did_keys()?;
        Ok(block)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let records = self
            .records
            .iter()
            .map(|record| {
                String::from_utf8(record.canonical_bytes()).expect("canonical bytes are utf8")
            })
            .collect::<Vec<_>>()
            .join("|");

        format!("type=did-key-block;records={records}").into_bytes()
    }

    pub fn verify_supported_did_keys(&self) -> Result<(), OwnershipProofError> {
        if self.records.len() != DIDS_PER_BLOCK {
            return Err(OwnershipProofError::WrongDidCount {
                expected: DIDS_PER_BLOCK,
                actual: self.records.len(),
            });
        }

        for record in &self.records {
            record.verify_supported_did_key()?;
        }

        Ok(())
    }

    pub fn verify_roles(&self) -> Result<(), OwnershipProofError> {
        let subject_count = self
            .records
            .iter()
            .filter(|record| record.role == DidRole::Subject)
            .count();
        let witness_count = self
            .records
            .iter()
            .filter(|record| record.role == DidRole::Witness)
            .count();

        if subject_count != 1 {
            return Err(OwnershipProofError::WrongSubjectCount {
                expected: 1,
                actual: subject_count,
            });
        }

        if witness_count != 1 {
            return Err(OwnershipProofError::WrongWitnessCount {
                expected: 1,
                actual: witness_count,
            });
        }

        Ok(())
    }
}

impl DidKeySubmission {
    pub fn with_role(did_key: impl Into<String>, role: DidRole, proof: OwnershipProof) -> Self {
        Self {
            did_key: did_key.into(),
            role,
            proof,
        }
    }

    pub fn into_verified_record(self) -> Result<DidKeyRecord, OwnershipProofError> {
        verify_did_key_ownership(&self.did_key, &self.proof)?;

        Ok(DidKeyRecord::new(self.did_key, self.role))
    }
}

impl DidRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Subject => "subject",
            Self::Witness => "witness",
            Self::Participant => "participant",
        }
    }
}

impl OwnershipProof {
    pub fn new(challenge: impl Into<String>, signature: impl Into<String>) -> Self {
        Self {
            challenge: challenge.into(),
            signature: signature.into(),
        }
    }
}

pub fn did_key_from_bls12_381_public_key(public_key: &[u8; 48]) -> String {
    let mut prefixed_key = Vec::with_capacity(BLS12_381_G1_DID_KEY_LENGTH);

    prefixed_key.extend_from_slice(&BLS12_381_G1_DID_KEY_PREFIX);
    prefixed_key.extend_from_slice(public_key);

    format!("did:key:z{}", bs58::encode(prefixed_key).into_string())
}

pub fn bls12_381_public_key_from_did_key(did_key: &str) -> Result<[u8; 48], OwnershipProofError> {
    let encoded = did_key
        .strip_prefix(DID_KEY_PREFIX)
        .ok_or(OwnershipProofError::UnsupportedDidKey)?;
    let payload = bs58::decode(encoded)
        .into_vec()
        .map_err(OwnershipProofError::InvalidDidKeyEncoding)?;

    if payload.len() != BLS12_381_G1_DID_KEY_LENGTH {
        return Err(OwnershipProofError::InvalidDidKeyLength {
            expected: BLS12_381_G1_DID_KEY_LENGTH,
            actual: payload.len(),
        });
    }

    if payload[..BLS12_381_G1_DID_KEY_PREFIX.len()] != BLS12_381_G1_DID_KEY_PREFIX {
        return Err(OwnershipProofError::UnsupportedDidKey);
    }

    payload[BLS12_381_G1_DID_KEY_PREFIX.len()..]
        .try_into()
        .map_err(OwnershipProofError::InvalidPublicKeyLength)
}

pub fn verify_did_key_ownership(
    did_key: &str,
    proof: &OwnershipProof,
) -> Result<(), OwnershipProofError> {
    let public_key_bytes = bls12_381_public_key_from_did_key(did_key)?;
    let public_key =
        PublicKey::uncompress(&public_key_bytes).map_err(OwnershipProofError::InvalidPublicKey)?;

    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&proof.signature)
        .map_err(OwnershipProofError::InvalidSignatureEncoding)?;
    let signature =
        Signature::uncompress(&signature_bytes).map_err(OwnershipProofError::InvalidSignature)?;

    let result = signature.verify(
        true,
        proof.challenge.as_bytes(),
        BLS_SIGNATURE_DST,
        &[],
        &public_key,
        true,
    );

    if result == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(OwnershipProofError::InvalidSignature(result))
    }
}
