use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use blst::BLST_ERROR;
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
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
pub const MAX_AMOUNT: u8 = 99;

#[derive(Debug, Clone)]
pub struct DidKeyRecord {
    pub did_key: String,
    pub role: DidRole,
    pub proof: OwnershipProof,
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
    pub amount: u8,
    pub amount_token: String,
    pub amount_tokens: AmountTokens,
    pub amount_proof_key: String,
    pub amount_proof_key_authority_proof: OwnershipProof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmountTokens {
    pub subject: String,
    pub witness: String,
    pub participant: String,
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
    WrongDidCount {
        expected: usize,
        actual: usize,
    },
    WrongSubjectCount {
        expected: usize,
        actual: usize,
    },
    WrongWitnessCount {
        expected: usize,
        actual: usize,
    },
    WrongParticipantCount {
        expected: usize,
        actual: usize,
    },
    InvalidAmount {
        amount: u8,
    },
    UnsupportedDidKey,
    InvalidDidKeyEncoding(bs58::decode::Error),
    InvalidDidKeyLength {
        expected: usize,
        actual: usize,
    },
    InvalidPublicKeyLength(TryFromSliceError),
    InvalidSignatureEncoding(base64::DecodeError),
    InvalidPublicKey(BLST_ERROR),
    InvalidAmountToken(BLST_ERROR),
    AmountAuthorityKeyDoesNotMatch {
        expected: String,
        actual: String,
    },
    AmountTokensDoNotMatch {
        expected: AmountTokens,
        actual: AmountTokens,
    },
    AmountProofKeyDoesNotMatch {
        expected: String,
        actual: String,
    },
    AmountProofChallengeDoesNotMatch {
        expected: String,
        actual: String,
    },
    AmountProofKeyAuthorityChallengeDoesNotMatch {
        expected: String,
        actual: String,
    },
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
            Self::WrongParticipantCount { expected, actual } => {
                write!(
                    f,
                    "expected {expected} participant DID in block, got {actual}"
                )
            }
            Self::InvalidAmount { amount } => {
                write!(f, "amount must be between 1 and {MAX_AMOUNT}, got {amount}")
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
            Self::InvalidAmountToken(error) => write!(f, "amount token is invalid: {error:?}"),
            Self::AmountAuthorityKeyDoesNotMatch { expected, actual } => {
                write!(
                    f,
                    "amount authority key mismatch: expected {expected}, got {actual}"
                )
            }
            Self::AmountTokensDoNotMatch { expected, actual } => {
                write!(
                    f,
                    "amount tokens mismatch: expected {expected:?}, got {actual:?}"
                )
            }
            Self::AmountProofKeyDoesNotMatch { expected, actual } => {
                write!(
                    f,
                    "amount proof key mismatch: expected {expected}, got {actual}"
                )
            }
            Self::AmountProofChallengeDoesNotMatch { expected, actual } => {
                write!(
                    f,
                    "amount proof challenge mismatch: expected {expected}, got {actual}"
                )
            }
            Self::AmountProofKeyAuthorityChallengeDoesNotMatch { expected, actual } => {
                write!(
                    f,
                    "amount proof key authority challenge mismatch: expected {expected}, got {actual}"
                )
            }
            Self::InvalidSignature(error) => {
                write!(f, "signature does not match challenge: {error:?}")
            }
        }
    }
}

impl Error for OwnershipProofError {}

impl DidKeyRecord {
    pub fn new(did_key: impl Into<String>, role: DidRole, proof: OwnershipProof) -> Self {
        Self {
            did_key: did_key.into(),
            role,
            proof,
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "type=did-key;did_key={};role={};challenge={};signature={}",
            self.did_key,
            self.role.as_str(),
            self.proof.challenge,
            self.proof.signature
        )
        .into_bytes()
    }

    pub fn verify_supported_did_key(&self) -> Result<(), OwnershipProofError> {
        bls12_381_public_key_from_did_key(&self.did_key).map(|_| ())
    }

    pub fn verify_ownership_proof(&self) -> Result<(), OwnershipProofError> {
        verify_did_key_ownership(&self.did_key, &self.proof)
    }
}

impl DidKeyBlock {
    pub fn new(
        records: Vec<DidKeyRecord>,
        amount: u8,
        amount_proof_key: String,
        authority_signing_key: &SecretKey,
        previous_participant_did_key: Option<&str>,
        previous_participant_amount_token: Option<&str>,
    ) -> Result<Self, OwnershipProofError> {
        if records.len() != DIDS_PER_BLOCK {
            return Err(OwnershipProofError::WrongDidCount {
                expected: DIDS_PER_BLOCK,
                actual: records.len(),
            });
        }

        let authority_did_key =
            did_key_from_bls12_381_public_key(&authority_signing_key.sk_to_pk().compress());
        validate_amount(amount)?;
        let amount_authority_proof = sign_amount_authority_proof(authority_signing_key, amount)?;
        let amount_token = amount_token_for_block(
            &records,
            amount,
            &amount_authority_proof.signature,
            &authority_did_key,
            previous_participant_did_key,
            previous_participant_amount_token,
        )?;
        let amount_token_group = amount_token_group_for_block(
            &records,
            amount,
            &authority_did_key,
            previous_participant_did_key,
            previous_participant_amount_token,
        )?;
        let amount_tokens = amount_tokens_for_records(&records, amount, &amount_token_group)?;
        let amount_proof_key_authority_proof =
            sign_amount_proof_key_authority_proof(authority_signing_key, &amount_proof_key);
        let block = Self {
            records,
            amount,
            amount_token,
            amount_tokens,
            amount_proof_key,
            amount_proof_key_authority_proof,
        };
        block.verify_roles()?;
        block.verify_supported_did_keys()?;
        block.verify_amount_token(
            &authority_did_key,
            previous_participant_did_key,
            previous_participant_amount_token,
        )?;
        block.verify_amount_proof_key()?;
        block.verify_amount_proof_challenges()?;
        block.verify_amount_proof_key_authority_proof(&authority_did_key)?;
        block.verify_ownership_proofs()?;
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

        format!(
            "type=did-key-block;amount={};amount_token={};amount_tokens={};amount_proof_key={};amount_proof_key_authority_challenge={};amount_proof_key_authority_signature={};records={records}",
            self.amount,
            self.amount_token,
            self.amount_tokens.canonical_string(),
            self.amount_proof_key,
            self.amount_proof_key_authority_proof.challenge,
            self.amount_proof_key_authority_proof.signature
        )
        .into_bytes()
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

    pub fn verify_ownership_proofs(&self) -> Result<(), OwnershipProofError> {
        if self.records.len() != DIDS_PER_BLOCK {
            return Err(OwnershipProofError::WrongDidCount {
                expected: DIDS_PER_BLOCK,
                actual: self.records.len(),
            });
        }

        for record in &self.records {
            record.verify_ownership_proof()?;
        }

        Ok(())
    }

    pub fn verify_amount_token(
        &self,
        authority_did_key: &str,
        previous_participant_did_key: Option<&str>,
        previous_participant_amount_token: Option<&str>,
    ) -> Result<(), OwnershipProofError> {
        let actual_amount_token = amount_token_for_block(
            &self.records,
            self.amount,
            &self.amount_token,
            authority_did_key,
            previous_participant_did_key,
            previous_participant_amount_token,
        )?;
        if self.amount_token != actual_amount_token {
            return Err(OwnershipProofError::AmountAuthorityKeyDoesNotMatch {
                expected: self.amount_token.clone(),
                actual: actual_amount_token,
            });
        }

        let amount_token_group = amount_token_group_for_block(
            &self.records,
            self.amount,
            authority_did_key,
            previous_participant_did_key,
            previous_participant_amount_token,
        )?;
        let actual = amount_tokens_for_records(&self.records, self.amount, &amount_token_group)?;

        if self.amount_tokens == actual {
            Ok(())
        } else {
            Err(OwnershipProofError::AmountTokensDoNotMatch {
                expected: self.amount_tokens.clone(),
                actual,
            })
        }
    }

    pub fn verify_amount_proof_key(&self) -> Result<(), OwnershipProofError> {
        let actual = amount_proof_key_for_records(&self.records)?;

        if self.amount_proof_key == actual {
            Ok(())
        } else {
            Err(OwnershipProofError::AmountProofKeyDoesNotMatch {
                expected: self.amount_proof_key.clone(),
                actual,
            })
        }
    }

    pub fn verify_amount_proof_challenges(&self) -> Result<(), OwnershipProofError> {
        for record in &self.records {
            if record.proof.challenge != self.amount_token {
                return Err(OwnershipProofError::AmountProofChallengeDoesNotMatch {
                    expected: self.amount_token.clone(),
                    actual: record.proof.challenge.clone(),
                });
            }
        }

        Ok(())
    }

    pub fn verify_amount_proof_key_authority_proof(
        &self,
        authority_did_key: &str,
    ) -> Result<(), OwnershipProofError> {
        let expected = amount_proof_key_authority_challenge(&self.amount_proof_key);

        if self.amount_proof_key_authority_proof.challenge != expected {
            return Err(
                OwnershipProofError::AmountProofKeyAuthorityChallengeDoesNotMatch {
                    expected,
                    actual: self.amount_proof_key_authority_proof.challenge.clone(),
                },
            );
        }

        verify_did_key_ownership(authority_did_key, &self.amount_proof_key_authority_proof)
    }

    pub fn verify_mining_proof(
        &self,
        authority_did_key: &str,
        previous_participant_did_key: Option<&str>,
        previous_participant_amount_token: Option<&str>,
    ) -> Result<(), OwnershipProofError> {
        self.verify_amount_token(
            authority_did_key,
            previous_participant_did_key,
            previous_participant_amount_token,
        )?;
        self.verify_amount_proof_key()?;
        self.verify_amount_proof_challenges()?;
        self.verify_amount_proof_key_authority_proof(authority_did_key)?;
        self.verify_ownership_proofs()
    }

    pub fn participant_did_key(&self) -> Result<&str, OwnershipProofError> {
        self.did_key_for_role(DidRole::Participant)
    }

    fn did_key_for_role(&self, role: DidRole) -> Result<&str, OwnershipProofError> {
        self.records
            .iter()
            .find(|record| record.role == role)
            .map(|record| record.did_key.as_str())
            .ok_or_else(|| missing_role_error(role))
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
        let participant_count = self
            .records
            .iter()
            .filter(|record| record.role == DidRole::Participant)
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

        if participant_count != 1 {
            return Err(OwnershipProofError::WrongParticipantCount {
                expected: 1,
                actual: participant_count,
            });
        }

        Ok(())
    }
}

impl AmountTokens {
    fn canonical_string(&self) -> String {
        format!(
            "subject={};witness={};participant={}",
            self.subject, self.witness, self.participant
        )
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

        Ok(DidKeyRecord::new(self.did_key, self.role, self.proof))
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

pub fn amount_token_for_block(
    records: &[DidKeyRecord],
    amount: u8,
    amount_authority_signature: &str,
    authority_did_key: &str,
    previous_participant_did_key: Option<&str>,
    previous_participant_amount_token: Option<&str>,
) -> Result<String, OwnershipProofError> {
    let group_key = amount_token_group_for_block(
        records,
        amount,
        authority_did_key,
        previous_participant_did_key,
        previous_participant_amount_token,
    )?;

    if amount_token_uses_duplicate_bridge(records, previous_participant_did_key)? {
        Ok(group_key)
    } else {
        verify_amount_authority_signature(amount, authority_did_key, amount_authority_signature)?;
        Ok(amount_authority_signature.to_string())
    }
}

fn amount_token_group_for_block(
    records: &[DidKeyRecord],
    amount: u8,
    authority_did_key: &str,
    previous_participant_did_key: Option<&str>,
    previous_participant_amount_token: Option<&str>,
) -> Result<String, OwnershipProofError> {
    validate_amount(amount)?;
    let authority_amount_token = authority_did_key.to_string();
    let Some(previous_participant_did_key) = previous_participant_did_key else {
        return Ok(authority_amount_token);
    };
    let current_subject_did_key = records
        .iter()
        .find(|record| record.role == DidRole::Subject)
        .map(|record| record.did_key.as_str())
        .ok_or_else(|| missing_role_error(DidRole::Subject))?;

    if current_subject_did_key != previous_participant_did_key {
        return Ok(authority_amount_token);
    }

    previous_participant_amount_token
        .map(str::to_string)
        .ok_or_else(|| missing_role_error(DidRole::Participant))
}

fn amount_token_uses_duplicate_bridge(
    records: &[DidKeyRecord],
    previous_participant_did_key: Option<&str>,
) -> Result<bool, OwnershipProofError> {
    let Some(previous_participant_did_key) = previous_participant_did_key else {
        return Ok(false);
    };
    let current_subject_did_key = records
        .iter()
        .find(|record| record.role == DidRole::Subject)
        .map(|record| record.did_key.as_str())
        .ok_or_else(|| missing_role_error(DidRole::Subject))?;

    Ok(current_subject_did_key == previous_participant_did_key)
}

pub fn amount_tokens_for_records(
    records: &[DidKeyRecord],
    amount: u8,
    amount_token: &str,
) -> Result<AmountTokens, OwnershipProofError> {
    validate_amount(amount)?;
    let amount_public_key = public_key_from_did_key(amount_token)?;

    Ok(AmountTokens {
        subject: amount_token_for_role(records, DidRole::Subject, amount, &amount_public_key)?,
        witness: amount_token_for_role(records, DidRole::Witness, amount, &amount_public_key)?,
        participant: amount_token_for_role(
            records,
            DidRole::Participant,
            amount,
            &amount_public_key,
        )?,
    })
}

pub fn amount_proof_key_for_records(
    records: &[DidKeyRecord],
) -> Result<String, OwnershipProofError> {
    let signatures = records
        .iter()
        .map(|record| signature_from_proof(&record.proof))
        .collect::<Result<Vec<_>, _>>()?;
    let signature_refs = signatures.iter().collect::<Vec<_>>();
    let aggregate = AggregateSignature::aggregate(&signature_refs, true)
        .map_err(OwnershipProofError::InvalidSignature)?;

    Ok(base64url(&aggregate.to_signature().compress()))
}

fn amount_token_for_role(
    records: &[DidKeyRecord],
    role: DidRole,
    amount: u8,
    amount_public_key: &PublicKey,
) -> Result<String, OwnershipProofError> {
    let record = records
        .iter()
        .find(|record| record.role == role)
        .ok_or_else(|| missing_role_error(role))?;
    let role_amount_token = amount_token_for_did_key(&record.did_key, amount)?;
    let role_public_key = public_key_from_did_key(&role_amount_token)?;

    aggregate_public_keys(&[amount_public_key, &role_public_key])
}

pub fn amount_authority_challenge(amount: u8) -> Result<String, OwnershipProofError> {
    validate_amount(amount)?;

    Ok(format!("authorize phi-crypto amount {amount}"))
}

pub fn amount_proof_key_authority_challenge(amount_proof_key: &str) -> String {
    format!("authorize phi-crypto amount proof key {amount_proof_key}")
}

fn sign_amount_authority_proof(
    signing_key: &SecretKey,
    amount: u8,
) -> Result<OwnershipProof, OwnershipProofError> {
    let challenge = amount_authority_challenge(amount)?;
    let signature = signing_key.sign(challenge.as_bytes(), BLS_SIGNATURE_DST, &[]);

    Ok(OwnershipProof::new(
        challenge,
        base64url(&signature.compress()),
    ))
}

fn sign_amount_proof_key_authority_proof(
    signing_key: &SecretKey,
    amount_proof_key: &str,
) -> OwnershipProof {
    let challenge = amount_proof_key_authority_challenge(amount_proof_key);
    let signature = signing_key.sign(challenge.as_bytes(), BLS_SIGNATURE_DST, &[]);

    OwnershipProof::new(challenge, base64url(&signature.compress()))
}

fn verify_amount_authority_signature(
    amount: u8,
    authority_did_key: &str,
    signature: &str,
) -> Result<(), OwnershipProofError> {
    let challenge = amount_authority_challenge(amount)?;

    verify_did_key_ownership(
        authority_did_key,
        &OwnershipProof::new(challenge, signature.to_string()),
    )
}

pub fn amount_token_for_did_key(did_key: &str, amount: u8) -> Result<String, OwnershipProofError> {
    validate_amount(amount)?;
    let public_key = public_key_from_did_key(did_key)?;
    let public_key_refs = (0..amount).map(|_| &public_key).collect::<Vec<_>>();
    let aggregate = AggregatePublicKey::aggregate(&public_key_refs, true)
        .map_err(OwnershipProofError::InvalidAmountToken)?;
    let amount_token = aggregate.to_public_key().compress();

    Ok(did_key_from_bls12_381_public_key(&amount_token))
}

fn aggregate_public_keys(public_keys: &[&PublicKey]) -> Result<String, OwnershipProofError> {
    let aggregate = AggregatePublicKey::aggregate(public_keys, true)
        .map_err(OwnershipProofError::InvalidAmountToken)?;
    let amount_token = aggregate.to_public_key().compress();

    Ok(did_key_from_bls12_381_public_key(&amount_token))
}

fn missing_role_error(role: DidRole) -> OwnershipProofError {
    match role {
        DidRole::Subject => OwnershipProofError::WrongSubjectCount {
            expected: 1,
            actual: 0,
        },
        DidRole::Witness => OwnershipProofError::WrongWitnessCount {
            expected: 1,
            actual: 0,
        },
        DidRole::Participant => OwnershipProofError::WrongParticipantCount {
            expected: 1,
            actual: 0,
        },
    }
}

pub fn verify_did_key_ownership(
    did_key: &str,
    proof: &OwnershipProof,
) -> Result<(), OwnershipProofError> {
    let public_key = public_key_from_did_key(did_key)?;
    let signature = signature_from_proof(proof)?;

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

fn signature_from_proof(proof: &OwnershipProof) -> Result<Signature, OwnershipProofError> {
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&proof.signature)
        .map_err(OwnershipProofError::InvalidSignatureEncoding)?;

    Signature::uncompress(&signature_bytes).map_err(OwnershipProofError::InvalidSignature)
}

fn base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn validate_amount(amount: u8) -> Result<(), OwnershipProofError> {
    if (1..=MAX_AMOUNT).contains(&amount) {
        Ok(())
    } else {
        Err(OwnershipProofError::InvalidAmount { amount })
    }
}

fn public_key_from_did_key(did_key: &str) -> Result<PublicKey, OwnershipProofError> {
    let public_key_bytes = bls12_381_public_key_from_did_key(did_key)?;

    PublicKey::uncompress(&public_key_bytes).map_err(OwnershipProofError::InvalidPublicKey)
}
