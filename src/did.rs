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
pub const MIN_DIDS_PER_BLOCK: usize = 2;
pub const MAX_DIDS_PER_BLOCK: usize = 3;
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
    pub degree_three_phi_token: String,
    pub degree_three_phi_token_authority_proof: OwnershipProof,
    pub disclosure_commitment: Option<String>,
    pub disclosure_group_id: Option<String>,
    pub disclosure_hop: Option<u8>,
    pub disclosure_max_depth: Option<u8>,
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
    WrongDidCount { expected: usize, actual: usize },
    WrongSubjectCount { expected: usize, actual: usize },
    WrongWitnessCount { expected: usize, actual: usize },
    WrongParticipantCount { expected: usize, actual: usize },
    InvalidAmount { amount: u8 },
    UnsupportedDidKey,
    InvalidDidKeyEncoding(bs58::decode::Error),
    InvalidDidKeyLength { expected: usize, actual: usize },
    InvalidPublicKeyLength(TryFromSliceError),
    InvalidSignatureEncoding(base64::DecodeError),
    InvalidPublicKey(BLST_ERROR),
    InvalidAmountToken(BLST_ERROR),
    InvalidDisclosureCommitment,
    AmountDoesNotMatchToken { expected: u8, actual: u8 },
    ThreeDegreePhiTokenDoesNotMatch { expected: String, actual: String },
    AmountProofChallengeDoesNotMatch { expected: String, actual: String },
    ThreeDegreePhiTokenAuthorityChallengeDoesNotMatch { expected: String, actual: String },
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
            Self::InvalidAmountToken(error) => {
                write!(f, "amount token is invalid: {error:?}")
            }
            Self::InvalidDisclosureCommitment => {
                write!(
                    f,
                    "disclosure commitment must be φtrait_ followed by hexadecimal bytes"
                )
            }
            Self::AmountDoesNotMatchToken { expected, actual } => {
                write!(
                    f,
                    "amount does not match amount token: expected {expected}, got {actual}"
                )
            }
            Self::ThreeDegreePhiTokenDoesNotMatch { expected, actual } => {
                write!(
                    f,
                    "degree three phi token mismatch: expected {expected}, got {actual}"
                )
            }
            Self::AmountProofChallengeDoesNotMatch { expected, actual } => {
                write!(
                    f,
                    "amount proof challenge mismatch: expected {expected}, got {actual}"
                )
            }
            Self::ThreeDegreePhiTokenAuthorityChallengeDoesNotMatch { expected, actual } => {
                write!(
                    f,
                    "degree three phi token authority challenge mismatch: expected {expected}, got {actual}"
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
        degree_three_phi_token: String,
        authority_signing_key: &SecretKey,
        previous_participant_did_key: Option<&str>,
        previous_participant_amount: Option<u8>,
        previous_participant_amount_token: Option<&str>,
    ) -> Result<Self, OwnershipProofError> {
        Self::new_with_disclosure_commitment(
            records,
            amount,
            degree_three_phi_token,
            authority_signing_key,
            previous_participant_did_key,
            previous_participant_amount,
            previous_participant_amount_token,
            None,
            None,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_disclosure_commitment(
        records: Vec<DidKeyRecord>,
        amount: u8,
        degree_three_phi_token: String,
        authority_signing_key: &SecretKey,
        previous_participant_did_key: Option<&str>,
        previous_participant_amount: Option<u8>,
        previous_participant_amount_token: Option<&str>,
        disclosure_commitment: Option<&str>,
        disclosure_group_id: Option<&str>,
        disclosure_hop: Option<u8>,
        disclosure_max_depth: Option<u8>,
    ) -> Result<Self, OwnershipProofError> {
        if !valid_did_count(records.len()) {
            return Err(OwnershipProofError::WrongDidCount {
                expected: MAX_DIDS_PER_BLOCK,
                actual: records.len(),
            });
        }

        let authority_did_key =
            did_key_from_bls12_381_public_key(&authority_signing_key.sk_to_pk().compress());
        validate_amount(amount)?;
        let amount_token_group = amount_token_group_for_block(
            &records,
            amount,
            &authority_did_key,
            previous_participant_did_key,
            previous_participant_amount,
            previous_participant_amount_token,
        )?;
        let base_amount_tokens = amount_tokens_for_records(&records, amount, &amount_token_group)?;
        let amount_tokens = match (
            disclosure_commitment,
            disclosure_group_id,
            disclosure_hop,
            disclosure_max_depth,
        ) {
            (Some(commitment), Some(group_id), Some(hop), Some(max_depth)) => {
                bind_amount_tokens_to_disclosure(
                    &base_amount_tokens,
                    commitment,
                    group_id,
                    hop,
                    max_depth,
                )?
            }
            (None, None, None, None) => base_amount_tokens.clone(),
            _ => return Err(OwnershipProofError::InvalidDisclosureCommitment),
        };
        let degree_three_phi_token_authority_proof =
            sign_degree_three_phi_token_authority_proof_with_disclosure(
                authority_signing_key,
                &degree_three_phi_token,
                disclosure_commitment,
                disclosure_group_id,
                disclosure_hop,
                disclosure_max_depth,
            );
        verify_roles_for_records(&records)?;
        verify_supported_did_keys_for_records(&records)?;
        verify_degree_three_phi_token_for_records(&records, &degree_three_phi_token)?;
        verify_amount_proof_challenges_for_records(&records, &amount_tokens)?;
        verify_ownership_proofs_for_records(&records)?;
        let block = Self {
            degree_three_phi_token,
            degree_three_phi_token_authority_proof,
            disclosure_commitment: disclosure_commitment.map(str::to_string),
            disclosure_group_id: disclosure_group_id.map(str::to_string),
            disclosure_hop,
            disclosure_max_depth,
        };
        block.verify_degree_three_phi_token_authority_proof(&authority_did_key)?;
        Ok(block)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "type=did-key-block;disclosure_commitment={};disclosure_group_id={};disclosure_hop={};disclosure_max_depth={};degree_three_phi_token={};degree_three_phi_token_authority_challenge={};degree_three_phi_token_authority_signature={}",
            self.disclosure_commitment.as_deref().unwrap_or(""),
            self.disclosure_group_id.as_deref().unwrap_or(""),
            self.disclosure_hop.map_or(String::new(), |value| value.to_string()),
            self.disclosure_max_depth.map_or(String::new(), |value| value.to_string()),
            self.degree_three_phi_token,
            self.degree_three_phi_token_authority_proof.challenge,
            self.degree_three_phi_token_authority_proof.signature
        )
        .into_bytes()
    }

    pub fn verify_degree_three_phi_token_authority_proof(
        &self,
        authority_did_key: &str,
    ) -> Result<(), OwnershipProofError> {
        let expected = degree_three_phi_token_authority_challenge_with_disclosure(
            &self.degree_three_phi_token,
            self.disclosure_commitment.as_deref(),
            self.disclosure_group_id.as_deref(),
            self.disclosure_hop,
            self.disclosure_max_depth,
        );

        if self.degree_three_phi_token_authority_proof.challenge != expected {
            return Err(
                OwnershipProofError::ThreeDegreePhiTokenAuthorityChallengeDoesNotMatch {
                    expected,
                    actual: self
                        .degree_three_phi_token_authority_proof
                        .challenge
                        .clone(),
                },
            );
        }

        verify_did_key_ownership(
            authority_did_key,
            &self.degree_three_phi_token_authority_proof,
        )
    }

    pub fn verify_mining_proof(&self, authority_did_key: &str) -> Result<(), OwnershipProofError> {
        self.verify_degree_three_phi_token_authority_proof(authority_did_key)
    }
}

fn verify_roles_for_records(records: &[DidKeyRecord]) -> Result<(), OwnershipProofError> {
    let subject_count = records
        .iter()
        .filter(|record| record.role == DidRole::Subject)
        .count();
    let witness_count = records
        .iter()
        .filter(|record| record.role == DidRole::Witness)
        .count();
    let participant_count = records
        .iter()
        .filter(|record| record.role == DidRole::Participant)
        .count();

    if subject_count != 1 {
        return Err(OwnershipProofError::WrongSubjectCount {
            expected: 1,
            actual: subject_count,
        });
    }

    if witness_count > 1 {
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

fn verify_supported_did_keys_for_records(
    records: &[DidKeyRecord],
) -> Result<(), OwnershipProofError> {
    if !valid_did_count(records.len()) {
        return Err(OwnershipProofError::WrongDidCount {
            expected: MAX_DIDS_PER_BLOCK,
            actual: records.len(),
        });
    }

    for record in records {
        record.verify_supported_did_key()?;
    }

    Ok(())
}

fn verify_ownership_proofs_for_records(
    records: &[DidKeyRecord],
) -> Result<(), OwnershipProofError> {
    if !valid_did_count(records.len()) {
        return Err(OwnershipProofError::WrongDidCount {
            expected: MAX_DIDS_PER_BLOCK,
            actual: records.len(),
        });
    }

    for record in records {
        record.verify_ownership_proof()?;
    }

    Ok(())
}

fn verify_degree_three_phi_token_for_records(
    records: &[DidKeyRecord],
    degree_three_phi_token: &str,
) -> Result<(), OwnershipProofError> {
    let actual = degree_three_phi_token_for_records(records)?;

    if degree_three_phi_token == actual {
        Ok(())
    } else {
        Err(OwnershipProofError::ThreeDegreePhiTokenDoesNotMatch {
            expected: degree_three_phi_token.to_string(),
            actual,
        })
    }
}

fn verify_amount_proof_challenges_for_records(
    records: &[DidKeyRecord],
    amount_tokens: &AmountTokens,
) -> Result<(), OwnershipProofError> {
    for record in records {
        let expected = match record.role {
            DidRole::Subject => &amount_tokens.subject,
            DidRole::Witness => &amount_tokens.witness,
            DidRole::Participant => &amount_tokens.participant,
        };

        if &record.proof.challenge != expected {
            return Err(OwnershipProofError::AmountProofChallengeDoesNotMatch {
                expected: expected.clone(),
                actual: record.proof.challenge.clone(),
            });
        }
    }

    Ok(())
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

pub fn amount_token_group_for_block(
    records: &[DidKeyRecord],
    amount: u8,
    authority_did_key: &str,
    previous_participant_did_key: Option<&str>,
    previous_participant_amount: Option<u8>,
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
    let previous_participant_amount =
        previous_participant_amount.ok_or_else(|| missing_role_error(DidRole::Participant))?;
    if amount != previous_participant_amount {
        return Err(OwnershipProofError::AmountDoesNotMatchToken {
            expected: previous_participant_amount,
            actual: amount,
        });
    }

    previous_participant_amount_token
        .map(str::to_string)
        .ok_or_else(|| missing_role_error(DidRole::Participant))
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
        witness: optional_amount_token_for_role(
            records,
            DidRole::Witness,
            amount,
            &amount_public_key,
        )
        .transpose()?
        .unwrap_or_default(),
        participant: amount_token_for_role(
            records,
            DidRole::Participant,
            amount,
            &amount_public_key,
        )?,
    })
}

pub fn degree_three_phi_token_for_records(
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

fn optional_amount_token_for_role(
    records: &[DidKeyRecord],
    role: DidRole,
    amount: u8,
    amount_public_key: &PublicKey,
) -> Option<Result<String, OwnershipProofError>> {
    records
        .iter()
        .any(|record| record.role == role)
        .then(|| amount_token_for_role(records, role, amount, amount_public_key))
}

fn valid_did_count(count: usize) -> bool {
    (MIN_DIDS_PER_BLOCK..=MAX_DIDS_PER_BLOCK).contains(&count)
}

pub fn degree_three_phi_token_authority_challenge(degree_three_phi_token: &str) -> String {
    format!("authorize degree-three-phi-crypto degree three phi token {degree_three_phi_token}")
}

pub fn degree_three_phi_token_authority_challenge_with_disclosure(
    degree_three_phi_token: &str,
    disclosure_commitment: Option<&str>,
    disclosure_group_id: Option<&str>,
    disclosure_hop: Option<u8>,
    disclosure_max_depth: Option<u8>,
) -> String {
    match (
        disclosure_commitment,
        disclosure_group_id,
        disclosure_hop,
        disclosure_max_depth,
    ) {
        (Some(commitment), Some(group_id), Some(hop), Some(max_depth)) => {
            format!(
                "authorize degree-three-phi-crypto degree three phi token {degree_three_phi_token} disclosure commitment {commitment} group {group_id} hop {hop} max depth {max_depth}"
            )
        }
        _ => degree_three_phi_token_authority_challenge(degree_three_phi_token),
    }
}

pub fn scaled_disclosure_commitment(
    disclosure_commitment: &str,
    hop: u8,
) -> Result<String, OwnershipProofError> {
    let encoded = disclosure_commitment
        .strip_prefix("φtrait_")
        .filter(|value| !value.is_empty() && value.len().is_multiple_of(2))
        .ok_or(OwnershipProofError::InvalidDisclosureCommitment)?;
    let mut bytes = (0..encoded.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&encoded[index..index + 2], 16)
                .map_err(|_| OwnershipProofError::InvalidDisclosureCommitment)
        })
        .collect::<Result<Vec<_>, _>>()?;
    for _ in 0..hop {
        let mut carry = 0u8;
        for byte in bytes.iter_mut().rev() {
            let next_carry = *byte >> 7;
            *byte = (*byte << 1) | carry;
            carry = next_carry;
        }
        if carry != 0 {
            bytes.insert(0, carry);
        }
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub fn bind_amount_token_to_disclosure(
    base_amount_token: &str,
    disclosure_commitment: &str,
    group_id: &str,
    role: DidRole,
    hop: u8,
    max_depth: u8,
) -> Result<String, OwnershipProofError> {
    let scaled_commitment = scaled_disclosure_commitment(disclosure_commitment, hop)?;
    Ok(format!(
        "phi-amount-token-v2|group_id={group_id}|role={}|hop={hop}|max_depth={max_depth}|base_amount_token={base_amount_token}|scaled_commitment={scaled_commitment}",
        role.as_str()
    ))
}

pub fn bind_amount_tokens_to_disclosure(
    amount_tokens: &AmountTokens,
    disclosure_commitment: &str,
    group_id: &str,
    hop: u8,
    max_depth: u8,
) -> Result<AmountTokens, OwnershipProofError> {
    Ok(AmountTokens {
        subject: bind_amount_token_to_disclosure(
            &amount_tokens.subject,
            disclosure_commitment,
            group_id,
            DidRole::Subject,
            hop,
            max_depth,
        )?,
        witness: (!amount_tokens.witness.is_empty())
            .then(|| {
                bind_amount_token_to_disclosure(
                    &amount_tokens.witness,
                    disclosure_commitment,
                    group_id,
                    DidRole::Witness,
                    hop,
                    max_depth,
                )
            })
            .transpose()?
            .unwrap_or_default(),
        participant: bind_amount_token_to_disclosure(
            &amount_tokens.participant,
            disclosure_commitment,
            group_id,
            DidRole::Participant,
            hop,
            max_depth,
        )?,
    })
}

fn sign_degree_three_phi_token_authority_proof_with_disclosure(
    signing_key: &SecretKey,
    degree_three_phi_token: &str,
    disclosure_commitment: Option<&str>,
    disclosure_group_id: Option<&str>,
    disclosure_hop: Option<u8>,
    disclosure_max_depth: Option<u8>,
) -> OwnershipProof {
    let challenge = degree_three_phi_token_authority_challenge_with_disclosure(
        degree_three_phi_token,
        disclosure_commitment,
        disclosure_group_id,
        disclosure_hop,
        disclosure_max_depth,
    );
    let signature = signing_key.sign(challenge.as_bytes(), BLS_SIGNATURE_DST, &[]);

    OwnershipProof::new(challenge, base64url(&signature.compress()))
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
