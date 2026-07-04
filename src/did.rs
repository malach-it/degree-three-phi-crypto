use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::array::TryFromSliceError;
use std::error::Error;
use std::fmt;

const ED25519_DID_KEY_PREFIX: [u8; 2] = [0xed, 0x01];

#[derive(Debug, Clone)]
pub struct DidKeyRecord {
    pub did_key: String,
    pub public_jwk: PublicJwk,
}

#[derive(Debug, Clone)]
pub struct PublicJwk {
    pub kty: String,
    pub crv: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
    pub e: Option<String>,
    pub n: Option<String>,
    pub d: Option<String>,
    pub k: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OwnershipProof {
    pub challenge: String,
    pub signature: String,
}

#[derive(Debug)]
pub enum OwnershipProofError {
    UnsupportedKeyType,
    MissingPublicKey,
    PrivateKeyMaterialPresent,
    SymmetricKeyMaterialPresent,
    InvalidPublicKeyEncoding(base64::DecodeError),
    PublicKeyDoesNotMatchDid { expected: String, actual: String },
    InvalidSignatureEncoding(base64::DecodeError),
    InvalidPublicKeyLength(TryFromSliceError),
    InvalidSignatureLength(ed25519_dalek::SignatureError),
    InvalidPublicKey(ed25519_dalek::SignatureError),
    InvalidSignature(ed25519_dalek::SignatureError),
}

impl fmt::Display for OwnershipProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedKeyType => write!(f, "only Ed25519 public JWKs are supported"),
            Self::MissingPublicKey => write!(f, "public JWK is missing the x coordinate"),
            Self::PrivateKeyMaterialPresent => {
                write!(f, "public JWK must not contain private key material")
            }
            Self::SymmetricKeyMaterialPresent => {
                write!(f, "public JWK must not contain symmetric key material")
            }
            Self::InvalidPublicKeyEncoding(error) => {
                write!(f, "public key is not valid base64url: {error}")
            }
            Self::PublicKeyDoesNotMatchDid { expected, actual } => {
                write!(
                    f,
                    "public JWK does not match DID: expected {expected}, got {actual}"
                )
            }
            Self::InvalidSignatureEncoding(error) => {
                write!(f, "signature is not valid base64url: {error}")
            }
            Self::InvalidPublicKeyLength(error) => {
                write!(f, "public key has invalid length: {error}")
            }
            Self::InvalidSignatureLength(error) => {
                write!(f, "signature has invalid length: {error}")
            }
            Self::InvalidPublicKey(error) => write!(f, "public key is invalid: {error}"),
            Self::InvalidSignature(error) => {
                write!(f, "signature does not match challenge: {error}")
            }
        }
    }
}

impl Error for OwnershipProofError {}

impl DidKeyRecord {
    pub fn new(did_key: impl Into<String>, public_jwk: PublicJwk) -> Self {
        Self {
            did_key: did_key.into(),
            public_jwk,
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "type=public-key;did_key={};jwk={}",
            self.did_key,
            self.public_jwk.canonical_string()
        )
        .into_bytes()
    }

    pub fn verify_did_matches_public_key(&self) -> Result<(), OwnershipProofError> {
        let actual = self.public_jwk.to_did_key()?;

        if self.did_key == actual {
            Ok(())
        } else {
            Err(OwnershipProofError::PublicKeyDoesNotMatchDid {
                expected: self.did_key.clone(),
                actual,
            })
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

impl PublicJwk {
    pub fn ed25519_public(x: impl Into<String>) -> Self {
        Self {
            kty: "OKP".to_string(),
            crv: Some("Ed25519".to_string()),
            x: Some(x.into()),
            y: None,
            e: None,
            n: None,
            d: None,
            k: None,
        }
    }

    pub fn canonical_string(&self) -> String {
        format!(
            "crv={};d={};e={};k={};kty={};n={};x={};y={}",
            self.crv.as_deref().unwrap_or(""),
            self.d.as_deref().unwrap_or(""),
            self.e.as_deref().unwrap_or(""),
            self.k.as_deref().unwrap_or(""),
            self.kty,
            self.n.as_deref().unwrap_or(""),
            self.x.as_deref().unwrap_or(""),
            self.y.as_deref().unwrap_or("")
        )
    }

    pub fn to_did_key(&self) -> Result<String, OwnershipProofError> {
        let public_key_bytes = self.ed25519_public_key_bytes()?;
        let mut prefixed_key =
            Vec::with_capacity(ED25519_DID_KEY_PREFIX.len() + public_key_bytes.len());

        prefixed_key.extend_from_slice(&ED25519_DID_KEY_PREFIX);
        prefixed_key.extend_from_slice(&public_key_bytes);

        Ok(format!(
            "did:key:z{}",
            bs58::encode(prefixed_key).into_string()
        ))
    }

    pub fn verify_ownership(&self, proof: &OwnershipProof) -> Result<(), OwnershipProofError> {
        let public_key_bytes = self.ed25519_public_key_bytes()?;
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(OwnershipProofError::InvalidPublicKey)?;

        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&proof.signature)
            .map_err(OwnershipProofError::InvalidSignatureEncoding)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(OwnershipProofError::InvalidSignatureLength)?;

        verifying_key
            .verify(proof.challenge.as_bytes(), &signature)
            .map_err(OwnershipProofError::InvalidSignature)
    }

    fn ed25519_public_key_bytes(&self) -> Result<[u8; 32], OwnershipProofError> {
        self.ensure_asymmetric_public_key()?;

        let public_key = self
            .x
            .as_ref()
            .ok_or(OwnershipProofError::MissingPublicKey)?;
        let public_key_bytes = URL_SAFE_NO_PAD
            .decode(public_key)
            .map_err(OwnershipProofError::InvalidPublicKeyEncoding)?;

        public_key_bytes
            .as_slice()
            .try_into()
            .map_err(OwnershipProofError::InvalidPublicKeyLength)
    }

    pub fn ensure_asymmetric_public_key(&self) -> Result<(), OwnershipProofError> {
        if self.k.is_some() || self.kty == "oct" {
            return Err(OwnershipProofError::SymmetricKeyMaterialPresent);
        }

        if self.d.is_some() {
            return Err(OwnershipProofError::PrivateKeyMaterialPresent);
        }

        if self.kty != "OKP" || self.crv.as_deref() != Some("Ed25519") {
            return Err(OwnershipProofError::UnsupportedKeyType);
        }

        if self.x.is_none() {
            return Err(OwnershipProofError::MissingPublicKey);
        }

        Ok(())
    }
}
