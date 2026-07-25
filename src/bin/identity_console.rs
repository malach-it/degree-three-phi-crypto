#[path = "../block.rs"]
#[allow(dead_code)]
mod block;
#[path = "../blockchain.rs"]
#[allow(dead_code)]
mod blockchain;
#[path = "../did.rs"]
#[allow(dead_code)]
mod did;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use blockchain::Blockchain;
use blst::min_pk::SecretKey;
use did::{
    BLS_SIGNATURE_DST, DidKeyRecord, DidKeySubmission, DidRole, OwnershipProof,
    amount_token_group_for_block, amount_tokens_for_records, bind_amount_tokens_to_disclosure,
    degree_three_phi_token_authority_challenge_with_disclosure, degree_three_phi_token_for_records,
    did_key_from_bls12_381_public_key, verify_did_key_ownership,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

const DEFAULT_ADDR: &str = "127.0.0.1:8790";
const AUTHORITY_SEED: &[u8] = b"phi-identity-console-local-authority-v1";
const INDEX_HTML: &str = include_str!("../../web/index.html");
const STYLES_CSS: &str = include_str!("../../web/styles.css");
const APP_JS: &str = include_str!("../../web/app.js");
const CORE_JS: &str = include_str!("../../web/core.mjs");

struct ConsoleState {
    blockchain: Mutex<Blockchain>,
    authority_key: SecretKey,
    authority_did_key: String,
    signing_keys: Mutex<HashMap<String, SecretKey>>,
    information_groups: Mutex<HashMap<String, InformationGroupState>>,
}

#[derive(Debug, Clone)]
struct InformationGroupState {
    amount: u8,
    disclosure_commitment: String,
    current_holder_did: String,
    participant_amount_token: String,
    hop: u8,
    last_exchange_id: String,
    receipt_json: String,
}

fn main() {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_ADDR.to_string());
    let authority_key =
        SecretKey::key_gen(AUTHORITY_SEED, &[]).expect("authority seed is valid BLS material");
    let authority_did_key = did_key_from_bls12_381_public_key(&authority_key.sk_to_pk().compress());
    let signing_keys = [7, 8, 9]
        .into_iter()
        .map(demo_signing_key)
        .map(|key| {
            (
                did_key_from_bls12_381_public_key(&key.sk_to_pk().compress()),
                key,
            )
        })
        .collect();
    let state = Arc::new(ConsoleState {
        blockchain: Mutex::new(Blockchain::new(1, authority_key.clone())),
        authority_key,
        authority_did_key,
        signing_keys: Mutex::new(signing_keys),
        information_groups: Mutex::new(HashMap::new()),
    });
    let listener = TcpListener::bind(&addr).expect("identity console should bind");

    println!("Phi Identity Console listening on http://{addr}");
    println!("BLS identity authority: {}", state.authority_did_key);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let state = Arc::clone(&state);
                thread::spawn(move || {
                    if let Err(error) = handle_connection(&mut stream, &state) {
                        let _ = write_response(
                            &mut stream,
                            "500 Internal Server Error",
                            "application/json; charset=utf-8",
                            &format!(r#"{{"error":"{}"}}"#, json_escape(&error)),
                        );
                    }
                });
            }
            Err(error) => eprintln!("identity console connection error: {error}"),
        }
    }
}

fn handle_connection(stream: &mut TcpStream, state: &ConsoleState) -> Result<(), String> {
    let request = Request::read(stream)?;
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => {
            write_response(stream, "200 OK", "text/html; charset=utf-8", INDEX_HTML)
        }
        ("GET", "/styles.css") => {
            write_response(stream, "200 OK", "text/css; charset=utf-8", STYLES_CSS)
        }
        ("GET", "/app.js") => {
            write_response(stream, "200 OK", "text/javascript; charset=utf-8", APP_JS)
        }
        ("GET", "/core.mjs") => {
            write_response(stream, "200 OK", "text/javascript; charset=utf-8", CORE_JS)
        }
        ("GET", "/api/chain-status") => {
            let chain = state
                .blockchain
                .lock()
                .map_err(|_| "blockchain lock was poisoned".to_string())?;
            let body = format!(
                r#"{{"authority_did_key":"{}","chain_blocks":{},"chain_valid":{}}}"#,
                json_escape(&state.authority_did_key),
                chain.chain.len(),
                chain.is_valid()
            );
            write_response(stream, "200 OK", "application/json; charset=utf-8", &body)
        }
        ("POST", "/api/did/generate") => match generate_identity(&request.body, state) {
            Ok(body) => write_response(stream, "200 OK", "application/json; charset=utf-8", &body),
            Err(error) => write_response(
                stream,
                "400 Bad Request",
                "application/json; charset=utf-8",
                &format!(r#"{{"error":"{}"}}"#, json_escape(&error)),
            ),
        },
        ("POST", "/api/exchange/sign") => match sign_exchange(&request.body, state) {
            Ok(body) => write_response(stream, "200 OK", "application/json; charset=utf-8", &body),
            Err(error) => write_response(
                stream,
                "400 Bad Request",
                "application/json; charset=utf-8",
                &format!(r#"{{"error":"{}"}}"#, json_escape(&error)),
            ),
        },
        ("POST", "/api/exchange/verify") => match verify_exchange(&request.body) {
            Ok(body) => write_response(stream, "200 OK", "application/json; charset=utf-8", &body),
            Err(error) => write_response(
                stream,
                "400 Bad Request",
                "application/json; charset=utf-8",
                &format!(r#"{{"error":"{}"}}"#, json_escape(&error)),
            ),
        },
        ("POST", "/api/group-exchange/commit") => {
            match commit_group_exchange(&request.body, state) {
                Ok(body) => {
                    write_response(stream, "200 OK", "application/json; charset=utf-8", &body)
                }
                Err(error) => write_response(
                    stream,
                    "400 Bad Request",
                    "application/json; charset=utf-8",
                    &format!(r#"{{"error":"{}"}}"#, json_escape(&error)),
                ),
            }
        }
        ("POST", "/api/group-exchange/verify-receipt") => {
            match verify_group_receipt(&request.body) {
                Ok(body) => {
                    write_response(stream, "200 OK", "application/json; charset=utf-8", &body)
                }
                Err(error) => write_response(
                    stream,
                    "400 Bad Request",
                    "application/json; charset=utf-8",
                    &format!(r#"{{"error":"{}"}}"#, json_escape(&error)),
                ),
            }
        }
        _ => write_response(
            stream,
            "404 Not Found",
            "application/json; charset=utf-8",
            r#"{"error":"not found"}"#,
        ),
    }
}

fn generate_identity(body: &str, state: &ConsoleState) -> Result<String, String> {
    let fields = parse_form(body);
    let name = required_field(&fields, "name")?;
    let context = required_field(&fields, "context")?;
    let entropy = required_field(&fields, "entropy")?;
    if name.chars().count() > 60 || context.chars().count() > 70 {
        return Err("name or context is too long".to_string());
    }
    if entropy.len() < 32
        || !entropy
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err("entropy must contain at least 128 bits of hexadecimal input".to_string());
    }

    let mut hasher = Sha256::new();
    hasher.update(b"phi-private-identity-v1\0");
    hasher.update(name.as_bytes());
    hasher.update(b"\0");
    hasher.update(context.as_bytes());
    hasher.update(b"\0");
    hasher.update(entropy.as_bytes());
    let ikm: [u8; 32] = hasher.finalize().into();
    let identity_key =
        SecretKey::key_gen(&ikm, &[]).map_err(|_| "could not derive BLS identity".to_string())?;
    let did = did_key_from_bls12_381_public_key(&identity_key.sk_to_pk().compress());
    state
        .signing_keys
        .lock()
        .map_err(|_| "identity signing vault lock was poisoned".to_string())?
        .insert(did.clone(), identity_key);
    let challenge = format!("attest phi private identity {did}");
    let proof = state
        .authority_key
        .sign(challenge.as_bytes(), BLS_SIGNATURE_DST, &[]);
    let fingerprint_hash = Sha256::digest(format!("{did}|{context}").as_bytes());
    let fingerprint = fingerprint_hash[..8]
        .chunks(2)
        .map(hex)
        .collect::<Vec<_>>()
        .join("·")
        .to_uppercase();

    Ok(format!(
        r#"{{"did":"{}","fingerprint":"{}","derivation":"phi-context-bls-v1","mode":"bls12-381","authority_did":"{}","authority_challenge":"{}","authority_proof":"{}"}}"#,
        json_escape(&did),
        fingerprint,
        json_escape(&state.authority_did_key),
        json_escape(&challenge),
        URL_SAFE_NO_PAD.encode(proof.compress())
    ))
}

fn sign_exchange(body: &str, state: &ConsoleState) -> Result<String, String> {
    let fields = parse_form(body);
    let did = required_field(&fields, "did")?;
    let payload = required_field(&fields, "payload")?;
    if payload.len() > 16 * 1024 {
        return Err("exchange payload is too large".to_string());
    }
    let keys = state
        .signing_keys
        .lock()
        .map_err(|_| "identity signing vault lock was poisoned".to_string())?;
    let key = keys.get(did).ok_or_else(|| {
        "the signing key for this DID is unavailable in the local runtime".to_string()
    })?;
    let signature = key.sign(payload.as_bytes(), BLS_SIGNATURE_DST, &[]);
    Ok(format!(
        r#"{{"did":"{}","signature":"{}"}}"#,
        json_escape(did),
        URL_SAFE_NO_PAD.encode(signature.compress())
    ))
}

fn verify_exchange(body: &str) -> Result<String, String> {
    let fields = parse_form(body);
    let did = required_field(&fields, "did")?;
    let payload = required_field(&fields, "payload")?;
    let signature = required_field(&fields, "signature")?;
    let proof = OwnershipProof::new(payload, signature);
    verify_did_key_ownership(did, &proof)
        .map_err(|error| format!("exchange signature verification failed: {error}"))?;
    Ok(r#"{"valid":true}"#.to_string())
}

fn commit_group_exchange(body: &str, state: &ConsoleState) -> Result<String, String> {
    let fields = parse_form(body);
    let exchange_id = required_field(&fields, "exchange_id")?;
    let group_id = required_field(&fields, "group_id")?;
    let disclosure_commitment = required_field(&fields, "disclosure_commitment")?;
    if !disclosure_commitment.starts_with("φtrait_") || disclosure_commitment.len() > 128 {
        return Err("disclosure commitment must be a valid phi trait commitment".to_string());
    }
    let subject_did = required_field(&fields, "subject_did")?;
    let participant_did = required_field(&fields, "participant_did")?;
    let witness_did = fields.get("witness_did").filter(|value| !value.is_empty());
    if subject_did == participant_did
        || witness_did.is_some_and(|did| did == subject_did || did == participant_did)
    {
        return Err("subject, witness, and participant DIDs must be distinct".to_string());
    }
    if let Some(witness_did) = witness_did {
        let approval_payload = required_field(&fields, "witness_approval_payload")?;
        let approval_signature = required_field(&fields, "witness_approval_signature")?;
        verify_did_key_ownership(
            witness_did,
            &OwnershipProof::new(approval_payload, approval_signature),
        )
        .map_err(|error| format!("explicit witness approval failed verification: {error}"))?;
    }
    let amount = required_field(&fields, "amount")?
        .parse::<u8>()
        .map_err(|_| "group amount must be an integer".to_string())?;
    let max_depth = group_max_depth(amount)?;

    let mut groups = state
        .information_groups
        .lock()
        .map_err(|_| "information group lock was poisoned".to_string())?;
    let previous = groups.get(group_id).cloned();
    if let Some(previous) = &previous {
        if previous.last_exchange_id == exchange_id {
            return Ok(previous.receipt_json.clone());
        }
        if previous.current_holder_did != subject_did {
            return Err("current subject is not the previous group participant".to_string());
        }
        if previous.amount != amount {
            return Err(format!(
                "group amount must remain {}, got {amount}",
                previous.amount
            ));
        }
        if previous.disclosure_commitment != disclosure_commitment {
            return Err(
                "disclosure commitment must remain unchanged across group hops".to_string(),
            );
        }
    }

    let mut records = vec![DidKeyRecord::new(
        subject_did,
        DidRole::Subject,
        OwnershipProof::new("", ""),
    )];
    if let Some(witness_did) = witness_did {
        records.push(DidKeyRecord::new(
            witness_did,
            DidRole::Witness,
            OwnershipProof::new("", ""),
        ));
    }
    records.push(DidKeyRecord::new(
        participant_did,
        DidRole::Participant,
        OwnershipProof::new("", ""),
    ));
    let amount_group = amount_token_group_for_block(
        &records,
        amount,
        &state.authority_did_key,
        previous
            .as_ref()
            .map(|group| group.current_holder_did.as_str()),
        previous.as_ref().map(|group| group.amount),
        previous
            .as_ref()
            .map(|group| group.participant_amount_token.as_str()),
    )
    .map_err(|error| error.to_string())?;
    let hop = previous
        .as_ref()
        .map_or(0, |group| group.hop.saturating_add(1));
    if hop > max_depth {
        return Err(format!(
            "group hop {hop} exceeds exponent-derived maximum depth {max_depth}"
        ));
    }
    let base_amount_tokens = amount_tokens_for_records(&records, amount, &amount_group)
        .map_err(|error| error.to_string())?;
    let amount_tokens = bind_amount_tokens_to_disclosure(
        &base_amount_tokens,
        disclosure_commitment,
        group_id,
        hop,
        max_depth,
    )
    .map_err(|error| error.to_string())?;
    let keys = state
        .signing_keys
        .lock()
        .map_err(|_| "identity signing vault lock was poisoned".to_string())?;
    for record in &mut records {
        let challenge = match record.role {
            DidRole::Subject => &amount_tokens.subject,
            DidRole::Witness => &amount_tokens.witness,
            DidRole::Participant => &amount_tokens.participant,
        };
        let key = keys.get(&record.did_key).ok_or_else(|| {
            format!(
                "the signing key for {} is unavailable in the local runtime",
                record.did_key
            )
        })?;
        let signature = key.sign(challenge.as_bytes(), BLS_SIGNATURE_DST, &[]);
        record.proof = OwnershipProof::new(challenge, URL_SAFE_NO_PAD.encode(signature.compress()));
    }
    let degree_three_phi_token =
        degree_three_phi_token_for_records(&records).map_err(|error| error.to_string())?;
    let role_signature = |role| {
        records
            .iter()
            .find(|record| record.role == role)
            .map(|record| record.proof.signature.as_str())
    };
    let subject_role_signature = role_signature(DidRole::Subject)
        .ok_or_else(|| "subject role signature is missing".to_string())?;
    let witness_role_signature_json = role_signature(DidRole::Witness)
        .map(|signature| format!(r#""{}""#, json_escape(signature)))
        .unwrap_or_else(|| "null".to_string());
    let participant_role_signature = role_signature(DidRole::Participant)
        .ok_or_else(|| "participant role signature is missing".to_string())?;
    let authority_challenge = degree_three_phi_token_authority_challenge_with_disclosure(
        &degree_three_phi_token,
        Some(disclosure_commitment),
        Some(group_id),
        Some(hop),
        Some(max_depth),
    );
    let authority_signature =
        state
            .authority_key
            .sign(authority_challenge.as_bytes(), BLS_SIGNATURE_DST, &[]);
    let submissions = records
        .iter()
        .map(|record| {
            DidKeySubmission::with_role(record.did_key.clone(), record.role, record.proof.clone())
        })
        .collect();
    let (block_index, block_hash) = {
        let mut blockchain = state
            .blockchain
            .lock()
            .map_err(|_| "blockchain lock was poisoned".to_string())?;
        blockchain
            .add_public_key_block_with_disclosure(
                submissions,
                amount,
                degree_three_phi_token.clone(),
                disclosure_commitment,
                group_id,
                hop,
                max_depth,
                previous
                    .as_ref()
                    .map(|group| group.current_holder_did.as_str()),
                previous.as_ref().map(|group| group.amount),
                previous
                    .as_ref()
                    .map(|group| group.participant_amount_token.as_str()),
            )
            .map_err(|error| error.to_string())?;
        let block = blockchain
            .chain
            .last()
            .ok_or_else(|| "accepted disclosure block is missing".to_string())?;
        (block.index, block.hash.clone())
    };
    let witness_did_json = witness_did
        .map(|did| format!(r#""{}""#, json_escape(did)))
        .unwrap_or_else(|| "null".to_string());
    let witness_amount_token_json = witness_did
        .map(|_| format!(r#""{}""#, json_escape(&amount_tokens.witness)))
        .unwrap_or_else(|| "null".to_string());
    let receipt_json = format!(
        r#"{{"groupId":"{}","amount":{},"maxDepth":{},"hop":{},"disclosureCommitment":"{}","blockIndex":{},"blockHash":"{}","amountTokenGroup":"{}","subjectAmountToken":"{}","subjectRoleSignature":"{}","witnessDid":{},"witnessAmountToken":{},"witnessRoleSignature":{},"participantBaseAmountToken":"{}","participantAmountToken":"{}","participantRoleSignature":"{}","degreeThreePhiToken":"{}","authorityDid":"{}","authorityChallenge":"{}","authoritySignature":"{}"}}"#,
        json_escape(group_id),
        amount,
        max_depth,
        hop,
        json_escape(disclosure_commitment),
        block_index,
        json_escape(&block_hash),
        json_escape(&amount_group),
        json_escape(&amount_tokens.subject),
        json_escape(subject_role_signature),
        witness_did_json,
        witness_amount_token_json,
        witness_role_signature_json,
        json_escape(&base_amount_tokens.participant),
        json_escape(&amount_tokens.participant),
        json_escape(participant_role_signature),
        json_escape(&degree_three_phi_token),
        json_escape(&state.authority_did_key),
        json_escape(&authority_challenge),
        URL_SAFE_NO_PAD.encode(authority_signature.compress())
    );
    groups.insert(
        group_id.to_string(),
        InformationGroupState {
            amount,
            disclosure_commitment: disclosure_commitment.to_string(),
            current_holder_did: participant_did.to_string(),
            participant_amount_token: base_amount_tokens.participant,
            hop,
            last_exchange_id: exchange_id.to_string(),
            receipt_json: receipt_json.clone(),
        },
    );
    Ok(receipt_json)
}

fn group_max_depth(amount: u8) -> Result<u8, String> {
    if amount == 0 || amount > 64 || !amount.is_power_of_two() {
        return Err(
            "group amount must be an exponent of two: 1, 2, 4, 8, 16, 32, or 64".to_string(),
        );
    }
    Ok(amount.ilog2() as u8)
}

fn verify_group_receipt(body: &str) -> Result<String, String> {
    let fields = parse_form(body);
    let degree_three_phi_token = required_field(&fields, "degree_three_phi_token")?;
    let disclosure_commitment = required_field(&fields, "disclosure_commitment")?;
    let group_id = required_field(&fields, "group_id")?;
    let hop = required_field(&fields, "hop")?
        .parse::<u8>()
        .map_err(|_| "receipt hop must be an integer".to_string())?;
    let max_depth = required_field(&fields, "max_depth")?
        .parse::<u8>()
        .map_err(|_| "receipt max depth must be an integer".to_string())?;
    let authority_did = required_field(&fields, "authority_did")?;
    let authority_challenge = required_field(&fields, "authority_challenge")?;
    let authority_signature = required_field(&fields, "authority_signature")?;
    let mut records = vec![DidKeyRecord::new(
        "",
        DidRole::Subject,
        OwnershipProof::new("", required_field(&fields, "subject_signature")?),
    )];
    if let Some(witness_signature) = fields
        .get("witness_signature")
        .filter(|signature| !signature.is_empty())
    {
        records.push(DidKeyRecord::new(
            "",
            DidRole::Witness,
            OwnershipProof::new("", witness_signature),
        ));
    }
    records.push(DidKeyRecord::new(
        "",
        DidRole::Participant,
        OwnershipProof::new("", required_field(&fields, "participant_signature")?),
    ));
    let recomputed =
        degree_three_phi_token_for_records(&records).map_err(|error| error.to_string())?;
    if recomputed != degree_three_phi_token {
        return Err("role signatures do not aggregate to the receipt phi token".to_string());
    }
    let expected_challenge = degree_three_phi_token_authority_challenge_with_disclosure(
        degree_three_phi_token,
        Some(disclosure_commitment),
        Some(group_id),
        Some(hop),
        Some(max_depth),
    );
    if authority_challenge != expected_challenge {
        return Err("authority challenge does not bind the receipt phi token".to_string());
    }
    verify_did_key_ownership(
        authority_did,
        &OwnershipProof::new(authority_challenge, authority_signature),
    )
    .map_err(|error| format!("authority receipt verification failed: {error}"))?;
    Ok(r#"{"valid":true}"#.to_string())
}

fn demo_signing_key(seed: u64) -> SecretKey {
    let mut ikm = [0u8; 32];
    ikm[..8].copy_from_slice(&seed.to_le_bytes());
    SecretKey::key_gen(&ikm, &[]).expect("demo BLS key material is valid")
}

fn required_field<'a>(fields: &'a HashMap<String, String>, name: &str) -> Result<&'a str, String> {
    fields
        .get(name)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("missing {name}"))
}

fn parse_form(body: &str) -> HashMap<String, String> {
    body.split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            Some((url_decode(key)?, url_decode(value)?))
        })
        .collect()
}

fn url_decode(value: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(value.len());
    let source = value.as_bytes();
    let mut index = 0;
    while index < source.len() {
        match source[index] {
            b'+' => bytes.push(b' '),
            b'%' if index + 2 < source.len() => {
                let encoded = std::str::from_utf8(&source[index + 1..index + 3]).ok()?;
                bytes.push(u8::from_str_radix(encoded, 16).ok()?);
                index += 2;
            }
            byte => bytes.push(byte),
        }
        index += 1;
    }
    String::from_utf8(bytes).ok()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

struct Request {
    method: String,
    path: String,
    body: String,
}

impl Request {
    fn read(stream: &mut TcpStream) -> Result<Self, String> {
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 4096];
        let header_end;
        loop {
            let count = stream
                .read(&mut buffer)
                .map_err(|error| error.to_string())?;
            if count == 0 {
                return Err("request ended before headers".to_string());
            }
            bytes.extend_from_slice(&buffer[..count]);
            if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                header_end = index + 4;
                break;
            }
            if bytes.len() > 64 * 1024 {
                return Err("request headers are too large".to_string());
            }
        }
        let headers = std::str::from_utf8(&bytes[..header_end])
            .map_err(|_| "headers are not UTF-8")?
            .to_owned();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        while bytes.len() < header_end + content_length {
            let count = stream
                .read(&mut buffer)
                .map_err(|error| error.to_string())?;
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
        let request_line = headers
            .lines()
            .next()
            .ok_or_else(|| "missing request line".to_string())?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts
            .next()
            .unwrap_or("/")
            .split('?')
            .next()
            .unwrap_or("/")
            .to_string();
        let body = String::from_utf8_lossy(
            &bytes[header_end..bytes.len().min(header_end + content_length)],
        )
        .into_owned();
        Ok(Self { method, path, body })
    }
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> Result<(), String> {
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\ncache-control: no-store\r\nx-content-type-options: nosniff\r\ncontent-security-policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_decodes_form_values() {
        let form = parse_form("name=Ada+Lovelace&context=R%26D");
        assert_eq!(form.get("name").unwrap(), "Ada Lovelace");
        assert_eq!(form.get("context").unwrap(), "R&D");
    }

    #[test]
    fn context_changes_generated_bls_identifier() {
        let authority_key = SecretKey::key_gen(AUTHORITY_SEED, &[]).unwrap();
        let state = ConsoleState {
            blockchain: Mutex::new(Blockchain::new(1, authority_key.clone())),
            authority_did_key: did_key_from_bls12_381_public_key(
                &authority_key.sk_to_pk().compress(),
            ),
            authority_key,
            signing_keys: Mutex::new(HashMap::new()),
            information_groups: Mutex::new(HashMap::new()),
        };
        let entropy = "00112233445566778899aabbccddeeff";
        let first = generate_identity(
            &format!("name=Ada&context=Research&entropy={entropy}"),
            &state,
        )
        .unwrap();
        let second = generate_identity(
            &format!("name=Ada&context=Treasury&entropy={entropy}"),
            &state,
        )
        .unwrap();
        assert_ne!(first, second);
        assert!(first.contains(r#""mode":"bls12-381""#));
        assert!(first.contains("did:key:z"));
    }

    #[test]
    fn exchange_payload_is_signed_and_publicly_verified() {
        let authority_key = SecretKey::key_gen(AUTHORITY_SEED, &[]).unwrap();
        let subject_key = demo_signing_key(7);
        let subject_did = did_key_from_bls12_381_public_key(&subject_key.sk_to_pk().compress());
        let state = ConsoleState {
            blockchain: Mutex::new(Blockchain::new(1, authority_key.clone())),
            authority_did_key: did_key_from_bls12_381_public_key(
                &authority_key.sk_to_pk().compress(),
            ),
            authority_key,
            signing_keys: Mutex::new(HashMap::from([(subject_did.clone(), subject_key)])),
            information_groups: Mutex::new(HashMap::new()),
        };
        let signed = sign_exchange(
            &format!("did={subject_did}&payload=phi-exchange-v1"),
            &state,
        )
        .unwrap();
        let signature = signed
            .split(r#""signature":""#)
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let verified = verify_exchange(&format!(
            "did={subject_did}&payload=phi-exchange-v1&signature={signature}"
        ))
        .unwrap();
        assert_eq!(verified, r#"{"valid":true}"#);
    }

    #[test]
    fn group_amount_exchange_links_previous_participant_to_next_subject() {
        let authority_key = SecretKey::key_gen(AUTHORITY_SEED, &[]).unwrap();
        let keys = [7, 8, 9].map(demo_signing_key);
        let dids = keys
            .iter()
            .map(|key| did_key_from_bls12_381_public_key(&key.sk_to_pk().compress()))
            .collect::<Vec<_>>();
        let witness_approval_payload = "approve-traits";
        let witness_approval_signature = URL_SAFE_NO_PAD.encode(
            keys[2]
                .sign(witness_approval_payload.as_bytes(), BLS_SIGNATURE_DST, &[])
                .compress(),
        );
        let state = ConsoleState {
            blockchain: Mutex::new(Blockchain::new(1, authority_key.clone())),
            authority_did_key: did_key_from_bls12_381_public_key(
                &authority_key.sk_to_pk().compress(),
            ),
            authority_key,
            signing_keys: Mutex::new(dids.iter().cloned().zip(keys).collect()),
            information_groups: Mutex::new(HashMap::new()),
        };
        let first = commit_group_exchange(
            &format!(
                "exchange_id=first&group_id=traits&disclosure_commitment=%CF%86trait_00112233445566778899aabbccddeeff00112233&amount=2&subject_did={}&participant_did={}&witness_did={}&witness_approval_payload={}&witness_approval_signature={}",
                dids[0],
                dids[1],
                dids[2],
                witness_approval_payload,
                witness_approval_signature
            ),
            &state,
        )
        .unwrap();
        assert!(first.contains(
            r#""disclosureCommitment":"φtrait_00112233445566778899aabbccddeeff00112233""#
        ));
        assert!(
            json_string_field(&first, "subjectAmountToken")
                .unwrap()
                .starts_with("did:key:z")
        );
        assert_eq!(state.blockchain.lock().unwrap().chain.len(), 2);
        assert_eq!(
            json_string_field(&first, "witnessDid"),
            Some(dids[2].as_str())
        );
        for (did, token_field, signature_field) in [
            (
                dids[0].as_str(),
                "subjectAmountToken",
                "subjectRoleSignature",
            ),
            (
                dids[2].as_str(),
                "witnessAmountToken",
                "witnessRoleSignature",
            ),
            (
                dids[1].as_str(),
                "participantAmountToken",
                "participantRoleSignature",
            ),
        ] {
            verify_did_key_ownership(
                did,
                &OwnershipProof::new(
                    json_string_field(&first, token_field).unwrap(),
                    json_string_field(&first, signature_field).unwrap(),
                ),
            )
            .unwrap();
        }
        verify_did_key_ownership(
            json_string_field(&first, "authorityDid").unwrap(),
            &OwnershipProof::new(
                json_string_field(&first, "authorityChallenge").unwrap(),
                json_string_field(&first, "authoritySignature").unwrap(),
            ),
        )
        .unwrap();
        let verified_receipt = verify_group_receipt(&format!(
            "degree_three_phi_token={}&disclosure_commitment=%CF%86trait_00112233445566778899aabbccddeeff00112233&group_id=traits&hop=0&max_depth=1&subject_signature={}&witness_signature={}&participant_signature={}&authority_did={}&authority_challenge={}&authority_signature={}",
            json_string_field(&first, "degreeThreePhiToken").unwrap(),
            json_string_field(&first, "subjectRoleSignature").unwrap(),
            json_string_field(&first, "witnessRoleSignature").unwrap(),
            json_string_field(&first, "participantRoleSignature").unwrap(),
            json_string_field(&first, "authorityDid").unwrap(),
            json_string_field(&first, "authorityChallenge").unwrap(),
            json_string_field(&first, "authoritySignature").unwrap(),
        ))
        .unwrap();
        assert_eq!(verified_receipt, r#"{"valid":true}"#);
        let missing_approval = commit_group_exchange(
            &format!(
                "exchange_id=unsigned-witness&group_id=unsigned-witness&disclosure_commitment=%CF%86trait_00112233445566778899aabbccddeeff00112233&amount=1&subject_did={}&participant_did={}&witness_did={}",
                dids[0], dids[1], dids[2]
            ),
            &state,
        );
        assert!(
            missing_approval
                .unwrap_err()
                .contains("missing witness_approval_payload")
        );
        let first_participant_token =
            json_string_field(&first, "participantBaseAmountToken").unwrap();
        let second = commit_group_exchange(
            &format!(
                "exchange_id=second&group_id=traits&disclosure_commitment=%CF%86trait_00112233445566778899aabbccddeeff00112233&amount=2&subject_did={}&participant_did={}",
                dids[1], dids[2]
            ),
            &state,
        )
        .unwrap();
        assert!(second.contains(r#""hop":1"#));
        assert!(
            json_string_field(&second, "participantAmountToken")
                .unwrap()
                .starts_with("did:key:z")
        );
        assert_ne!(
            json_string_field(&first, "participantAmountToken"),
            json_string_field(&second, "participantAmountToken")
        );
        assert_eq!(
            json_string_field(&second, "amountTokenGroup").unwrap(),
            first_participant_token
        );
        assert_eq!(state.blockchain.lock().unwrap().chain.len(), 3);
        assert!(state.blockchain.lock().unwrap().is_valid());
        {
            let mut blockchain = state.blockchain.lock().unwrap();
            let block::BlockData::PublicKeys(receipt) =
                &mut blockchain.chain.last_mut().unwrap().data
            else {
                panic!("latest block should contain a disclosure receipt");
            };
            receipt.disclosure_hop = Some(0);
            assert!(
                receipt
                    .verify_mining_proof(&state.authority_did_key)
                    .is_err()
            );
            receipt.disclosure_hop = Some(1);
        }
        let wrong_commitment = commit_group_exchange(
            &format!(
                "exchange_id=wrong-commitment&group_id=traits&disclosure_commitment=%CF%86trait_ffeeddccbbaa99887766554433221100ffeeddcc&amount=2&subject_did={}&participant_did={}",
                dids[2], dids[0]
            ),
            &state,
        );
        assert!(
            wrong_commitment
                .unwrap_err()
                .contains("disclosure commitment must remain unchanged")
        );
        let too_deep = commit_group_exchange(
            &format!(
                "exchange_id=too-deep&group_id=traits&disclosure_commitment=%CF%86trait_00112233445566778899aabbccddeeff00112233&amount=2&subject_did={}&participant_did={}",
                dids[2], dids[0]
            ),
            &state,
        );
        assert!(
            too_deep
                .unwrap_err()
                .contains("exceeds exponent-derived maximum depth 1")
        );
        let wrong_amount = commit_group_exchange(
            &format!(
                "exchange_id=third&group_id=traits&disclosure_commitment=%CF%86trait_00112233445566778899aabbccddeeff00112233&amount=1&subject_did={}&participant_did={}",
                dids[2], dids[0]
            ),
            &state,
        );
        assert!(
            wrong_amount
                .unwrap_err()
                .contains("group amount must remain 2")
        );
        assert!(group_max_depth(3).unwrap_err().contains("exponent of two"));
    }

    fn json_string_field<'a>(json: &'a str, field: &str) -> Option<&'a str> {
        json.split(&format!(r#""{field}":""#))
            .nth(1)?
            .split('"')
            .next()
    }
}
