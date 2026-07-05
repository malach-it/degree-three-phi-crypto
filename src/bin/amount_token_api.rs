#[path = "../block.rs"]
#[allow(dead_code)]
mod block;
#[path = "../blockchain.rs"]
#[allow(dead_code)]
mod blockchain;
#[path = "../did.rs"]
#[allow(dead_code)]
mod did;

use blockchain::Blockchain;
use blst::min_pk::SecretKey;
use did::{
    BLS_SIGNATURE_DST, DidKeyRecord, DidKeySubmission, DidRole, OwnershipProof,
    amount_token_for_did_key, amount_token_group_for_block, amount_tokens_for_records,
    did_key_from_bls12_381_public_key, three_degree_phi_token_for_records,
    verify_did_key_ownership,
};
use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;

const DEFAULT_ADDR: &str = "127.0.0.1:8787";
const DEFAULT_DIFFICULTY_BITS: u8 = 1;
const AUTHORITY_SEED: u64 = 42;

fn main() {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_ADDR.to_string());
    let listener = TcpListener::bind(&addr).expect("amount-token API should bind");
    let authority_key = bls_secret_key(AUTHORITY_SEED);
    let authority_did_key = did_key_from_bls12_381_public_key(&authority_key.sk_to_pk().compress());
    let state = ApiState {
        blockchain: Mutex::new(Blockchain::new(DEFAULT_DIFFICULTY_BITS, authority_key)),
        authority_did_key,
    };

    println!("amount_token_api listening on http://{addr}");
    println!("blockchain authority did {}", state.authority_did_key);
    println!(
        "challenge URL: http://{addr}/amount-token/challenge?role=subject&challenge=did%3Akey%3Aexample"
    );

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Err(error) = handle_connection(&mut stream, &state) {
                    let body = json_error(&error.to_string());
                    let _ = write_response(
                        &mut stream,
                        "500 Internal Server Error",
                        "application/json",
                        &body,
                    );
                }
            }
            Err(error) => eprintln!("amount_token_api connection error: {error}"),
        }
    }
}

struct ApiState {
    blockchain: Mutex<Blockchain>,
    authority_did_key: String,
}

fn handle_connection(stream: &mut TcpStream, state: &ApiState) -> Result<(), ApiError> {
    let request = HttpRequest::read(stream)?;

    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => write_response(
            stream,
            "200 OK",
            "text/plain",
            "three-degree-phi-crypto amount token API\n",
        )?,
        ("GET", "/blockchain") => {
            let body = blockchain_status(state);

            write_response(stream, "200 OK", "application/json", &body)?;
        }
        ("GET", "/amount-token") => {
            let amount = optional_param(&request.query, "amount")
                .unwrap_or("7")
                .parse::<u8>()
                .map_err(|_| ApiError::bad_request("amount must be an integer"))?;
            let did_key = optional_param(&request.query, "challenge")
                .unwrap_or(state.authority_did_key.as_str());
            let amount_token = amount_token_for_did_key(did_key, amount)
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            let body = amount_token_response(did_key, amount, &amount_token);

            write_response(stream, "200 OK", "application/json", &body)?;
        }
        ("GET", "/amount-token/start") => {
            let flow = FlowParams::from_query(&request.query)?;
            let challenges = amount_token_challenges(state, &flow)?;
            let location = challenge_location(&flow, DidRole::Subject, &challenges.subject, "");

            write_redirect(stream, &location)?;
        }
        ("GET", "/amount-token/challenge") => {
            let challenge = required_param(&request.query, "challenge")?;
            let role = optional_param(&request.query, "role").unwrap_or("subject");
            let role = parse_role(role)?;
            let did_key = demo_did_key_for_role(role);
            let body = challenge_page(challenge, &did_key, role.as_str(), &request.query);

            write_response(stream, "200 OK", "text/html", &body)?;
        }
        ("POST", "/amount-token/demo-sign") => {
            let form = parse_form(&request.body);
            let challenge = required_param(&form, "challenge")?;
            let role = parse_role(optional_param(&form, "role").unwrap_or("subject"))?;
            let signature = demo_signature_for_role(role, challenge);
            let body = format!(r#"{{"signature":"{}"}}"#, json_escape(&signature));

            write_response(stream, "200 OK", "application/json", &body)?;
        }
        ("POST", "/amount-token/sign") | ("POST", "/amount-token/submit") => {
            let form = parse_form(&request.body);
            let submission = submission_from_form(&form)?;

            if optional_param(&form, "flow") == Some("1") {
                continue_flow(stream, state, &form, submission)?;
            } else {
                write_response(
                    stream,
                    "200 OK",
                    "application/json",
                    &submission_json(&submission),
                )?;
            }
        }
        _ => {
            let body = json_error("not found");
            write_response(stream, "404 Not Found", "application/json", &body)?;
        }
    }

    Ok(())
}

fn blockchain_status(state: &ApiState) -> String {
    let blockchain = state
        .blockchain
        .lock()
        .expect("blockchain mutex should not be poisoned");

    format!(
        r#"{{"authority_did_key":"{}","difficulty_bits":{},"chain_blocks":{},"chain_valid":{}}}"#,
        json_escape(&state.authority_did_key),
        DEFAULT_DIFFICULTY_BITS,
        blockchain.chain.len(),
        blockchain.is_valid()
    )
}

fn amount_token_response(did_key: &str, amount: u8, amount_token: &str) -> String {
    format!(
        r#"{{"did_key":"{}","amount":{},"amount_token":"{}"}}"#,
        json_escape(did_key),
        amount,
        json_escape(amount_token)
    )
}

#[derive(Debug, Clone)]
struct FlowParams {
    amount: u8,
    subject_did_key: String,
    witness_did_key: String,
    participant_did_key: String,
}

impl FlowParams {
    fn from_query(query: &HashMap<String, String>) -> Result<Self, ApiError> {
        Ok(Self {
            amount: optional_param(query, "amount")
                .unwrap_or("7")
                .parse::<u8>()
                .map_err(|_| ApiError::bad_request("amount must be an integer"))?,
            subject_did_key: did_key_param(query, "subject")?,
            witness_did_key: did_key_param(query, "witness")?,
            participant_did_key: did_key_param(query, "participant")?,
        })
    }
}

fn did_key_param(query: &HashMap<String, String>, role_name: &str) -> Result<String, ApiError> {
    let did_key_name = format!("{role_name}_did_key");
    if let Some(did_key) = optional_param(query, &did_key_name) {
        return Ok(did_key.to_string());
    }

    let role = parse_role(role_name)?;

    Ok(demo_did_key_for_role(role))
}

fn amount_token_challenges(
    state: &ApiState,
    flow: &FlowParams,
) -> Result<did::AmountTokens, ApiError> {
    let records = flow_records_without_proofs(flow);
    let blockchain = state
        .blockchain
        .lock()
        .expect("blockchain mutex should not be poisoned");
    let amount_token_group = amount_token_group_for_block(
        &records,
        flow.amount,
        &state.authority_did_key,
        blockchain.current_participant_did_key(),
        blockchain.current_amount(),
        blockchain.current_participant_amount_token(),
    )
    .map_err(|error| ApiError::bad_request(error.to_string()))?;

    amount_tokens_for_records(&records, flow.amount, &amount_token_group)
        .map_err(|error| ApiError::bad_request(error.to_string()))
}

fn flow_records_without_proofs(flow: &FlowParams) -> Vec<DidKeyRecord> {
    [
        (DidRole::Subject, flow.subject_did_key.as_str()),
        (DidRole::Witness, flow.witness_did_key.as_str()),
        (DidRole::Participant, flow.participant_did_key.as_str()),
    ]
    .into_iter()
    .map(|(role, did_key)| DidKeyRecord::new(did_key, role, OwnershipProof::new("", "")))
    .collect()
}

fn continue_flow(
    stream: &mut TcpStream,
    state: &ApiState,
    form: &HashMap<String, String>,
    submission: DidKeySubmission,
) -> Result<(), ApiError> {
    let flow = FlowParams::from_query(form)?;
    let mut submissions = parse_submissions(optional_param(form, "submissions").unwrap_or(""))?;
    submissions.push(submission);

    match parse_role(required_param(form, "role")?)? {
        DidRole::Subject => {
            let challenges = amount_token_challenges(state, &flow)?;
            let location = challenge_location(
                &flow,
                DidRole::Witness,
                &challenges.witness,
                &serialize_submissions(&submissions),
            );

            write_redirect(stream, &location)
        }
        DidRole::Witness => {
            let challenges = amount_token_challenges(state, &flow)?;
            let location = challenge_location(
                &flow,
                DidRole::Participant,
                &challenges.participant,
                &serialize_submissions(&submissions),
            );

            write_redirect(stream, &location)
        }
        DidRole::Participant => {
            let result = create_flow_block(state, flow.amount, submissions)?;
            let body = block_created_page(&result);

            write_response(stream, "200 OK", "text/html", &body)
        }
    }
}

struct BlockCreationResult {
    block_index: u64,
    block_hash: String,
    mount_token: String,
    three_degree_phi_token: String,
    chain_blocks: usize,
    chain_valid: bool,
}

fn create_flow_block(
    state: &ApiState,
    amount: u8,
    submissions: Vec<DidKeySubmission>,
) -> Result<BlockCreationResult, ApiError> {
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
    let three_degree_phi_token = three_degree_phi_token_for_records(&records).map_err(|error| {
        ApiError::bad_request(format!("could not aggregate submissions: {error}"))
    })?;
    let mut blockchain = state
        .blockchain
        .lock()
        .expect("blockchain mutex should not be poisoned");

    blockchain
        .add_public_key_block(submissions, amount, three_degree_phi_token.clone())
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let block = blockchain
        .chain
        .last()
        .expect("accepted block should be appended");

    Ok(BlockCreationResult {
        block_index: block.index,
        block_hash: block.hash.clone(),
        mount_token: blockchain
            .current_participant_amount_token()
            .expect("accepted block should register a participant amount token")
            .to_string(),
        three_degree_phi_token,
        chain_blocks: blockchain.chain.len(),
        chain_valid: blockchain.is_valid(),
    })
}

fn block_created_page(result: &BlockCreationResult) -> String {
    let example_dids = demo_dids_html();

    format!(
        r#"<!doctype html>
<html>
<body>
<h1>block created</h1>
{example_dids}
<dl>
  <dt>block index</dt>
  <dd>{}</dd>
  <dt>block hash</dt>
  <dd>{}</dd>
  <dt>mount token</dt>
  <dd>{}</dd>
  <dt>three degree phi token</dt>
  <dd>{}</dd>
  <dt>chain blocks</dt>
  <dd>{}</dd>
  <dt>chain valid</dt>
  <dd>{}</dd>
</dl>
</body>
</html>"#,
        result.block_index,
        html_escape(&result.block_hash),
        html_escape(&result.mount_token),
        html_escape(&result.three_degree_phi_token),
        result.chain_blocks,
        result.chain_valid,
        example_dids = example_dids
    )
}

fn challenge_location(
    flow: &FlowParams,
    role: DidRole,
    challenge: &str,
    submissions: &str,
) -> String {
    format!(
        "/amount-token/challenge?flow=1&amount={}&role={}&challenge={}&submissions={}",
        flow.amount,
        role.as_str(),
        url_encode(challenge),
        url_encode(submissions)
    )
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    query: HashMap<String, String>,
    body: String,
}

impl HttpRequest {
    fn read(stream: &mut TcpStream) -> Result<Self, ApiError> {
        let mut buffer = [0u8; 8192];
        let bytes_read = stream.read(&mut buffer)?;
        let request = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();
        let (head, body_start) = request
            .split_once("\r\n\r\n")
            .ok_or_else(|| ApiError::bad_request("invalid HTTP request"))?;
        let mut lines = head.lines();
        let request_line = lines
            .next()
            .ok_or_else(|| ApiError::bad_request("missing request line"))?;
        let mut request_parts = request_line.split_whitespace();
        let method = request_parts
            .next()
            .ok_or_else(|| ApiError::bad_request("missing method"))?
            .to_string();
        let target = request_parts
            .next()
            .ok_or_else(|| ApiError::bad_request("missing target"))?;
        let content_length = lines
            .filter_map(|line| line.split_once(':'))
            .find_map(|(name, value)| {
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);
        let body = if content_length <= body_start.len() {
            body_start[..content_length].to_string()
        } else {
            body_start.to_string()
        };
        let (path, query) = parse_target(target);

        Ok(Self {
            method,
            path,
            query,
            body,
        })
    }
}

fn parse_target(target: &str) -> (String, HashMap<String, String>) {
    let Some((path, query)) = target.split_once('?') else {
        return (target.to_string(), HashMap::new());
    };

    (path.to_string(), parse_form(query))
}

fn parse_form(input: &str) -> HashMap<String, String> {
    input
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));

            (url_decode(key), url_decode(value))
        })
        .collect()
}

fn required_param<'a>(
    params: &'a HashMap<String, String>,
    name: &str,
) -> Result<&'a str, ApiError> {
    optional_param(params, name).ok_or_else(|| ApiError::bad_request(format!("missing {name}")))
}

fn optional_param<'a>(params: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    params.get(name).map(String::as_str)
}

fn parse_role(value: &str) -> Result<DidRole, ApiError> {
    match value {
        "subject" => Ok(DidRole::Subject),
        "witness" => Ok(DidRole::Witness),
        "participant" => Ok(DidRole::Participant),
        _ => Err(ApiError::bad_request(
            "role must be subject, witness, or participant",
        )),
    }
}

fn challenge_page(
    challenge: &str,
    did_key: &str,
    role: &str,
    query: &HashMap<String, String>,
) -> String {
    let hidden_inputs = ["flow", "amount", "submissions"]
        .into_iter()
        .filter_map(|name| {
            query.get(name).map(|value| {
                format!(
                    r#"<input type="hidden" name="{name}" value="{}">"#,
                    html_escape(value)
                )
            })
        })
        .collect::<Vec<_>>()
        .join("\n  ");
    let example_dids = demo_dids_html();

    format!(
        r#"<!doctype html>
<html>
<body>
{example_dids}
<form id="sign" method="post" action="/amount-token/submit">
  <input type="hidden" name="challenge" value="{challenge}">
  <input type="hidden" name="did_key" value="{did_key}">
  <input type="hidden" name="role" value="{role}">
  {hidden_inputs}
  <h3>{role}</h3>
  <p>amount token: <code>{challenge}</code></p>
  <label>signature <input name="signature"></label>
  <button type="submit">submit</button>
</form>
<script>
window.phiCryptoDemoSign = async ({{ challenge, role }}) => {{
  const body = new URLSearchParams({{ challenge, role }});
  const response = await fetch('/amount-token/demo-sign', {{
    method: 'POST',
    headers: {{ 'content-type': 'application/x-www-form-urlencoded' }},
    body
  }});
  if (!response.ok) {{
    throw new Error(await response.text());
  }}
  const proof = await response.json();
  return proof.signature;
}};

(async () => {{
  const signer = window.phiCryptoSign || window.phiCryptoDemoSign;
  if (!signer) {{
    return;
  }}
  const form = document.getElementById('sign');
  form.signature.value = await signer({{
    didKey: form.did_key.value,
    challenge: form.challenge.value,
    role: form.role.value
  }});
}})();
</script>
</body>
</html>"#,
        challenge = html_escape(challenge),
        did_key = html_escape(did_key),
        role = html_escape(role),
        example_dids = example_dids,
        hidden_inputs = hidden_inputs
    )
}

fn demo_dids_html() -> String {
    let subject = demo_did_key(7);
    let witness = demo_did_key(8);
    let participant = demo_did_key(9);

    format!(
        "<h2>example DIDs</h2>\n<ul>\n<li>subject: {}</li>\n<li>witness: {}</li>\n<li>participant: {}</li>\n</ul>",
        html_escape(&subject),
        html_escape(&witness),
        html_escape(&participant)
    )
}

fn demo_did_key(seed: u64) -> String {
    let signing_key = bls_secret_key(seed);

    did_key_from_bls12_381_public_key(&signing_key.sk_to_pk().compress())
}

fn demo_did_key_for_role(role: DidRole) -> String {
    match role {
        DidRole::Subject => demo_did_key(7),
        DidRole::Witness => demo_did_key(8),
        DidRole::Participant => demo_did_key(9),
    }
}

fn demo_signature_for_role(role: DidRole, challenge: &str) -> String {
    let seed = match role {
        DidRole::Subject => 7,
        DidRole::Witness => 8,
        DidRole::Participant => 9,
    };
    let signing_key = bls_secret_key(seed);
    let signature = signing_key.sign(challenge.as_bytes(), BLS_SIGNATURE_DST, &[]);

    base64url(&signature.compress())
}

fn submission_from_form(form: &HashMap<String, String>) -> Result<DidKeySubmission, ApiError> {
    let challenge = required_param(form, "challenge")?;
    let did_key = required_param(form, "did_key")?;
    let signature = required_param(form, "signature")?;
    let role = parse_role(optional_param(form, "role").unwrap_or("subject"))?;
    let proof = OwnershipProof::new(challenge, signature);

    verify_did_key_ownership(did_key, &proof)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;

    Ok(DidKeySubmission::with_role(did_key, role, proof))
}

fn submission_json(submission: &DidKeySubmission) -> String {
    format!(
        r#"{{"did_key":"{}","role":"{}","proof":{{"challenge":"{}","signature":"{}"}}}}"#,
        json_escape(&submission.did_key),
        submission.role.as_str(),
        json_escape(&submission.proof.challenge),
        json_escape(&submission.proof.signature)
    )
}

fn serialize_submissions(submissions: &[DidKeySubmission]) -> String {
    submissions
        .iter()
        .map(|submission| {
            [
                submission.role.as_str().to_string(),
                url_encode(&submission.did_key),
                url_encode(&submission.proof.challenge),
                url_encode(&submission.proof.signature),
            ]
            .join("~")
        })
        .collect::<Vec<_>>()
        .join("!")
}

fn parse_submissions(serialized: &str) -> Result<Vec<DidKeySubmission>, ApiError> {
    if serialized.is_empty() {
        return Ok(Vec::new());
    }

    serialized
        .split('!')
        .map(|entry| {
            let parts = entry.split('~').collect::<Vec<_>>();
            if parts.len() != 4 {
                return Err(ApiError::bad_request("invalid submissions query parameter"));
            }
            let role = parse_role(parts[0])?;
            let did_key = url_decode(parts[1]);
            let challenge = url_decode(parts[2]);
            let signature = url_decode(parts[3]);

            Ok(DidKeySubmission::with_role(
                did_key,
                role,
                OwnershipProof::new(challenge, signature),
            ))
        })
        .collect()
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> Result<(), ApiError> {
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content_type}; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );

    stream
        .write_all(response.as_bytes())
        .map_err(ApiError::from)
}

fn write_redirect(stream: &mut TcpStream, location: &str) -> Result<(), ApiError> {
    let body = format!("redirecting to {location}\n");
    let response = format!(
        "HTTP/1.1 303 See Other\r\nlocation: {location}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );

    stream
        .write_all(response.as_bytes())
        .map_err(ApiError::from)
}

fn bls_secret_key(seed: u64) -> SecretKey {
    let mut ikm = [0u8; 32];
    ikm[..8].copy_from_slice(&seed.to_le_bytes());

    SecretKey::key_gen(&ikm, &[]).expect("API BLS key material should be valid")
}

fn url_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                if let Ok(hex) = u8::from_str_radix(&value[index + 1..index + 3], 16) {
                    decoded.push(hex);
                    index += 3;
                } else {
                    decoded.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8_lossy(&decoded).to_string()
}

fn url_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![byte as char]
            }
            byte => format!("%{byte:02X}").chars().collect::<Vec<_>>(),
        })
        .collect()
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn json_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn json_error(message: &str) -> String {
    format!(r#"{{"error":"{}"}}"#, json_escape(message))
}

fn base64url(bytes: &[u8]) -> String {
    use base64::Engine;

    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Debug)]
struct ApiError {
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ApiError {}

impl From<std::io::Error> for ApiError {
    fn from(error: std::io::Error) -> Self {
        Self {
            message: error.to_string(),
        }
    }
}
