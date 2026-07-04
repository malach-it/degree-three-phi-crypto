#[path = "../block.rs"]
mod block;
#[path = "../blockchain.rs"]
mod blockchain;
#[path = "../did.rs"]
mod did;

use block::BlockData;
use blockchain::Blockchain;
use blst::min_pk::SecretKey;
use did::{
    BLS_SIGNATURE_DST, DidKeyRecord, DidKeySubmission, DidRole, OwnershipProof,
    amount_authority_challenge, amount_proof_key_for_records, amount_token_for_block,
    did_key_from_bls12_381_public_key, verify_did_key_ownership,
};
use std::env;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

#[derive(Debug, Clone, Copy)]
struct Config {
    workers: usize,
    ops_per_worker: usize,
    parties: usize,
    difficulty_bits: u8,
    seed: u64,
    print_blocks: bool,
}

#[derive(Debug, Clone)]
struct Party {
    signing_key: SecretKey,
    did_key: String,
}

#[derive(Debug)]
struct WorkerStats {
    accepted: usize,
    rejected: usize,
    third_party_checks: usize,
    third_party_check_failures: usize,
}

fn main() {
    let config = Config::from_args();
    let amount_authority_key = bls_secret_key(42);
    let amount_authority_did_key = did_key_for_secret_key(&amount_authority_key);
    let blockchain = Arc::new(Mutex::new(Blockchain::new(
        config.difficulty_bits,
        amount_authority_key.clone(),
    )));
    let parties = Arc::new(
        (0..config.parties)
            .map(|index| {
                let signing_key = bls_secret_key((index + 1) as u64);
                let did_key = did_key_for_secret_key(&signing_key);

                Party {
                    signing_key,
                    did_key,
                }
            })
            .collect::<Vec<_>>(),
    );

    let started = Instant::now();
    let handles = (0..config.workers)
        .map(|worker_index| {
            let blockchain = Arc::clone(&blockchain);
            let parties = Arc::clone(&parties);
            let amount_authority_key = amount_authority_key.clone();
            let amount_authority_did_key = amount_authority_did_key.clone();
            let mut rng = XorShift64::new(config.seed ^ ((worker_index as u64 + 1) << 32));

            thread::spawn(move || {
                run_worker(
                    config.ops_per_worker,
                    &mut rng,
                    &blockchain,
                    &parties,
                    &amount_authority_key,
                    &amount_authority_did_key,
                    config.print_blocks,
                )
            })
        })
        .collect::<Vec<_>>();

    let stats = handles
        .into_iter()
        .map(|handle| handle.join().expect("load-test worker should not panic"))
        .fold(
            WorkerStats {
                accepted: 0,
                rejected: 0,
                third_party_checks: 0,
                third_party_check_failures: 0,
            },
            |mut total, stats| {
                total.accepted += stats.accepted;
                total.rejected += stats.rejected;
                total.third_party_checks += stats.third_party_checks;
                total.third_party_check_failures += stats.third_party_check_failures;
                total
            },
        );
    let elapsed = started.elapsed();
    let blockchain = blockchain
        .lock()
        .expect("blockchain mutex should not be poisoned");

    println!("load_test workers {}", config.workers);
    println!("load_test ops_per_worker {}", config.ops_per_worker);
    println!("load_test parties {}", config.parties);
    println!("load_test difficulty_bits {}", config.difficulty_bits);
    println!("load_test accepted {}", stats.accepted);
    println!("load_test rejected {}", stats.rejected);
    println!("load_test third_party_checks {}", stats.third_party_checks);
    println!(
        "load_test third_party_check_failures {}",
        stats.third_party_check_failures
    );
    println!("load_test chain_blocks {}", blockchain.chain.len());
    println!("load_test chain_valid {}", blockchain.is_valid());
    println!("load_test elapsed_ms {}", elapsed.as_millis());
}

fn run_worker(
    ops: usize,
    rng: &mut XorShift64,
    blockchain: &Arc<Mutex<Blockchain>>,
    parties: &[Party],
    amount_authority_key: &SecretKey,
    amount_authority_did_key: &str,
    print_blocks: bool,
) -> WorkerStats {
    let mut stats = WorkerStats {
        accepted: 0,
        rejected: 0,
        third_party_checks: 0,
        third_party_check_failures: 0,
    };

    for _ in 0..ops {
        let mut blockchain = blockchain
            .lock()
            .expect("blockchain mutex should not be poisoned");
        let exchange = random_exchange(rng, &blockchain, parties);
        let amount_authority_signature =
            sign_amount_authority(amount_authority_key, exchange.amount);
        let amount_token = amount_token_for_exchange(
            &blockchain,
            &exchange,
            &amount_authority_signature,
            amount_authority_did_key,
        );
        let submissions = exchange_submissions(&exchange, &amount_token);
        let amount_proof_key = amount_proof_key_for_submissions(&submissions);

        match blockchain.add_public_key_block(submissions, exchange.amount, amount_proof_key) {
            Ok(()) => {
                stats.accepted += 1;

                let block = blockchain
                    .chain
                    .last()
                    .expect("accepted operation should append a block");
                let check_stats = verify_two_party_third_checks(block);
                stats.third_party_checks += check_stats.total;
                stats.third_party_check_failures += check_stats.failed;

                if print_blocks {
                    print_created_block(block);
                    print_two_party_third_check_results(block);
                    println!("\n\n");
                }
            }
            Err(error) => {
                stats.rejected += 1;
                println!("load_test rejected_operation {error}");
            }
        }
    }

    stats
}

#[derive(Debug)]
struct ThirdPartyCheckStats {
    total: usize,
    failed: usize,
}

fn verify_two_party_third_checks(block: &block::Block) -> ThirdPartyCheckStats {
    let BlockData::PublicKeys(did_block) = &block.data else {
        return ThirdPartyCheckStats {
            total: 0,
            failed: 0,
        };
    };
    let mut stats = ThirdPartyCheckStats {
        total: 0,
        failed: 0,
    };

    for target_role in [DidRole::Subject, DidRole::Witness, DidRole::Participant] {
        stats.total += 1;

        if !two_party_third_check_passes(did_block, target_role) {
            stats.failed += 1;
            println!(
                "load_test third_party_check_failed block_index {} verify {}",
                block.index,
                target_role.as_str()
            );
        }
    }

    stats
}

fn print_two_party_third_check_results(block: &block::Block) {
    let BlockData::PublicKeys(did_block) = &block.data else {
        return;
    };

    for target_role in [DidRole::Subject, DidRole::Witness, DidRole::Participant] {
        let result = two_party_third_check_result(did_block, target_role);

        println!(
            "load_test proof_result block_index {} verifiers {} verify {} challenge {} signature {} aggregate {} passed {}",
            block.index,
            verifier_roles_for(target_role),
            target_role.as_str(),
            result.challenge_matches_block,
            result.target_signature_valid,
            result.block_result_matches,
            result.passed()
        );
    }
}

fn two_party_third_check_passes(did_block: &did::DidKeyBlock, target_role: DidRole) -> bool {
    two_party_third_check_result(did_block, target_role).passed()
}

#[derive(Debug)]
struct ThirdPartyCheckResult {
    challenge_matches_block: bool,
    target_signature_valid: bool,
    block_result_matches: bool,
}

impl ThirdPartyCheckResult {
    fn failed() -> Self {
        Self {
            challenge_matches_block: false,
            target_signature_valid: false,
            block_result_matches: false,
        }
    }

    fn passed(&self) -> bool {
        self.challenge_matches_block && self.target_signature_valid && self.block_result_matches
    }
}

fn two_party_third_check_result(
    did_block: &did::DidKeyBlock,
    target_role: DidRole,
) -> ThirdPartyCheckResult {
    let Some(target_record) = record_for_role(did_block, target_role) else {
        return ThirdPartyCheckResult::failed();
    };
    let challenge_matches_block = target_record.proof.challenge == did_block.amount_token;
    let target_signature_valid =
        verify_did_key_ownership(&target_record.did_key, &target_record.proof).is_ok();
    let block_result_matches = amount_proof_key_for_records(&did_block.records)
        .map(|amount_proof_key| amount_proof_key == did_block.amount_proof_key)
        .unwrap_or(false);

    ThirdPartyCheckResult {
        challenge_matches_block,
        target_signature_valid,
        block_result_matches,
    }
}

fn print_created_block(block: &block::Block) {
    let BlockData::PublicKeys(did_block) = &block.data else {
        return;
    };
    let subject = did_key_for_role(did_block, DidRole::Subject).expect("block has subject");
    let witness = did_key_for_role(did_block, DidRole::Witness).expect("block has witness");
    let participant =
        did_key_for_role(did_block, DidRole::Participant).expect("block has participant");

    println!(
        "load_test block_created index {}\n hash {}\n amount {}\n subject {}\n witness {}\n participant {}\n amount_token {}\n amount_proof_key {}\n",
        block.index,
        block.hash,
        did_block.amount,
        subject,
        witness,
        participant,
        did_block.amount_token,
        did_block.amount_proof_key
    );
}

fn record_for_role(did_block: &did::DidKeyBlock, role: DidRole) -> Option<&DidKeyRecord> {
    did_block.records.iter().find(|record| record.role == role)
}

fn verifier_roles_for(target_role: DidRole) -> String {
    [DidRole::Subject, DidRole::Witness, DidRole::Participant]
        .into_iter()
        .filter(|role| *role != target_role)
        .map(DidRole::as_str)
        .collect::<Vec<_>>()
        .join("+")
}

#[derive(Debug)]
struct Exchange<'a> {
    subject: &'a Party,
    witness: &'a Party,
    participant: &'a Party,
    amount: u8,
}

fn random_exchange<'a>(
    rng: &mut XorShift64,
    blockchain: &Blockchain,
    parties: &'a [Party],
) -> Exchange<'a> {
    let current_owner_index = current_owner_index(blockchain, parties);
    let link_previous_owner = current_owner_index.is_some() && rng.next_u64() % 4 != 0;
    let subject_index = if link_previous_owner {
        current_owner_index.expect("linked exchange should have an owner")
    } else if let Some(current_owner_index) = current_owner_index {
        random_distinct_index(rng, parties.len(), &[current_owner_index])
    } else {
        rng.next_usize(parties.len())
    };
    let participant_index = random_distinct_index(rng, parties.len(), &[subject_index]);
    let witness_index =
        random_distinct_index(rng, parties.len(), &[subject_index, participant_index]);
    let amount = if link_previous_owner {
        current_owner_amount(blockchain).expect("linked exchange should have an amount")
    } else {
        rng.next_amount()
    };

    Exchange {
        subject: &parties[subject_index],
        witness: &parties[witness_index],
        participant: &parties[participant_index],
        amount,
    }
}

fn amount_token_for_exchange(
    blockchain: &Blockchain,
    exchange: &Exchange<'_>,
    amount_authority_signature: &str,
    amount_authority_did_key: &str,
) -> String {
    let records = exchange_records_without_proofs(exchange);
    let previous_participant = blockchain
        .chain
        .last()
        .and_then(|block| match &block.data {
            BlockData::Genesis => None,
            BlockData::PublicKeys(did_block) => did_key_for_role(did_block, DidRole::Participant),
        })
        .map(String::as_str);
    let previous_participant_amount = blockchain.chain.last().and_then(|block| match &block.data {
        BlockData::Genesis => None,
        BlockData::PublicKeys(did_block) => Some(did_block.amount),
    });
    let previous_participant_amount_token =
        blockchain.chain.last().and_then(|block| match &block.data {
            BlockData::Genesis => None,
            BlockData::PublicKeys(did_block) => Some(did_block.amount_tokens.participant.as_str()),
        });

    amount_token_for_block(
        &records,
        exchange.amount,
        amount_authority_signature,
        amount_authority_did_key,
        previous_participant,
        previous_participant_amount,
        previous_participant_amount_token,
    )
    .expect("load-test amount token should compute")
}

fn exchange_submissions(exchange: &Exchange<'_>, amount_token: &str) -> Vec<DidKeySubmission> {
    [
        (exchange.subject, DidRole::Subject),
        (exchange.witness, DidRole::Witness),
        (exchange.participant, DidRole::Participant),
    ]
    .into_iter()
    .map(|(party, role)| {
        let signature = party
            .signing_key
            .sign(amount_token.as_bytes(), BLS_SIGNATURE_DST, &[]);

        DidKeySubmission::with_role(
            party.did_key.clone(),
            role,
            OwnershipProof::new(amount_token, base64url(&signature.compress())),
        )
    })
    .collect()
}

fn exchange_records_without_proofs(exchange: &Exchange<'_>) -> Vec<DidKeyRecord> {
    [
        (exchange.subject, DidRole::Subject),
        (exchange.witness, DidRole::Witness),
        (exchange.participant, DidRole::Participant),
    ]
    .into_iter()
    .map(|(party, role)| {
        DidKeyRecord::new(party.did_key.clone(), role, OwnershipProof::new("", ""))
    })
    .collect()
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

    amount_proof_key_for_records(&records).expect("load-test signatures should aggregate")
}

fn current_owner_index(blockchain: &Blockchain, parties: &[Party]) -> Option<usize> {
    let owner_did_key = blockchain
        .chain
        .iter()
        .rev()
        .find_map(|block| match &block.data {
            BlockData::Genesis => None,
            BlockData::PublicKeys(did_block) => did_key_for_role(did_block, DidRole::Participant),
        })?;

    parties
        .iter()
        .position(|party| party.did_key == *owner_did_key)
}

fn current_owner_amount(blockchain: &Blockchain) -> Option<u8> {
    blockchain
        .chain
        .iter()
        .rev()
        .find_map(|block| match &block.data {
            BlockData::Genesis => None,
            BlockData::PublicKeys(did_block) => Some(did_block.amount),
        })
}

fn did_key_for_role(did_block: &did::DidKeyBlock, role: DidRole) -> Option<&String> {
    did_block
        .records
        .iter()
        .find(|record| record.role == role)
        .map(|record| &record.did_key)
}

fn random_distinct_index(rng: &mut XorShift64, len: usize, excluded: &[usize]) -> usize {
    loop {
        let index = rng.next_usize(len);
        if !excluded.contains(&index) {
            return index;
        }
    }
}

fn sign_amount_authority(signing_key: &SecretKey, amount: u8) -> String {
    let challenge = amount_authority_challenge(amount).expect("load-test amount should be valid");
    let signature = signing_key.sign(challenge.as_bytes(), BLS_SIGNATURE_DST, &[]);

    base64url(&signature.compress())
}

fn did_key_for_secret_key(signing_key: &SecretKey) -> String {
    did_key_from_bls12_381_public_key(&signing_key.sk_to_pk().compress())
}

fn bls_secret_key(seed: u64) -> SecretKey {
    let mut ikm = [0u8; 32];
    ikm[..8].copy_from_slice(&seed.to_le_bytes());

    SecretKey::key_gen(&ikm, &[]).expect("load-test BLS key material should be valid")
}

fn base64url(bytes: &[u8]) -> String {
    use base64::Engine;

    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Debug, Clone, Copy)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.state = value;
        value
    }

    fn next_usize(&mut self, max: usize) -> usize {
        (self.next_u64() as usize) % max
    }

    fn next_amount(&mut self) -> u8 {
        (self.next_u64() % 99 + 1) as u8
    }
}

impl Config {
    fn from_args() -> Self {
        let args = env::args().collect::<Vec<_>>();

        Self {
            workers: arg_or_default(&args, "--workers", 4),
            ops_per_worker: arg_or_default(&args, "--ops", 250),
            parties: arg_or_default(&args, "--parties", 32).max(3),
            difficulty_bits: arg_or_default(&args, "--difficulty", 1),
            seed: arg_or_default(&args, "--seed", 0x5048_4943_5259_5054),
            print_blocks: args.iter().any(|arg| arg == "--print-blocks"),
        }
    }
}

fn arg_or_default<T>(args: &[String], name: &str, default: T) -> T
where
    T: std::str::FromStr,
{
    args.windows(2)
        .find(|window| window[0] == name)
        .and_then(|window| window[1].parse::<T>().ok())
        .unwrap_or(default)
}
