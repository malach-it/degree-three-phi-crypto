# phi-crypto

A small Rust blockchain experiment using BLS12-381 `did:key` identifiers.

The chain has a square-mined genesis block. Public-key blocks are mined by
verifying an amount proof protocol between three roles:

- subject
- witness
- participant

Each public-key block is now a receipt: it stores only the accepted
`three_degree_phi_token` and the authority signature over that token. The
amount, role records, role tokens, and party signatures are verified when the
block is created, but they are not persisted in the block.

## Amount Protocol

An amount is a small integer less than 100. The amount authority is not stored
as a block participant. For a fresh transaction, the `amount_token_group` starts
from the authority DID key. For a linked duplicate transaction, where the
previous participant becomes the next subject, the `amount_token_group` starts from
the previous participant amount token:

```text
fresh amount_token_group = authority_key
linked amount_token_group = previous_participant_amount_token
```

The parties derive an amount token for each role:

```text
amount_token_subject = amount_token_group + amount * subject_key
amount_token_witness = amount_token_group + amount * witness_key
amount_token_participant = amount_token_group + amount * participant_key
```

These are public group keys. They prove the block used the same amount
duplication count for each role key.

Each party signs its own role amount token:

```text
subject_signature = sign(subject_key, amount_token_subject)
witness_signature = sign(witness_key, amount_token_witness)
participant_signature = sign(participant_key, amount_token_participant)
```

The submitted `three_degree_phi_token` is the aggregate of those signatures:

```text
three_degree_phi_token =
  subject_signature + witness_signature + participant_signature
```

During block creation, the block verifies the submitted aggregate and the
authority signs the accepted three degree phi token:

```text
three_degree_phi_token_authority_signature =
  sign(authority_key, "authorize phi-crypto three degree phi token {three_degree_phi_token}")
```

At block creation, the chain recomputes the role amount tokens, checks that
each party signed the correct role token, checks that the submitted
`three_degree_phi_token` matches the aggregate signatures, and verifies the authority
signature over the resulting `three_degree_phi_token`.

Later chain validation can verify the persisted receipt and block hash, but it
cannot replay the full three-party transaction proof from the block alone
because the block no longer stores the amount or DID records.

## Three-Party Block Verification

The three parties can still verify a block together if they retain or exchange
the transaction witness data used at creation time:

```text
amount
subject DID record and signature
witness DID record and signature
participant DID record and signature
previous participant amount token, for chained transactions
```

Given that witness data and the stored block receipt, they verify:

```text
role amount tokens recompute from amount and DID records
each party signature verifies its role amount token
subject_signature + witness_signature + participant_signature == three_degree_phi_token
three_degree_phi_token_authority_signature verifies authority approval of three_degree_phi_token
```

Without that external witness data, the stored block proves only that the
authority approved the aggregate `three_degree_phi_token`; it does not reveal or
reconstruct the three parties, their roles, or the amount.

## Can Two Parties Deduce The Third DID?

No.

Two parties cannot derive the third party DID from only:

```text
three_degree_phi_token
three_degree_phi_token_authority_signature
their own amount tokens
their own signatures
```

The reason is that `three_degree_phi_token` is an aggregate of BLS signatures, not an
aggregate of public DID keys. Removing two known signatures from the aggregate
can reveal the remaining signature value, but a BLS signature does not reveal
the signer's public key. Recovering the public key from that signature would be
equivalent to breaking the underlying elliptic-curve discrete-log assumption.

The authority signature does not change that. It attests that the authority saw
and accepted the aggregate three degree phi token, but it does not make the aggregate
reversible into the hidden party's DID.

What two parties can do is verify a candidate DID if someone presents one. Given
the candidate DID, the role-specific challenge, and the candidate signature,
they can check whether the candidate verifies against the aggregate protocol.

So the distinction is:

- Derivation: not possible from the aggregate proof alone.
- Candidate verification: possible when a candidate DID/signature is supplied.

To verify a known candidate third DID, two parties check the candidate against
the public block result:

```text
candidate_signature verifies candidate_did over candidate_role_amount_token
candidate_signature + known_signature_1 + known_signature_2 == three_degree_phi_token
three_degree_phi_token_authority_signature verifies authority approval of three_degree_phi_token
```

In other words, the candidate DID is accepted only if its signature verifies the
candidate role amount token and the three signatures aggregate back to the
block's `three_degree_phi_token`.

This means the protocol can prove participation by known DIDs, but it is not a
DID discovery mechanism.

## Load Test

Run parallel random token exchanges with:

```bash
cargo run --bin load_test -- --workers 4 --ops 250 --parties 32 --difficulty 1 --print-blocks
```

Omit `--print-blocks` for longer runs. The load test prints accepted/rejected
operation counts, two-party proof checks, final chain validity, and elapsed
time.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
