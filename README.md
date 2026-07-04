# phi-crypto

A small Rust blockchain experiment using BLS12-381 `did:key` identifiers.

The chain has a square-mined genesis block. Public-key blocks are mined by
verifying an amount proof protocol between three roles:

- subject
- witness
- participant

Each public-key block stores three DID keys, one per role. The witness is a
separate role, and only one witness is allowed per block.

## Amount Protocol

An amount is a small integer less than 100. The amount authority is not stored
as a block participant. Instead, it signs the amount:

```text
authority_signature = sign(authority_key, "authorize phi-crypto amount {amount}")
```

For a normal block, the block `amount_key` is this authority signature. For a
linked duplicate block, where the previous participant becomes the next subject,
the `amount_key` is a group addition:

```text
amount_key = authority_key + previous_participant_key + subject_key
```

Each party receives the same common challenge:

```text
common_challenge = amount_key
```

Then each party signs that challenge:

```text
subject_signature = sign(subject_key, amount_key)
witness_signature = sign(witness_key, amount_key)
participant_signature = sign(participant_key, amount_key)
```

The block `amount_proof_key` is the aggregate of those signatures:

```text
amount_proof_key =
  subject_signature + witness_signature + participant_signature
```

The authority then signs the aggregate amount proof key:

```text
amount_proof_key_authority_signature =
  sign(authority_key, "authorize phi-crypto amount proof key {amount_proof_key}")
```

Block verification recomputes the aggregate, checks that each party actually
signed the block `amount_key`, and verifies the authority signature over the
resulting `amount_proof_key`.

## Role Amount Keys

The block also stores a derived amount key for each role:

```text
amount_key_subject = amount_key_group + amount * subject_key
amount_key_witness = amount_key_group + amount * witness_key
amount_key_participant = amount_key_group + amount * participant_key
```

These are public group keys. They prove the block used the same amount
duplication count for each role key.

## Can Two Parties Deduce The Third DID?

No.

Two parties cannot derive the third party DID from only:

```text
amount_proof_key
amount_proof_key_authority_signature
their own amount keys
their own signatures
```

The reason is that `amount_proof_key` is an aggregate of BLS signatures, not an
aggregate of public DID keys. Removing two known signatures from the aggregate
can reveal the remaining signature value, but a BLS signature does not reveal
the signer's public key. Recovering the public key from that signature would be
equivalent to breaking the underlying elliptic-curve discrete-log assumption.

The authority signature does not change that. It attests that the authority saw
and accepted the aggregate amount proof key, but it does not make the aggregate
reversible into the hidden party's DID.

What two parties can do is verify a candidate DID if someone presents one. Given
the candidate DID, the common challenge, and the candidate signature, they can
check whether the candidate verifies against the aggregate protocol.

So the distinction is:

- Derivation: not possible from the aggregate proof alone.
- Candidate verification: possible when a candidate DID/signature is supplied.

This means the protocol can prove participation by known DIDs, but it is not a
DID discovery mechanism.
