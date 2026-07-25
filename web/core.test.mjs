import test from "node:test";
import assert from "node:assert/strict";
import {
  createForwardExchange,
  createTraitExchange,
  decryptPrivateValue,
  derivePrivateDid,
  encryptPrivateValue,
  exchangeValidity,
  groupAmountForDepth,
  informationHoldingsFor,
  maxDepthFromGroupAmount,
  recipientAcceptancePayload,
  traitCommitment,
  traitVerificationPayload,
  witnessApprovalPayload,
} from "./core.mjs";

const identities = [
  { id: "owner", did: "did:phi:owner", role: "Owner", status: "active" },
  { id: "member", did: "did:phi:member", role: "Member", status: "active" },
];

test("private DID derivation is deterministic but context-separated", async () => {
  const input = { name: "Ada", context: "Research", entropy: "fixed-private-salt" };
  const first = await derivePrivateDid(input);
  const second = await derivePrivateDid(input);
  const otherContext = await derivePrivateDid({ ...input, context: "Treasury" });
  assert.equal(first.did, second.did);
  assert.notEqual(first.did, otherContext.did);
  assert.match(first.did, /^did:phi:z/);
});

test("group amount exponent deterministically encodes maximum depth", () => {
  assert.equal(groupAmountForDepth(0), 1);
  assert.equal(groupAmountForDepth(3), 8);
  assert.equal(groupAmountForDepth(6), 64);
  assert.equal(maxDepthFromGroupAmount(8), 3);
  assert.equal(maxDepthFromGroupAmount(3), null);
});

test("private information is encrypted with authenticated AES-GCM", async () => {
  const key = await globalThis.crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  const encrypted = await encryptPrivateValue("EU", key);
  assert.equal(encrypted.algorithm, "AES-GCM");
  assert.notEqual(encrypted.ciphertext, "EU");
  assert.equal(await decryptPrivateValue(encrypted, key), "EU");
  await assert.rejects(
    decryptPrivateValue({ ...encrypted, ciphertext: `${encrypted.ciphertext.slice(0, -2)}AA` }, key),
  );
});

test("verified information has a canonical owner-signing payload", () => {
  const trait = {
    id: "jurisdiction",
    name: "Jurisdiction",
    value: "EU",
    classification: "verified",
    subjectId: "member",
    subjectDid: identities[1].did,
  };
  const first = traitVerificationPayload(identities[0].did, trait);
  assert.equal(first, traitVerificationPayload(identities[0].did, { ...trait }));
  assert.notEqual(
    first,
    traitVerificationPayload(identities[0].did, { ...trait, value: "US" }),
  );
});

test("trait commitments detect changes to an information snapshot", () => {
  const sourceTrait = {
    id: "trait_jurisdiction",
    name: "Jurisdiction",
    value: "EU",
    classification: "verified",
  };
  const snapshot = [{ ...sourceTrait }];
  const commitment = traitCommitment(snapshot);
  sourceTrait.value = "US";
  assert.equal(snapshot[0].value, "EU");
  assert.equal(commitment, traitCommitment(snapshot));
  assert.notEqual(commitment, traitCommitment([sourceTrait]));
});

test("owned information preserves an independent claim subject", () => {
  const sourceTraits = [
    {
      id: "member-status",
      name: "Membership",
      value: "Active",
      classification: "verified",
      subjectId: "member",
      subjectDid: identities[1].did,
    },
  ];
  const exchange = createTraitExchange({
    sourceId: "owner",
    targetId: "third",
    sourceDid: identities[0].did,
    targetDid: "did:phi:third",
    sourceTraits,
    traitIds: ["member-status"],
    purpose: "Share owned membership information",
    expiresAt: "2026-03-01T00:00:00.000Z",
    consent: true,
    now: "2026-02-01T00:00:00.000Z",
  });
  assert.equal(exchange.sourceId, "owner");
  assert.equal(exchange.claimSubjectId, "member");
  assert.equal(exchange.claimSubjectDid, identities[1].did);
});

test("trait exchange selectively discloses consented owned information", () => {
  const sourceTraits = [
    { id: "country", name: "Country", value: "FR", classification: "verified" },
    { id: "member", name: "Membership", value: "Core", classification: "private" },
  ];
  const exchange = createTraitExchange({
    sourceId: "owner",
    targetId: "member",
    sourceDid: identities[0].did,
    targetDid: identities[1].did,
    witnessId: "witness",
    witnessDid: "did:phi:witness",
    sourceTraits,
    traitIds: ["country"],
    purpose: "Eligibility check",
    expiresAt: "2026-03-01T00:00:00.000Z",
    consent: true,
    allowRedisclosure: true,
    maxDepth: 2,
    now: "2026-02-01T00:00:00.000Z",
  });
  assert.deepEqual(exchange.disclosures.map((trait) => trait.id), ["country"]);
  assert.equal(exchange.groupAmount, 4);
  assert.equal(maxDepthFromGroupAmount(exchange.groupAmount), 2);
  assert.equal(exchange.status, "pending_witness");
  exchange.senderSignature = "sender-bls-signature";
  const witnessPayload = witnessApprovalPayload(exchange);
  assert.match(witnessPayload, /sender-bls-signature/);
  exchange.witnessSignature = "witness-bls-signature";
  exchange.witnessVerified = true;
  const acceptancePayload = recipientAcceptancePayload(exchange);
  assert.match(acceptancePayload, /sender-bls-signature/);
  assert.match(acceptancePayload, /witness-bls-signature/);
  exchange.recipientSignature = "recipient-bls-signature";
  exchange.signaturesVerified = true;
  exchange.groupReceipt = {
    amount: 4,
    maxDepth: 2,
    hop: 0,
    disclosureCommitment: exchange.disclosureCommitment,
    blockIndex: 1,
    blockHash: "block-hash",
    witnessDid: "did:phi:witness",
    degreeThreePhiToken: "phi-group-token-hop-0",
    participantAmountToken: "participant-amount-token-hop-0",
  };
  exchange.status = "accepted";
  exchange.acceptedAt = "2026-02-01T00:01:00.000Z";
  assert.equal(
    exchangeValidity(exchange, new Date("2026-02-02T00:00:00.000Z")).valid,
    true,
  );
  const holdings = informationHoldingsFor(
    "member",
    [exchange],
    new Date("2026-02-02T00:00:00.000Z"),
  );
  assert.equal(holdings.length, 1);
  assert.equal(holdings[0].holderId, "member");
  assert.equal(holdings[0].subjectId, "owner");
  assert.equal(holdings[0].trait.value, "FR");
  assert.equal(holdings[0].valid, true);
  const forwarded = createForwardExchange({
    parentExchange: exchange,
    sourceId: "member",
    targetId: "third",
    sourceDid: identities[1].did,
    targetDid: "did:phi:third",
    purpose: "Downstream eligibility",
    expiresAt: "2026-02-20T00:00:00.000Z",
    consent: true,
    now: "2026-02-03T00:00:00.000Z",
  });
  assert.equal(forwarded.claimSubjectId, "owner");
  assert.equal(forwarded.sourceId, "member");
  assert.equal(forwarded.depth, 1);
  assert.equal(forwarded.groupId, exchange.groupId);
  assert.equal(forwarded.groupAmount, exchange.groupAmount);
  exchange.status = "revoked";
  assert.equal(
    exchangeValidity(exchange, new Date("2026-02-02T00:00:00.000Z")).valid,
    false,
  );
  assert.equal(
    informationHoldingsFor(
      "member",
      [exchange],
      new Date("2026-02-02T00:00:00.000Z"),
    )[0].valid,
    false,
  );
});

test("trait exchange rejects missing consent and self-disclosure", () => {
  const sourceTraits = [
    { id: "country", name: "Country", value: "FR", classification: "verified" },
  ];
  const request = {
    sourceId: "owner",
    targetId: "member",
    sourceDid: identities[0].did,
    targetDid: identities[1].did,
    sourceTraits,
    traitIds: ["country"],
    purpose: "Eligibility check",
    expiresAt: "2026-03-01T00:00:00.000Z",
    consent: false,
    now: "2026-02-01T00:00:00.000Z",
  };
  assert.throws(() => createTraitExchange(request), /consent/i);
  assert.throws(
    () => createTraitExchange({ ...request, consent: true, targetId: "owner" }),
    /different identities/i,
  );
  assert.throws(
    () =>
      createTraitExchange({
        ...request,
        consent: true,
        witnessId: "owner",
        witnessDid: identities[0].did,
      }),
    /witness must be a distinct identity/i,
  );
});
