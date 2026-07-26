export const ROLE_LEVELS = {
  Observer: 1,
  Member: 2,
  Steward: 3,
  Admin: 4,
  Owner: 5,
};

export const MAX_GROUP_DEPTH = 6;

export function groupAmountForDepth(depth) {
  const normalized = Math.max(0, Math.min(MAX_GROUP_DEPTH, Number(depth) || 0));
  return 2 ** normalized;
}

export function maxDepthFromGroupAmount(amount) {
  const value = Number(amount);
  if (!Number.isInteger(value) || value < 1 || value > 64 || (value & (value - 1)) !== 0) {
    return null;
  }
  return Math.log2(value);
}

export function uid(prefix = "rec") {
  const random = globalThis.crypto?.randomUUID?.() || Math.random().toString(36).slice(2);
  return `${prefix}_${random}`;
}

export function phiHash(input, length = 24) {
  let left = 0x811c9dc5;
  let right = 0x9e3779b9;
  for (let index = 0; index < input.length; index += 1) {
    const code = input.charCodeAt(index);
    left = Math.imul(left ^ code, 0x01000193);
    right = Math.imul(right ^ code, 0x85ebca6b);
  }
  let output = "";
  while (output.length < length) {
    left ^= left >>> 16;
    left = Math.imul(left, 0x7feb352d);
    right ^= right >>> 13;
    right = Math.imul(right, 0xc2b2ae35);
    output += `${(left >>> 0).toString(16).padStart(8, "0")}${(right >>> 0)
      .toString(16)
      .padStart(8, "0")}`;
  }
  return output.slice(0, length);
}

function base58(bytes) {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let index = 0; index < digits.length; index += 1) {
      carry += digits[index] << 8;
      digits[index] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  return [...bytes]
    .findIndex((byte) => byte !== 0) > 0
    ? "1".repeat([...bytes].findIndex((byte) => byte !== 0)) +
        digits.reverse().map((digit) => alphabet[digit]).join("")
    : digits.reverse().map((digit) => alphabet[digit]).join("");
}

export async function derivePrivateDid({ name, context, entropy }) {
  const input = new TextEncoder().encode(`phi-identity-v1|${name}|${context}|${entropy}`);
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", input));
  const did = `did:phi:z${base58(digest)}`;
  return {
    did,
    fingerprint: phiHash(`${did}|${context}`, 16).match(/.{1,4}/g).join("·").toUpperCase(),
    derivation: "phi-context-v1",
    mode: "browser-derived",
  };
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return globalThis.btoa(binary);
}

function base64ToBytes(value) {
  const binary = globalThis.atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export async function encryptPrivateValue(value, key) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(String(value)),
  );
  return {
    algorithm: "AES-GCM",
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  };
}

export async function decryptPrivateValue(encryptedValue, key) {
  if (encryptedValue?.algorithm !== "AES-GCM") {
    throw new Error("Unsupported private information encryption.");
  }
  const plaintext = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(encryptedValue.iv) },
    key,
    base64ToBytes(encryptedValue.ciphertext),
  );
  return new TextDecoder().decode(plaintext);
}

export function roleContract(identity) {
  const level = ROLE_LEVELS[identity.role] || 1;
  const inherited = Object.entries(ROLE_LEVELS)
    .filter(([, value]) => value <= level)
    .map(([role]) => role.toLowerCase());
  return `φ.role(${identity.did.slice(-8)}) ≥ ${level} ⇒ {${inherited.join(", ")}}`;
}

export function traitCommitment(traits = []) {
  const canonical = traits
    .map(
      ({
        id,
        name,
        value,
        encryptedValue,
        verification,
        classification,
        subjectId,
        subjectDid,
      }) => ({
      id,
      name: String(name).trim(),
      value: value == null ? null : String(value).trim(),
      encryptedValue: encryptedValue || null,
      verification: verification || null,
      classification,
      subjectId: subjectId || null,
      subjectDid: subjectDid || null,
      }),
    )
    .sort((left, right) => left.id.localeCompare(right.id));
  return `φtrait_${phiHash(JSON.stringify(canonical), 40)}`;
}

export function traitVerificationPayload(ownerDid, trait) {
  return JSON.stringify({
    protocol: "phi-trait-verification-v1",
    ownerDid,
    id: trait.id,
    name: String(trait.name).trim(),
    value: trait.value == null ? null : String(trait.value).trim(),
    classification: trait.classification,
    subjectId: trait.subjectId || null,
    subjectDid: trait.subjectDid || null,
  });
}

export function amountTokenEntries(receipt = {}) {
  receipt ||= {};
  return [
    {
      key: "group",
      label: "Group custody input",
      shortLabel: "G",
      kind: "base",
      token: receipt.amountTokenGroup,
    },
    {
      key: "subject",
      label: "Subject amount token",
      shortLabel: "S",
      kind: "role",
      token: receipt.subjectAmountToken,
    },
    {
      key: "witness",
      label: "Witness amount token",
      shortLabel: "W",
      kind: "role",
      token: receipt.witnessAmountToken,
    },
    {
      key: "participantBase",
      label: "Recipient custody token",
      shortLabel: "B",
      kind: "base",
      token: receipt.participantBaseAmountToken,
    },
    {
      key: "participant",
      label: "Recipient amount token",
      shortLabel: "R",
      kind: "role",
      token: receipt.participantAmountToken,
    },
  ].filter(({ token }) => typeof token === "string" && token.length > 0);
}

export function identityWalletUrl(identityId, view = null) {
  const id = String(identityId || "").trim();
  if (!id) throw new Error("Identity ID is required.");
  const query = new URLSearchParams({ identity: id });
  if (view) query.set("view", view);
  return `/wallet?${query}`;
}

export function walletSignatureRequests(identityId, exchanges = []) {
  return exchanges.flatMap((exchange) => {
    const role = pendingExchangeSignatureRole(exchange);
    if (role === "sender" && exchange.sourceId === identityId) {
      return [{ exchange, role: "sender" }];
    }
    if (role === "witness" && exchange.witnessId === identityId) {
      return [{ exchange, role: "witness" }];
    }
    if (role === "recipient" && exchange.targetId === identityId) {
      return [{ exchange, role: "recipient" }];
    }
    return [];
  });
}

export function pendingExchangeSignatureRole(exchange) {
  if (!exchange || exchange.status === "accepted" || exchange.status === "revoked") {
    return null;
  }
  if (!exchange.senderSignature) return "sender";
  if (
    exchange.witnessDid &&
    (!exchange.witnessSignature || !exchange.witnessVerified)
  ) {
    return "witness";
  }
  if (!exchange.recipientSignature) return "recipient";
  return null;
}

export function createTraitExchange({
  sourceId,
  targetId,
  sourceDid,
  targetDid,
  witnessId = null,
  witnessDid = null,
  sourceTraits,
  traitIds,
  purpose,
  expiresAt,
  consent,
  allowRedisclosure = false,
  maxDepth = 0,
  now = new Date().toISOString(),
}) {
  if (!consent) throw new Error("Source consent is required.");
  if (!sourceId || sourceId === targetId) {
    throw new Error("Source and recipient must be different identities.");
  }
  if (!sourceDid || !targetDid || sourceDid === targetDid) {
    throw new Error("Source and recipient must have distinct DIDs.");
  }
  if (
    (witnessId && !witnessDid) ||
    (!witnessId && witnessDid) ||
    (witnessDid && (witnessDid === sourceDid || witnessDid === targetDid))
  ) {
    throw new Error("Witness must be a distinct identity with a DID.");
  }
  const disclosures = (sourceTraits || [])
    .filter((trait) => traitIds.includes(trait.id))
    .map((trait) => ({ ...trait }));
  if (!disclosures.length) throw new Error("Select at least one owned information record.");
  const claimSubjects = new Map(
    disclosures.map((trait) => [
      trait.subjectId || sourceId,
      trait.subjectDid || sourceDid,
    ]),
  );
  if (claimSubjects.size !== 1) {
    throw new Error("One exchange can disclose information about only one subject.");
  }
  const [claimSubjectId, claimSubjectDid] = claimSubjects.entries().next().value;
  if (!purpose?.trim()) throw new Error("An exchange purpose is required.");
  if (!expiresAt || new Date(expiresAt) <= new Date(now)) {
    throw new Error("Expiry must be in the future.");
  }
  const id = uid("xchg");
  const disclosureCommitment = traitCommitment(disclosures);
  const depthLimit = allowRedisclosure
    ? Math.max(1, Math.min(MAX_GROUP_DEPTH, Number(maxDepth) || 1))
    : 0;
  const groupAmount = groupAmountForDepth(depthLimit);
  const exchange = {
    protocol: "phi-exchange-v1",
    id,
    sourceDid,
    targetDid,
    witnessDid,
    claimSubjectDid,
    sourceRegistryCommitment: traitCommitment(sourceTraits),
    disclosureCommitment,
    purpose: purpose.trim(),
    expiresAt,
    createdAt: now,
    parentExchangeId: null,
    groupId: id,
    groupAmount,
    traitCount: disclosures.length,
    depth: 0,
    allowRedisclosure: Boolean(allowRedisclosure),
    maxDepth: depthLimit,
  };
  return {
    id,
    sourceId,
    targetId,
    claimSubjectId,
    sourceDid,
    targetDid,
    claimSubjectDid,
    witnessId,
    witnessDid,
    disclosures: disclosures.map((trait) => ({ ...trait })),
    disclosureCommitment,
    purpose: purpose.trim(),
    expiresAt,
    consentedAt: null,
    createdAt: now,
    parentExchangeId: null,
    groupId: id,
    groupAmount,
    traitCount: disclosures.length,
    depth: 0,
    allowRedisclosure: exchange.allowRedisclosure,
    maxDepth: depthLimit,
    payload: JSON.stringify(exchange),
    status: "pending_sender",
    revokedAt: null,
    senderSignature: null,
    witnessSignature: null,
    witnessVerified: false,
    recipientSignature: null,
    signaturesVerified: false,
    groupReceipt: null,
  };
}

export function createForwardExchange({
  parentExchange,
  sourceId,
  targetId,
  sourceDid,
  targetDid,
  witnessId = null,
  witnessDid = null,
  purpose,
  expiresAt,
  consent,
  now = new Date().toISOString(),
}) {
  const parentValidity = exchangeValidity(parentExchange, new Date(now));
  if (!parentValidity.valid) throw new Error("The parent information holding is not valid.");
  if (!parentExchange.allowRedisclosure) {
    throw new Error("The original subject did not grant redisclosure rights.");
  }
  const derivedMaxDepth = maxDepthFromGroupAmount(parentExchange.groupAmount);
  if (derivedMaxDepth === null) {
    throw new Error("The parent group amount is not a valid exponent.");
  }
  if (parentExchange.depth >= derivedMaxDepth) {
    throw new Error("The information group has reached its maximum redisclosure depth.");
  }
  if (sourceId !== parentExchange.targetId || sourceDid !== parentExchange.targetDid) {
    throw new Error("Only the current information holder can redisclose this group.");
  }
  if (!targetId || targetId === sourceId || !targetDid || targetDid === sourceDid) {
    throw new Error("Choose a different recipient identity.");
  }
  if (
    (witnessId && !witnessDid) ||
    (!witnessId && witnessDid) ||
    (witnessDid && (witnessDid === sourceDid || witnessDid === targetDid))
  ) {
    throw new Error("Witness must be a distinct identity with a DID.");
  }
  if (!consent) throw new Error("Current holder consent is required.");
  if (!purpose?.trim()) throw new Error("A redisclosure purpose is required.");
  if (
    !expiresAt ||
    new Date(expiresAt) <= new Date(now) ||
    new Date(expiresAt) > new Date(parentExchange.expiresAt)
  ) {
    throw new Error("Expiry must be in the future and no later than the parent receipt.");
  }
  const id = uid("xchg");
  const depth = parentExchange.depth + 1;
  const payloadFields = {
    protocol: "phi-exchange-v1",
    id,
    sourceDid,
    targetDid,
    witnessDid,
    claimSubjectDid: parentExchange.claimSubjectDid || parentExchange.sourceDid,
    parentReceiptCommitment: parentExchange.groupReceipt.degreeThreePhiToken,
    disclosureCommitment: parentExchange.disclosureCommitment,
    purpose: purpose.trim(),
    expiresAt,
    createdAt: now,
    parentExchangeId: parentExchange.id,
    groupId: parentExchange.groupId,
    groupAmount: parentExchange.groupAmount,
    traitCount: parentExchange.traitCount || parentExchange.disclosures.length,
    depth,
    allowRedisclosure: parentExchange.allowRedisclosure,
    maxDepth: derivedMaxDepth,
  };
  return {
    id,
    sourceId,
    targetId,
    claimSubjectId: parentExchange.claimSubjectId || parentExchange.sourceId,
    sourceDid,
    targetDid,
    claimSubjectDid: parentExchange.claimSubjectDid || parentExchange.sourceDid,
    witnessId,
    witnessDid,
    disclosures: parentExchange.disclosures.map((trait) => ({ ...trait })),
    disclosureCommitment: parentExchange.disclosureCommitment,
    purpose: purpose.trim(),
    expiresAt,
    consentedAt: null,
    createdAt: now,
    parentExchangeId: parentExchange.id,
    groupId: parentExchange.groupId,
    groupAmount: parentExchange.groupAmount,
    traitCount: parentExchange.traitCount || parentExchange.disclosures.length,
    depth,
    allowRedisclosure: parentExchange.allowRedisclosure,
    maxDepth: derivedMaxDepth,
    payload: JSON.stringify(payloadFields),
    status: "pending_sender",
    revokedAt: null,
    senderSignature: null,
    witnessSignature: null,
    witnessVerified: false,
    recipientSignature: null,
    signaturesVerified: false,
    groupReceipt: null,
  };
}

export function recipientAcceptancePayload(exchange) {
  return JSON.stringify({
    protocol: "phi-exchange-acceptance-v1",
    exchangePayload: exchange.payload,
    senderSignature: exchange.senderSignature,
    witnessSignature: exchange.witnessSignature || null,
  });
}

export function witnessApprovalPayload(exchange) {
  return JSON.stringify({
    protocol: "phi-exchange-witness-v1",
    exchangePayload: exchange.payload,
    senderSignature: exchange.senderSignature,
    witnessDid: exchange.witnessDid,
  });
}

export function exchangeValidity(exchange, now = new Date()) {
  if (exchange.status === "revoked") return { valid: false, reason: "Exchange revoked" };
  if (new Date(exchange.expiresAt) <= now) return { valid: false, reason: "Exchange expired" };
  if (traitCommitment(exchange.disclosures) !== exchange.disclosureCommitment) {
    return { valid: false, reason: "Disclosure commitment mismatch" };
  }
  const derivedMaxDepth = maxDepthFromGroupAmount(exchange.groupAmount);
  if (derivedMaxDepth === null || exchange.depth > derivedMaxDepth) {
    return { valid: false, reason: "Invalid exponentiated group depth" };
  }
  if (!exchange.senderSignature) return { valid: false, reason: "Sender signature missing" };
  if (
    exchange.witnessDid &&
    (!exchange.witnessSignature || !exchange.witnessVerified)
  ) {
    return { valid: false, reason: "Awaiting witness approval" };
  }
  if (!exchange.recipientSignature || exchange.status === "pending_recipient") {
    return { valid: false, reason: "Awaiting recipient signature" };
  }
  if (!exchange.signaturesVerified) {
    return { valid: false, reason: "Signatures not verified" };
  }
  if (!exchange.groupReceipt) {
    return { valid: false, reason: "Group amount receipt missing" };
  }
  if (
    Number(exchange.groupReceipt.amount) !== Number(exchange.groupAmount) ||
    Number(exchange.groupReceipt.maxDepth) !== derivedMaxDepth ||
    Number(exchange.groupReceipt.hop) !== Number(exchange.depth) ||
    exchange.groupReceipt.disclosureCommitment !== exchange.disclosureCommitment
  ) {
    return { valid: false, reason: "Group amount receipt mismatch" };
  }
  if (
    !Number.isInteger(Number(exchange.groupReceipt.blockIndex)) ||
    !exchange.groupReceipt.blockHash
  ) {
    return { valid: false, reason: "On-chain block reference missing" };
  }
  if (
    (exchange.witnessDid || null) !==
    (exchange.groupReceipt.witnessDid || null)
  ) {
    return { valid: false, reason: "Witness receipt mismatch" };
  }
  return { valid: true, reason: "Dual signatures and group amount verified" };
}

export function informationHoldingsFor(
  holderId,
  exchanges,
  now = new Date(),
) {
  return exchanges
    .filter((exchange) => exchange.targetId === holderId)
    .flatMap((exchange) => {
      const validity = exchangeValidity(exchange, now);
      return exchange.disclosures.map((trait) => ({
        id: `${exchange.id}:${trait.id}`,
        holderId,
        subjectId: exchange.claimSubjectId || exchange.sourceId,
        sourceDid: exchange.claimSubjectDid || exchange.sourceDid,
        trait: { ...trait },
        exchangeId: exchange.id,
        purpose: exchange.purpose,
        acquiredAt: exchange.acceptedAt || exchange.createdAt,
        expiresAt: exchange.expiresAt,
        receiptStatus: exchange.status,
        depth: exchange.depth || 0,
        allowRedisclosure: exchange.allowRedisclosure === true,
        maxDepth: maxDepthFromGroupAmount(exchange.groupAmount) ?? 0,
        amountToken: exchange.groupReceipt?.participantAmountToken || null,
        valid: validity.valid,
        validityReason: validity.reason,
      }));
    });
}

export function demoState() {
  const now = Date.now();
  const identities = [
    {
      id: "id_ava",
      name: "Ava Chen",
      handle: "@ava",
      did: "did:key:z3tEFHKPLWzgC9mXrQj6PiDzxmfMCPdb1JUWkWnaeaZCXDRhHhmjv5knBohRaZEncfsr5i",
      fingerprint: "29A4·BC19·73F0·E2C8",
      role: "Owner",
      context: "Core treasury",
      status: "active",
      createdAt: new Date(now - 86400000 * 12).toISOString(),
      authenticity: "BLS12-381 authority attested",
      traits: [
        {
          id: "trait_ava_jurisdiction",
          name: "Jurisdiction",
          value: "EU",
          classification: "verified",
          subjectId: "id_ava",
          subjectDid:
            "did:key:z3tEFHKPLWzgC9mXrQj6PiDzxmfMCPdb1JUWkWnaeaZCXDRhHhmjv5knBohRaZEncfsr5i",
        },
        {
          id: "trait_ava_membership",
          name: "Membership",
          value: "Core contributor",
          classification: "private",
          subjectId: "id_ava",
          subjectDid:
            "did:key:z3tEFHKPLWzgC9mXrQj6PiDzxmfMCPdb1JUWkWnaeaZCXDRhHhmjv5knBohRaZEncfsr5i",
        },
      ],
    },
    {
      id: "id_mika",
      name: "Mika Sol",
      handle: "@mika",
      did: "did:key:z3tEG1BgUeeVmofi5MV3cU7LaYeocm9Ne2QkBPDdpDozyBCKjYgWa1VpStYho9EhC9P7vh",
      fingerprint: "3F9D·47C2·13A0·8BB5",
      role: "Steward",
      context: "Protocol operations",
      status: "active",
      createdAt: new Date(now - 86400000 * 8).toISOString(),
      authenticity: "BLS12-381 authority attested",
      traits: [
        {
          id: "trait_mika_clearance",
          name: "Verification level",
          value: "Level 3",
          classification: "verified",
          subjectId: "id_mika",
          subjectDid:
            "did:key:z3tEG1BgUeeVmofi5MV3cU7LaYeocm9Ne2QkBPDdpDozyBCKjYgWa1VpStYho9EhC9P7vh",
        },
      ],
    },
    {
      id: "id_noah",
      name: "Noah Williams",
      handle: "@noah",
      did: "did:key:z3tEGSKFD3nuGm4JqErNTVUYzeksa2Hs6P3C9rpFp93CbYQNDkyScdC7JPa8xojkatS4kA",
      fingerprint: "A10E·28D7·F34C·90B1",
      role: "Member",
      context: "Community",
      status: "active",
      createdAt: new Date(now - 86400000 * 4).toISOString(),
      authenticity: "BLS12-381 authority attested",
      traits: [],
    },
  ];
  return {
    version: 1,
    identities,
    exchanges: [],
  };
}

export function emptyState() {
  return {
    version: 1,
    identities: [],
    exchanges: [],
  };
}
