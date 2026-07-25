import {
  ROLE_LEVELS,
  amountTokenEntries,
  createForwardExchange,
  createTraitExchange,
  decryptPrivateValue,
  demoState,
  derivePrivateDid,
  emptyState,
  encryptPrivateValue,
  exchangeValidity,
  informationHoldingsFor,
  phiHash,
  recipientAcceptancePayload,
  roleContract,
  traitCommitment,
  traitVerificationPayload,
  uid,
  witnessApprovalPayload,
} from "./core.mjs";

const STORAGE_KEY = "phi.identity.workspace.v1";
const navItems = [
  ["overview", "⌂", "Overview"],
  ["identities", "◉", "Identities"],
  ["administration", "⇄", "Exchange"],
];

const app = document.querySelector("#app");
const modalRoot = document.querySelector("#modal-root");
const toastRoot = document.querySelector("#toast-root");
let state = loadState();
let currentPage = location.hash.slice(1) || "overview";
let pendingUndo = null;
const receiptVerificationResults = new Map();
const receiptRevealedParties = new Map();
const privateValueCache = new Map();
const ENCRYPTION_DB = "phi.identity.encryption.v1";

function privateValueKey(trait) {
  return `${trait.id}:${trait.encryptedValue?.ciphertext || ""}`;
}

function displayTraitValue(trait) {
  if (trait.classification !== "private") return trait.value ?? "";
  return privateValueCache.get(privateValueKey(trait)) || "•••• encrypted";
}

function classificationLabel(trait) {
  if (trait.classification === "private") return "private · AES-GCM encrypted";
  if (trait.classification === "verified") return "verified · BLS signed";
  return "public · cleartext";
}

function openEncryptionDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(ENCRYPTION_DB, 1);
    request.onupgradeneeded = () => request.result.createObjectStore("keys");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function workspaceEncryptionKey() {
  const database = await openEncryptionDatabase();
  const existing = await new Promise((resolve, reject) => {
    const request = database.transaction("keys").objectStore("keys").get("workspace");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  if (existing) {
    database.close();
    return existing;
  }
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  await new Promise((resolve, reject) => {
    const transaction = database.transaction("keys", "readwrite");
    transaction.objectStore("keys").put(key, "workspace");
    transaction.oncomplete = resolve;
    transaction.onerror = () => reject(transaction.error);
  });
  database.close();
  return key;
}

async function protectTrait(trait, ownerDid, allowVerifiedDowngrade = true) {
  if (trait.classification === "private") {
    const key = await workspaceEncryptionKey();
    if (trait.value != null) {
      const plaintext = String(trait.value);
      trait.encryptedValue = await encryptPrivateValue(plaintext, key);
      trait.value = null;
      privateValueCache.set(privateValueKey(trait), plaintext);
      return true;
    }
    if (trait.encryptedValue) {
      const plaintext = await decryptPrivateValue(trait.encryptedValue, key);
      privateValueCache.set(privateValueKey(trait), plaintext);
    }
    return false;
  }
  if (trait.classification === "verified") {
    const payload = traitVerificationPayload(ownerDid, trait);
    if (
      trait.verification?.did === ownerDid &&
      trait.verification.payload === payload &&
      trait.verification.signature
    ) {
      try {
        if (
          await verifyExchangeSignature(
            ownerDid,
            payload,
            trait.verification.signature,
          )
        ) {
          return false;
        }
      } catch {
        // Attempt to replace an unverifiable legacy signature below.
      }
    }
    try {
      const signature = await signExchangePayload(ownerDid, payload);
      if (!(await verifyExchangeSignature(ownerDid, payload, signature))) {
        throw new Error("Trait signature verification failed.");
      }
      trait.verification = { did: ownerDid, payload, signature };
    } catch {
      if (!allowVerifiedDowngrade) {
        throw new Error("Verified information requires the owner's active BLS signing key.");
      }
      trait.classification = "public";
      trait.verification = null;
    }
    return true;
  }
  return false;
}

async function hydratePrivateInformation() {
  let encryptionKey;
  const hydrate = async (trait) => {
    if (trait.classification !== "private") return;
    if (trait.value != null) {
      privateValueCache.set(privateValueKey(trait), String(trait.value));
      return;
    }
    if (!trait.encryptedValue) return;
    encryptionKey ||= await workspaceEncryptionKey();
    const plaintext = await decryptPrivateValue(trait.encryptedValue, encryptionKey);
    privateValueCache.set(privateValueKey(trait), plaintext);
  };

  for (const identity of state.identities) {
    for (const trait of identity.traits || []) await hydrate(trait);
  }
  for (const exchange of state.exchanges) {
    for (const trait of exchange.disclosures || []) await hydrate(trait);
  }
}

function loadState() {
  const serialized = localStorage.getItem(STORAGE_KEY);
  try {
    if (serialized) {
      const stored = JSON.parse(serialized);
      if (
        stored?.version === 1 &&
        Array.isArray(stored.identities) &&
        Array.isArray(stored.exchanges)
      ) {
        return stored;
      }
    }
  } catch {
    // Preserve unreadable storage instead of modifying it during startup.
  }
  const initial = demoState();
  if (!serialized) localStorage.setItem(STORAGE_KEY, JSON.stringify(initial));
  return initial;
}

function save() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

function escapeHtml(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function initials(name) {
  return name
    .split(/\s+/)
    .map((part) => part[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();
}

function shortDid(did) {
  return did.length > 35 ? `${did.slice(0, 19)}…${did.slice(-10)}` : did;
}

function renderAmountTokenSummary(receipt) {
  const entries = amountTokenEntries(receipt).filter(({ kind }) => kind === "role");
  if (!entries.length) return `<small class="helper">Pending accepted receipt</small>`;
  return `<div class="amount-token-summary">${entries
    .map(
      ({ label, shortLabel, token }) =>
        `<span title="${escapeHtml(`${label}: ${token}`)}"><b>${shortLabel}</b><code>${escapeHtml(shortDid(token))}</code></span>`,
    )
    .join("")}</div>`;
}

function renderAmountTokenDetails(receipt) {
  const entries = amountTokenEntries(receipt);
  if (!entries.length) {
    return `<div class="notice">Amount tokens are created when the recipient accepts and the exchange receipt is committed.</div>`;
  }
  return `<section class="amount-token-panel"><div class="token-panel-heading"><div><h3>Amount tokens</h3><p>Compact disclosure-bound BLS group points</p></div><span class="status-pill">${entries.filter(({ kind }) => kind === "role").length} role tokens</span></div><div class="amount-token-list">${entries
    .map(
      ({ label, kind, token }) =>
        `<div class="amount-token-row"><div><strong>${escapeHtml(label)}</strong><small>${kind === "base" ? "Custody chaining" : "Signed role token"}</small></div><code title="${escapeHtml(token)}">${escapeHtml(token)}</code><button class="button compact" data-action="copy-value" data-value="${escapeHtml(token)}">Copy</button></div>`,
    )
    .join("")}</div></section>`;
}

function ago(date) {
  const seconds = Math.max(1, Math.floor((Date.now() - new Date(date).getTime()) / 1000));
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function identityById(id) {
  return state.identities.find((identity) => identity.id === id);
}

function pageHeading(eyebrow, title, description, actions = "") {
  return `<div class="page-heading">
    <div><p class="eyebrow">${eyebrow}</p><h1>${title}</h1><p>${description}</p></div>
    ${actions ? `<div class="heading-actions">${actions}</div>` : ""}
  </div>`;
}

function emptyPanel(title, copy, action, label) {
  return `<div class="panel empty"><div><div class="empty-mark">φ</div><h3>${title}</h3><p>${copy}</p>
    ${action ? `<button class="button primary" data-action="${action}">${label}</button>` : ""}</div></div>`;
}

function identityRow(identity) {
  return `<div class="identity-row" data-action="view-identity" data-id="${identity.id}" tabindex="0">
    <div class="identity-main"><span class="identity-avatar">${initials(identity.name)}</span><span>
      <strong>${escapeHtml(identity.name)} <span style="color:var(--muted);font-weight:500">${escapeHtml(identity.handle)}</span></strong>
      <small title="${escapeHtml(identity.did)}">${escapeHtml(shortDid(identity.did))}</small>
    </span></div>
    <span class="role-pill">L${ROLE_LEVELS[identity.role]} · ${identity.role}</span>
    <span class="status-pill">${identity.status}</span>
    <button class="more" data-action="identity-menu" data-id="${identity.id}" aria-label="Identity actions">•••</button>
  </div>`;
}

function activityItems() {
  const items = [
    ...state.identities.map((item) => ({
      at: item.createdAt,
      icon: "◉",
      title: `${item.name} identity generated`,
      note: item.authenticity || "Privacy-scoped identifier",
    })),
    ...state.exchanges.map((item) => ({
      at: item.revokedAt || item.createdAt,
      icon: "⇄",
      title: `Trait exchange ${item.status === "revoked" ? "revoked" : "created"}`,
      note: `${identityById(item.sourceId)?.name || "Subject"} → ${identityById(item.targetId)?.name || "Recipient"}`,
    })),
  ];
  return items.sort((a, b) => new Date(b.at) - new Date(a.at)).slice(0, 5);
}

function custodySummary() {
  const exchanges = state.exchanges
    .filter((exchange) => exchangeValidity(exchange).valid)
    .slice()
    .reverse()
    .slice(0, 4);
  if (!exchanges.length) {
    return `<div class="empty"><div><div class="empty-mark">⇄</div><h3>No verified holdings yet</h3><p>Accepted information exchanges will appear here.</p><button class="button primary" data-nav="administration">Exchange information</button></div></div>`;
  }
  return `<div class="activity-list">${exchanges
    .map((exchange) => {
      const source = identityById(exchange.sourceId);
      const target = identityById(exchange.targetId);
      const subject = identityById(exchange.claimSubjectId || exchange.sourceId);
      return `<div class="activity"><span class="activity-icon">⇄</span><div><strong>${escapeHtml(source?.name || "Deleted sender")} → ${escapeHtml(target?.name || "Deleted recipient")}</strong><small>${exchange.disclosures.length} trait${exchange.disclosures.length === 1 ? "" : "s"} about ${escapeHtml(subject?.name || "deleted subject")} · ${ago(exchange.createdAt)}</small></div></div>`;
    })
    .join("")}</div>`;
}

function renderOverview() {
  const ownedInformation = state.identities.reduce(
    (sum, identity) => sum + (identity.traits?.length || 0),
    0,
  );
  const verifiedExchanges = state.exchanges.filter(
    (exchange) => exchangeValidity(exchange).valid,
  );
  return `${pageHeading(
    "Identity operations",
    "Your identity network",
    "Generate private identifiers and manage verifiable access from one workspace.",
    `<button class="button primary" data-action="new-identity">＋ Generate DID</button>`,
  )}
  <div class="metrics">
    <div class="metric"><small>Active identities</small><strong>${state.identities.filter((item) => item.status === "active").length}</strong><span>Local & private</span></div>
    <div class="metric"><small>Accepted exchanges</small><strong>${state.exchanges.filter((item) => item.status === "accepted").length}</strong><span>Dual-signed receipts</span></div>
    <div class="metric"><small>Owned information</small><strong>${ownedInformation}</strong><span>Subject-bound records</span></div>
    <div class="metric"><small>Verified receipts</small><strong>${verifiedExchanges.length}</strong><span>Cryptographically valid</span></div>
  </div>
  <div class="dashboard-grid">
    <div class="stack">
      <section class="panel">
        <div class="panel-header"><div><h2>Identity registry</h2><p>Identifiers and their phi-contract access</p></div><button class="text-button" data-nav="identities">View registry →</button></div>
        ${state.identities.length ? `<div class="identity-list">${state.identities.slice(0, 5).map(identityRow).join("")}</div>` : emptyPanel("No identities", "Generate a privacy-scoped identifier to begin.", "new-identity", "Generate identity")}
      </section>
      <section class="panel">
        <div class="panel-header"><div><h2>Verified information custody</h2><p>Valid exchanges held by their recipients</p></div><button class="text-button" data-nav="administration">Manage exchanges →</button></div>
        ${custodySummary()}
      </section>
    </div>
    <div class="stack">
      <section class="panel">
        <div class="panel-header"><div><h2>Recent activity</h2><p>Local, append-style event view</p></div></div>
        <div class="activity-list">${activityItems()
          .map(
            (item) => `<div class="activity"><span class="activity-icon">${item.icon}</span><div><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.note)} · ${ago(item.at)}</small></div></div>`,
          )
          .join("") || `<div class="empty"><p>No activity yet.</p></div>`}</div>
      </section>
      <section class="panel">
        <div class="panel-header"><div><h2>Security posture</h2><p>Workspace validation summary</p></div><span class="status-pill">Healthy</span></div>
        <div class="activity-list">
          <div class="activity"><span class="activity-icon">✓</span><div><strong>Dual-signed exchanges</strong><small>${verifiedExchanges.length}/${state.exchanges.length} receipts currently valid</small></div></div>
          <div class="activity"><span class="activity-icon">◇</span><div><strong>Receipt verification</strong><small>Party and authority signatures are checked independently</small></div></div>
          <div class="activity"><span class="activity-icon">φ</span><div><strong>Scoped identifiers</strong><small>Context salt prevents passive correlation</small></div></div>
        </div>
      </section>
    </div>
  </div>`;
}

function renderIdentities() {
  return `${pageHeading(
    "Registry",
    "Decentralized identities",
    "Each identifier is privacy-scoped, authority-attested when the local BLS runtime is available, and governed by a hierarchical role contract.",
    `<button class="button primary" data-action="new-identity">＋ Generate identity</button>`,
  )}
  ${
    state.identities.length
      ? `<section class="panel flush"><div class="table-wrap"><table><thead><tr><th>Identity</th><th>Role contract</th><th>Context</th><th>Authenticity</th><th></th></tr></thead><tbody>
      ${state.identities
        .map((identity) => `<tr><td><div class="identity-main"><span class="identity-avatar">${initials(identity.name)}</span><span><strong>${escapeHtml(identity.name)}</strong><small>${escapeHtml(shortDid(identity.did))}</small></span></div></td>
          <td><span class="role-pill">L${ROLE_LEVELS[identity.role]} · ${identity.role}</span></td><td>${escapeHtml(identity.context)}</td>
          <td><span class="status-pill">${identity.did.startsWith("did:key") ? "BLS attested" : "Local derived"}</span></td>
          <td><button class="more" data-action="identity-menu" data-id="${identity.id}">•••</button></td></tr>`)
        .join("")}</tbody></table></div></section>`
      : emptyPanel("Your registry is empty", "Generate a context-specific DID. The same person can hold unlinkable identifiers for different scopes.", "new-identity", "Generate identity")
  }`;
}

function renderAdministration() {
  const subjectsWithTraits = state.identities.filter((identity) => identity.traits?.length);
  const exchangeSources = subjectsWithTraits;
  const ownedInformation = state.identities.reduce(
    (sum, identity) => sum + (identity.traits?.length || 0),
    0,
  );
  const defaultExpiry = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);
  const canExchange = exchangeSources.length > 0 && state.identities.length > 1;
  return `${pageHeading(
    "Controlled disclosure",
    "Identity information exchange",
    "Manage subject-owned information and exchange only consented disclosures with another subject.",
    state.identities.length
      ? ""
      : `<button class="button primary" data-action="new-identity">＋ Create subject</button>`,
  )}
  <div class="metrics">
    <div class="metric"><small>Owned information</small><strong>${state.identities.reduce((sum, identity) => sum + (identity.traits?.length || 0), 0)}</strong><span>Subject-bound records</span></div>
    <div class="metric"><small>Exchangeable records</small><strong>${ownedInformation}</strong><span>Committed when shared</span></div>
    <div class="metric"><small>Active exchanges</small><strong>${state.exchanges.filter((exchange) => exchangeValidity(exchange).valid).length}</strong><span>Consent receipts</span></div>
    <div class="metric"><small>Recipients</small><strong>${new Set(state.exchanges.map((exchange) => exchange.targetId)).size}</strong><span>Selective disclosures</span></div>
  </div>
  <div class="two-column">
    <section class="panel">
      <div class="panel-header"><div><h2>Subject-owned information registry</h2><p>Record who owns the information and who it describes</p></div></div>
      ${
        state.identities.length
          ? `<form id="trait-form" class="form-grid">
            <div class="field-pair"><div class="field"><label>Information owner</label><select name="ownerId" required>${state.identities.map((identity) => `<option value="${identity.id}">${escapeHtml(identity.name)}</option>`).join("")}</select></div><div class="field"><label>Information subject</label><select name="subjectId" required>${state.identities.map((identity) => `<option value="${identity.id}">${escapeHtml(identity.name)}</option>`).join("")}</select></div></div>
            <div class="field-pair"><div class="field"><label>Information type</label><input name="name" required maxlength="40" placeholder="e.g. Jurisdiction" /></div><div class="field"><label>Value</label><input name="value" required maxlength="80" placeholder="e.g. EU" /></div></div>
            <div class="field"><label>Protection</label><select name="classification"><option value="private">Private · AES-GCM encrypted</option><option value="verified">Verified · BLS signed</option><option value="public">Public · cleartext</option></select><small class="helper">Private values are encrypted before persistence. Verified values require the owner's signing key.</small></div>
            <button class="button secondary">Add owned information</button>
          </form>`
          : `<div class="empty"><div><div class="empty-mark">φ</div><h3>No subjects</h3><p>Create an identity before adding traits.</p><button class="button primary" data-action="new-identity">Create subject</button></div></div>`
      }
      ${
        subjectsWithTraits.length
          ? `<div class="trait-registry">${subjectsWithTraits
              .map(
                (identity) => `<div class="trait-subject"><div class="identity-main"><span class="identity-avatar">${initials(identity.name)}</span><span><strong>${escapeHtml(identity.name)}</strong><small>Owns ${identity.traits.length} information item${identity.traits.length === 1 ? "" : "s"}</small></span></div>
                <div class="trait-list">${identity.traits
                  .map(
                    (trait) => `<div class="trait-record"><span><strong>${escapeHtml(trait.name)}</strong><small>${escapeHtml(displayTraitValue(trait))} · about ${escapeHtml(identityById(trait.subjectId)?.name || "Unknown subject")} · ${escapeHtml(classificationLabel(trait))}</small></span><button class="more" data-action="delete-trait" data-id="${identity.id}" data-trait-id="${trait.id}" aria-label="Delete information">×</button></div>`,
                  )
                  .join("")}</div></div>`,
              )
              .join("")}</div>`
          : state.identities.length
            ? `<div class="notice" style="margin-top:14px">No owned information has been added yet. Selected records become tamper-evident when committed into a signed exchange receipt.</div>`
            : ""
      }
    </section>
    <section class="panel">
      <div class="panel-header"><div><h2>Exchange identity information</h2><p>Source consent + selective committed disclosure</p></div></div>
      ${
        canExchange
          ? `<form id="exchange-form" class="form-grid">
            <div class="field-pair">
              <div class="field"><label>Source subject</label><select id="exchange-source" name="sourceId" required>${exchangeSources.map((identity) => `<option value="${identity.id}">${escapeHtml(identity.name)}</option>`).join("")}</select></div>
              <div class="field"><label>Recipient subject</label><select id="exchange-target" name="targetId" required>${state.identities.map((identity) => `<option value="${identity.id}">${escapeHtml(identity.name)}</option>`).join("")}</select></div>
            </div>
            <div class="field"><label>Witness (optional)</label><select name="witnessId"><option value="">No witness</option>${state.identities.map((identity) => `<option value="${identity.id}">${escapeHtml(identity.name)} · ${identity.role}</option>`).join("")}</select><small class="helper">Must be distinct from the source and recipient.</small></div>
            <div class="field"><label>Owned information to disclose</label><div id="exchange-traits" class="check-list"></div><small class="helper">Selected records are copied into the receipt and protected by its phi commitment.</small></div>
            <div class="field"><label>Purpose</label><input name="purpose" required maxlength="100" placeholder="e.g. Confirm eligibility for working group" /></div>
            <div class="field"><label>Disclosure expiry</label><input name="expiresAt" type="date" min="${new Date(Date.now() + 86400000).toISOString().slice(0, 10)}" value="${defaultExpiry}" required /></div>
            <label class="consent"><input name="consent" type="checkbox" required /> The source subject explicitly consents to this limited disclosure.</label>
            <label class="consent"><input name="allowRedisclosure" type="checkbox" /> Grant the recipient permission to redisclose this information through the group amount chain.</label>
            <div class="field"><label>Maximum redisclosure depth</label><input name="maxDepth" type="number" min="1" max="6" value="1" /><small class="helper">Encoded as group amount 2^depth; ignored unless redisclosure is granted.</small></div>
            <button class="button primary">Exchange selected information</button>
          </form>`
          : `<div class="empty"><div><div class="empty-mark">⇄</div><h3>Exchange unavailable</h3><p>You need two identities and at least one owned information record.</p>${state.identities.length < 2 ? `<button class="button primary" data-action="new-identity">Create subject</button>` : ""}</div></div>`
      }
    </section>
  </div>
  <section class="panel" style="margin-top:16px">
    <div class="panel-header"><div><h2>Recipient-owned information</h2><p>Information holdings derived from accepted exchange receipts</p></div></div>
    ${
      state.exchanges.length
        ? `<div class="holdings-grid">${state.identities
            .map((holder) => ({
              holder,
              holdings: informationHoldingsFor(holder.id, state.exchanges),
            }))
            .filter(({ holdings }) => holdings.length)
            .map(
              ({ holder, holdings }) => `<article class="holding-owner">
                <div class="identity-main"><span class="identity-avatar">${initials(holder.name)}</span><span><strong>${escapeHtml(holder.name)}</strong><small>Owns ${holdings.length} received information item${holdings.length === 1 ? "" : "s"}</small></span></div>
                <div class="holding-list">${holdings
                  .map((holding) => {
                    const subject = identityById(holding.subjectId);
                    return `<div class="holding-card">
                      <div class="chain-card-header"><span class="role-pill">About ${escapeHtml(subject?.name || "Deleted subject")}</span><span class="status-pill ${holding.valid ? "" : "revoked"}">${holding.valid ? "owned · verified" : holding.validityReason}</span></div>
                      <strong>${escapeHtml(holding.trait.name)}: ${escapeHtml(displayTraitValue(holding.trait))}</strong>
                      <small>${escapeHtml(holding.purpose)} · expires ${new Date(holding.expiresAt).toLocaleDateString()} · group hop ${holding.depth}</small>
                      <div class="signature">Receipt ${escapeHtml(holding.exchangeId)} · source ${escapeHtml(shortDid(holding.sourceDid || ""))}</div>
                      ${
                        holding.valid &&
                        holding.allowRedisclosure &&
                        holding.depth < holding.maxDepth &&
                        state.exchanges.find((item) => item.id === holding.exchangeId)?.disclosures[0]
                          ?.id === holding.trait.id
                          ? `<button class="button secondary compact" data-action="forward-exchange" data-id="${holding.exchangeId}">Re-exchange owned information</button>`
                          : ""
                      }
                    </div>`;
                  })
                  .join("")}</div>
              </article>`,
            )
            .join("") || `<div class="empty"><p>No recipient holdings have been created yet.</p></div>`}</div>`
        : `<div class="empty"><div><div class="empty-mark">▣</div><h3>No owned information yet</h3><p>Information appears here when a recipient accepts and co-signs a selective disclosure.</p></div></div>`
    }
  </section>
  <section class="panel flush" style="margin-top:16px">
    <div style="padding:18px 19px 6px" class="panel-header"><div><h2>Disclosure ledger</h2><p>Revocable receipts for subject-to-subject exchanges</p></div></div>
    ${
      state.exchanges.length
        ? `<div class="table-wrap"><table><thead><tr><th>Exchange</th><th>Disclosed traits</th><th>Purpose</th><th>Validity</th><th>Receipt</th><th>Amount tokens</th><th></th></tr></thead><tbody>${state.exchanges
            .slice()
            .reverse()
            .map((exchange) => {
              const validity = exchangeValidity(exchange);
              return `<tr><td><strong>${escapeHtml(identityById(exchange.sourceId)?.name || "Deleted")}</strong> → <strong>${escapeHtml(identityById(exchange.targetId)?.name || "Deleted")}</strong>${exchange.witnessId ? `<br><span class="role-pill">Witness: ${escapeHtml(identityById(exchange.witnessId)?.name || "Deleted")}</span>` : ""}<br><small class="helper">${ago(exchange.createdAt)} · group hop ${exchange.depth || 0} · expires ${new Date(exchange.expiresAt).toLocaleDateString()}</small></td>
                <td><div class="trait-chips">${exchange.disclosures.map((trait) => `<span class="trait-chip">${escapeHtml(trait.name)}: ${escapeHtml(displayTraitValue(trait))}</span>`).join("")}</div></td>
                <td>${escapeHtml(exchange.purpose)}</td><td><span class="status-pill ${validity.valid ? "" : "revoked"}">${validity.valid ? "dual-signed" : validity.reason}</span></td>
                <td><div class="receipt-signers"><span class="${exchange.senderSignature ? "signed" : ""}">S ${exchange.senderSignature ? "✓" : "—"}</span>${exchange.witnessDid ? `<span class="${exchange.witnessSignature ? "signed" : ""}">W ${exchange.witnessSignature ? "✓" : "—"}</span>` : ""}<span class="${exchange.recipientSignature ? "signed" : ""}">R ${exchange.recipientSignature ? "✓" : "—"}</span></div><small class="mono" title="${escapeHtml(exchange.recipientSignature || exchange.witnessSignature || exchange.senderSignature || "")}">${escapeHtml(shortDid(exchange.recipientSignature || exchange.witnessSignature || exchange.senderSignature || "unsigned"))}</small></td>
                <td>${renderAmountTokenSummary(exchange.groupReceipt)}</td>
                <td><div class="form-actions" style="margin:0"><button class="button compact" data-action="inspect-receipt" data-id="${exchange.id}">Inspect</button>${
                  exchange.status === "pending_witness"
                    ? `<button class="button secondary compact" data-action="approve-witness" data-id="${exchange.id}">Witness & sign</button>`
                    : exchange.status === "pending_recipient"
                    ? `<button class="button primary compact" data-action="accept-exchange" data-id="${exchange.id}">Accept & co-sign</button>`
                    : exchange.status === "accepted"
                      ? `<button class="button danger compact" data-action="revoke-exchange" data-id="${exchange.id}">Revoke</button>`
                      : `<button class="button compact" data-action="restore-exchange" data-id="${exchange.id}">Restore</button>`
                }</div></td></tr>`;
            })
            .join("")}</tbody></table></div>`
        : `<div class="empty"><div><div class="empty-mark">⇄</div><h3>No disclosures exchanged</h3><p>Completed exchanges will appear here with their consent and phi commitment receipts.</p></div></div>`
    }
  </section>`;
}

function render() {
  if (!navItems.some(([id]) => id === currentPage)) currentPage = "overview";
  document.querySelector("#primary-nav").innerHTML = navItems
    .map(([id, icon, label]) => {
      const count =
        id === "identities"
          ? state.identities.length
          : id === "administration"
            ? state.exchanges.length
            : "";
      return `<button class="nav-item ${id === currentPage ? "active" : ""}" data-nav="${id}"><span class="nav-icon">${icon}</span>${label}${count !== "" ? `<span class="nav-badge">${count}</span>` : ""}</button>`;
    })
    .join("");
  document.querySelector("#page-crumb").textContent =
    navItems.find(([id]) => id === currentPage)?.[2] || "Overview";
  const pages = {
    overview: renderOverview,
    identities: renderIdentities,
    administration: renderAdministration,
  };
  app.innerHTML = pages[currentPage]();
  if (currentPage === "administration") updateExchangeFields();
  document.body.classList.remove("nav-open");
}

function modal(title, copy, body) {
  modalRoot.innerHTML = `<div class="modal-backdrop" data-action="close-modal"><div class="modal" role="dialog" aria-modal="true" aria-label="${escapeHtml(title)}" data-modal>
    <div class="modal-header"><div><h2>${title}</h2><p>${copy}</p></div><button class="close-button" data-action="close-modal" aria-label="Close">×</button></div>
    <div class="modal-body">${body}</div></div></div>`;
  modalRoot.querySelector("input,select,button")?.focus();
}

function openIdentityModal() {
  modal(
    "Generate private identity",
    "Create an authentic identifier scoped to one relationship or purpose.",
    `<div class="privacy-callout"><strong>φ</strong><span>A fresh 128-bit salt is mixed with the context. Reusing a name across contexts does not create the same public identifier.</span></div>
    <form id="identity-form" class="form-grid">
      <div class="field"><label for="identity-name">Display name</label><input id="identity-name" name="name" maxlength="60" required autocomplete="off" placeholder="e.g. Ada Lovelace" /></div>
      <div class="field"><label for="identity-handle">Handle</label><input id="identity-handle" name="handle" maxlength="30" pattern="^@[A-Za-z0-9_-]{2,29}$" required placeholder="@ada" /><small class="helper">Starts with @; letters, numbers, hyphens, and underscores only.</small></div>
      <div class="field"><label for="identity-context">Privacy context</label><input id="identity-context" name="context" maxlength="70" required placeholder="e.g. Research treasury" /><small class="helper">Context separation makes identifiers unlinkable by default.</small></div>
      <div class="field"><label for="identity-role">Access role</label><select id="identity-role" name="role">${Object.keys(ROLE_LEVELS).reverse().map((role) => `<option>${role}</option>`).join("")}</select></div>
      <div class="form-actions"><button type="button" class="button" data-action="close-modal">Cancel</button><button class="button primary">Generate DID</button></div>
    </form>`,
  );
}

function updateExchangeFields() {
  const sourceSelect = document.querySelector("#exchange-source");
  const targetSelect = document.querySelector("#exchange-target");
  const traitsContainer = document.querySelector("#exchange-traits");
  if (!sourceSelect || !traitsContainer) return;
  if (targetSelect?.value === sourceSelect.value) {
    const other = [...targetSelect.options].find((option) => option.value !== sourceSelect.value);
    if (other) targetSelect.value = other.value;
  }
  const source = identityById(sourceSelect.value);
  const defaultSubjectId = source?.traits[0]?.subjectId;
  traitsContainer.innerHTML = source?.traits?.length
    ? source.traits
        .map(
          (trait) =>
            `<label><input type="checkbox" name="traitIds" value="${trait.id}" ${trait.subjectId === defaultSubjectId ? "checked" : ""} /><span><strong>${escapeHtml(trait.name)}</strong><small>${escapeHtml(displayTraitValue(trait))} · about ${escapeHtml(identityById(trait.subjectId)?.name || "Unknown subject")} · ${escapeHtml(classificationLabel(trait))}</small></span></label>`,
        )
        .join("")
    : `<span class="helper">This source has no owned information to disclose.</span>`;
}

function openIdentityDetails(id) {
  const identity = identityById(id);
  if (!identity) return;
  const holdings = informationHoldingsFor(id, state.exchanges);
  modal(
    identity.name,
    `${identity.handle} · ${identity.authenticity}`,
    `<div class="form-grid"><div><span class="role-pill">Level ${ROLE_LEVELS[identity.role]} · ${identity.role}</span><span class="status-pill" style="margin-left:6px">${identity.status}</span></div>
    <div class="field"><label>Decentralized identifier</label><div class="contract">${escapeHtml(identity.did)}</div></div>
    <div class="field"><label>Authenticity fingerprint</label><div class="contract">${escapeHtml(identity.fingerprint)}</div></div>
    <div class="field"><label>Phi access contract</label><div class="contract">${escapeHtml(roleContract(identity))}</div></div>
    <div class="field"><label>Information this identity owns</label>${
      identity.traits.length
        ? `<div class="holding-list">${identity.traits.map((trait) => `<div class="trait-record"><span><strong>About ${escapeHtml(identityById(trait.subjectId)?.name || "Unknown subject")}: ${escapeHtml(trait.name)} = ${escapeHtml(displayTraitValue(trait))}</strong><small>${escapeHtml(classificationLabel(trait))} · source registry</small></span><span class="status-pill">owned</span></div>`).join("")}</div>`
        : `<div class="notice">This identity has no source information in its ownership registry.</div>`
    }</div>
    <div class="field"><label>Owned information received from other subjects</label>${
      holdings.length
        ? `<div class="holding-list">${holdings
            .map((holding) => {
              const subject = identityById(holding.subjectId);
              return `<div class="trait-record"><span><strong>About ${escapeHtml(subject?.name || "Deleted subject")}: ${escapeHtml(holding.trait.name)} = ${escapeHtml(displayTraitValue(holding.trait))}</strong><small>${escapeHtml(classificationLabel(holding.trait))} · ${escapeHtml(holding.purpose)} · ${holding.valid ? "dual-signed holding" : holding.validityReason}</small></span><span class="status-pill ${holding.valid ? "" : "revoked"}">${holding.valid ? "owned" : "inactive"}</span></div>`;
            })
            .join("")}</div>`
        : `<div class="notice">This identity does not currently hold information received from another subject.</div>`
    }</div>
    <div class="form-actions"><button class="button" data-action="copy-value" data-value="${escapeHtml(identity.did)}">Copy DID</button><button class="button danger" data-action="delete-identity" data-id="${identity.id}">Delete identity</button></div></div>`,
  );
}

function openForwardExchange(parentId) {
  const parent = state.exchanges.find((exchange) => exchange.id === parentId);
  if (!parent) return;
  const holder = identityById(parent.targetId);
  const subject = identityById(parent.claimSubjectId || parent.sourceId);
  const recipients = state.identities.filter((identity) => identity.id !== holder?.id);
  const latestExpiry = new Date(parent.expiresAt).toISOString().slice(0, 10);
  const suggestedExpiry = new Date(
    Math.min(new Date(parent.expiresAt).getTime(), Date.now() + 14 * 86400000),
  )
    .toISOString()
    .slice(0, 10);
  modal(
    "Re-exchange owned information",
    `Continue group ${parent.groupId} from ${holder?.name || "holder"} to a new recipient.`,
    `<div class="privacy-callout"><strong>φ</strong><span>The claim remains about ${escapeHtml(subject?.name || "the original subject")}. The current holder becomes the group subject for this custody hop.</span></div>
    <div class="trait-chips">${parent.disclosures.map((trait) => `<span class="trait-chip">${escapeHtml(trait.name)}: ${escapeHtml(displayTraitValue(trait))}</span>`).join("")}</div>
    <form id="forward-exchange-form" class="form-grid" style="margin-top:14px">
      <input type="hidden" name="parentId" value="${parent.id}" />
      <div class="field"><label>Current holder</label><div class="contract">${escapeHtml(holder?.name || "")} · hop ${parent.depth || 0} of ${parent.maxDepth}</div></div>
      <div class="field"><label>New recipient</label><select name="targetId" required>${recipients.map((identity) => `<option value="${identity.id}">${escapeHtml(identity.name)}</option>`).join("")}</select></div>
      <div class="field"><label>Witness (optional)</label><select name="witnessId"><option value="">No witness</option>${state.identities.map((identity) => `<option value="${identity.id}">${escapeHtml(identity.name)} · ${identity.role}</option>`).join("")}</select><small class="helper">Signs a separate witness amount token for this hop.</small></div>
      <div class="field"><label>Redisclosure purpose</label><input name="purpose" required maxlength="100" placeholder="e.g. Verify downstream eligibility" /></div>
      <div class="field"><label>Expiry</label><input name="expiresAt" type="date" min="${new Date(Date.now() + 86400000).toISOString().slice(0, 10)}" max="${latestExpiry}" value="${suggestedExpiry}" required /></div>
      <label class="consent"><input name="consent" type="checkbox" required /> The current holder consents to this authorized redisclosure.</label>
      <div class="form-actions"><button type="button" class="button" data-action="close-modal">Cancel</button><button class="button primary">Sender sign & continue group</button></div>
    </form>`,
  );
}

function partyVerificationBadge(result) {
  if (!result) return `<span class="status-pill revoked">not verified</span>`;
  const valid = Object.values(result).every(Boolean);
  return `<span class="status-pill ${valid ? "" : "revoked"}">${valid ? "verified" : "failed"}</span>`;
}

function partyChecks(result) {
  if (!result) return "Select Verify parties to check cryptographic proofs.";
  return Object.entries(result)
    .map(([name, valid]) => `${name.replaceAll("_", " ")} ${valid ? "✓" : "✕"}`)
    .join(" · ");
}

function openReceiptInspector(id, revealedKeys = null, results = null) {
  const exchange = state.exchanges.find((item) => item.id === id);
  if (!exchange) return;
  results ||= receiptVerificationResults.get(id) || null;
  const revealed = new Set(revealedKeys || receiptRevealedParties.get(id) || []);
  const receipt = exchange.groupReceipt || {};
  const rows = [
    {
      key: "sender",
      role: exchange.depth ? "Current holder / group subject" : "Original subject / sender",
      identity: identityById(exchange.sourceId),
      did: exchange.sourceDid,
    },
    ...(exchange.witnessDid
      ? [
          {
            key: "witness",
            role: "Witness",
            identity: identityById(exchange.witnessId),
            did: exchange.witnessDid,
          },
        ]
      : []),
    {
      key: "recipient",
      role: "Recipient / group participant",
      identity: identityById(exchange.targetId),
      did: exchange.targetDid,
    },
    {
      key: "authority",
      role: "Group authority",
      identity: null,
      did: receipt.authorityDid,
    },
  ];
  if (exchange.depth && exchange.claimSubjectDid !== exchange.sourceDid) {
    rows.unshift({
      key: "provenance",
      role: "Original claim subject",
      identity: identityById(exchange.claimSubjectId),
      did: exchange.claimSubjectDid,
    });
  }
  modal(
    `Receipt ${exchange.id}`,
    `Group ${exchange.groupId} · hop ${exchange.depth || 0} · amount ${exchange.groupAmount}`,
    `<div>
      <div class="privacy-callout"><strong>◉</strong><span>Select only the parties you need to reveal. Signature verification remains available while every identity is masked.</span></div>
      <div class="party-list">${rows
        .map((party) => {
          const result = results?.[party.key];
          const isRevealed = revealed.has(party.key);
          return `<div class="party-row"><input class="party-selector" type="checkbox" name="partyReveal" value="${party.key}" ${isRevealed ? "checked" : ""} aria-label="Select ${escapeHtml(party.role)} for reveal" /><span class="identity-avatar">${party.key === "authority" ? "φ" : isRevealed ? initials(party.identity?.name || "?") : "••"}</span><div><strong>${escapeHtml(party.role)}</strong><small>${isRevealed ? escapeHtml(party.identity?.name || (party.key === "authority" ? "Phi authority" : "Unknown identity")) : "Identity hidden"}</small><code>${isRevealed ? escapeHtml(party.did || "Unavailable") : "did:key:••••••••••••"}</code>${!isRevealed && party.key !== "provenance" ? `<div class="candidate-check"><input data-candidate-party="${party.key}" placeholder="Paste candidate DID" aria-label="Candidate DID for ${escapeHtml(party.role)}" /><button class="button compact" data-action="verify-party-candidate" data-id="${exchange.id}" data-party="${party.key}">Verify candidate</button></div>` : ""}<small>${escapeHtml(partyChecks(result))}</small></div>${partyVerificationBadge(result)}</div>`;
        })
        .join("")}</div>
      <div class="field"><label>Disclosure commitment</label><div class="contract">${escapeHtml(exchange.disclosureCommitment)}</div></div>
      ${renderAmountTokenDetails(receipt)}
      ${receipt.blockHash ? `<div class="field"><label>On-chain block</label><div class="contract">#${receipt.blockIndex} · ${escapeHtml(receipt.blockHash)}</div></div>` : ""}
      <div class="form-actions"><button class="button" data-action="hide-receipt-parties" data-id="${exchange.id}">Hide all</button><button class="button secondary" data-action="apply-party-reveal" data-id="${exchange.id}">Reveal & verify selected</button><button class="button primary" data-action="verify-receipt-parties" data-id="${exchange.id}">Verify revealed</button></div>
    </div>`,
  );
}

async function verifyReceiptParties(exchange) {
  const receipt = exchange.groupReceipt || {};
  const verify = (did, payload, signature) =>
    did && payload && signature
      ? verifyExchangeSignature(did, payload, signature).catch(() => false)
      : Promise.resolve(false);
  const aggregateValid = await verifyGroupReceiptAggregate(
    receipt,
    exchange.disclosureCommitment,
  ).catch(() => false);
  const results = {
    sender: {
      approval: await verify(exchange.sourceDid, exchange.payload, exchange.senderSignature),
      amount_role: await verify(
        exchange.sourceDid,
        receipt.subjectAmountToken,
        receipt.subjectRoleSignature,
      ),
      aggregate_receipt: aggregateValid,
    },
    recipient: {
      acceptance: await verify(
        exchange.targetDid,
        recipientAcceptancePayload(exchange),
        exchange.recipientSignature,
      ),
      amount_role: await verify(
        exchange.targetDid,
        receipt.participantAmountToken,
        receipt.participantRoleSignature,
      ),
      aggregate_receipt: aggregateValid,
    },
    authority: {
      aggregate_approval: await verify(
        receipt.authorityDid,
        receipt.authorityChallenge,
        receipt.authoritySignature,
      ),
      aggregate_receipt: aggregateValid,
    },
  };
  if (exchange.witnessDid) {
    results.witness = {
      approval: await verify(
        exchange.witnessDid,
        witnessApprovalPayload(exchange),
        exchange.witnessSignature,
      ),
      amount_role: await verify(
        exchange.witnessDid,
        receipt.witnessAmountToken,
        receipt.witnessRoleSignature,
      ),
      aggregate_receipt: aggregateValid,
    };
  }
  if (exchange.depth && exchange.claimSubjectDid !== exchange.sourceDid) {
    const parent = state.exchanges.find((item) => item.id === exchange.parentExchangeId);
    results.provenance = {
      parent_receipt: Boolean(parent && exchangeValidity(parent).valid),
    };
  }
  return results;
}

async function verifyCandidateParty(exchange, party, candidateDid) {
  const receipt = exchange.groupReceipt || {};
  const aggregateReceipt = await verifyGroupReceiptAggregate(
    receipt,
    exchange.disclosureCommitment,
  ).catch(() => false);
  if (party === "sender") {
    return {
      approval: await verifyExchangeSignature(
        candidateDid,
        exchange.payload,
        exchange.senderSignature,
      ).catch(() => false),
      amount_role: await verifyExchangeSignature(
        candidateDid,
        receipt.subjectAmountToken,
        receipt.subjectRoleSignature,
      ).catch(() => false),
      aggregate_receipt: aggregateReceipt,
    };
  }
  if (party === "witness") {
    return {
      approval: await verifyExchangeSignature(
        candidateDid,
        witnessApprovalPayload(exchange),
        exchange.witnessSignature,
      ).catch(() => false),
      amount_role: await verifyExchangeSignature(
        candidateDid,
        receipt.witnessAmountToken,
        receipt.witnessRoleSignature,
      ).catch(() => false),
      aggregate_receipt: aggregateReceipt,
    };
  }
  if (party === "recipient") {
    return {
      acceptance: await verifyExchangeSignature(
        candidateDid,
        recipientAcceptancePayload(exchange),
        exchange.recipientSignature,
      ).catch(() => false),
      amount_role: await verifyExchangeSignature(
        candidateDid,
        receipt.participantAmountToken,
        receipt.participantRoleSignature,
      ).catch(() => false),
      aggregate_receipt: aggregateReceipt,
    };
  }
  if (party === "authority") {
    return {
      aggregate_approval: await verifyExchangeSignature(
        candidateDid,
        receipt.authorityChallenge,
        receipt.authoritySignature,
      ).catch(() => false),
      aggregate_receipt: aggregateReceipt,
    };
  }
  return { candidate_supported: false };
}

function openSettings() {
  modal(
    "Workspace settings",
    "All records are persisted only in this browser profile.",
    `<div class="form-grid"><div class="notice">Clearing removes identities, exchanges, and receipts from this browser. You can load the example workspace again at any time.</div>
    <button class="button" data-action="export-workspace">Export workspace JSON</button><button class="button secondary" data-action="load-demo">Load example workspace</button><button class="button danger" data-action="clear-workspace">Clear workspace</button></div>`,
  );
}

function closeModal() {
  modalRoot.innerHTML = "";
  receiptRevealedParties.clear();
}

function toast(message, undo) {
  const element = document.createElement("div");
  element.className = "toast";
  element.innerHTML = `<span>${escapeHtml(message)}</span>${undo ? `<button data-action="undo">Undo</button>` : ""}`;
  toastRoot.append(element);
  setTimeout(() => element.remove(), undo ? 6500 : 3500);
}

function deleteWithUndo(message, mutate, restore) {
  mutate();
  save();
  render();
  closeModal();
  pendingUndo = restore;
  toast(message, true);
  setTimeout(() => {
    pendingUndo = null;
  }, 6500);
}

async function generateIdentity(form) {
  const data = new FormData(form);
  const name = data.get("name").trim();
  const handle = data.get("handle").trim();
  const context = data.get("context").trim();
  if (state.identities.some((identity) => identity.handle.toLowerCase() === handle.toLowerCase())) {
    form.elements.handle.setCustomValidity("That handle is already used in this workspace.");
    form.reportValidity();
    return;
  }
  const entropy = Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  let derived;
  try {
    const response = await fetch("/api/did/generate", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ name, context, entropy }),
    });
    if (!response.ok) throw new Error("BLS runtime unavailable");
    derived = await response.json();
  } catch {
    derived = await derivePrivateDid({ name, context, entropy });
  }
  state.identities.push({
    id: uid("id"),
    name,
    handle,
    context,
    role: data.get("role"),
    did: derived.did,
    fingerprint: derived.fingerprint,
    authenticity:
      derived.mode === "bls12-381"
        ? "BLS12-381 authority attested"
        : "Browser-derived privacy identifier",
    authorityProof: derived.authority_proof || null,
    traits: [],
    status: "active",
    createdAt: new Date().toISOString(),
  });
  save();
  closeModal();
  render();
  toast(derived.mode === "bls12-381" ? "BLS identity generated and attested." : "Private local identity generated.");
}

async function signExchangePayload(did, payload) {
  const response = await fetch("/api/exchange/sign", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ did, payload }),
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error || "BLS signing failed.");
  return result.signature;
}

async function verifyExchangeSignature(did, payload, signature) {
  const response = await fetch("/api/exchange/verify", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ did, payload, signature }),
  });
  if (!response.ok) return false;
  const result = await response.json();
  return result.valid === true;
}

async function verifyDualSignedExchange(exchange) {
  if (!exchange.senderSignature || !exchange.recipientSignature) return false;
  const checks = [
    verifyExchangeSignature(exchange.sourceDid, exchange.payload, exchange.senderSignature),
    verifyExchangeSignature(
      exchange.targetDid,
      recipientAcceptancePayload(exchange),
      exchange.recipientSignature,
    ),
  ];
  if (exchange.witnessDid) {
    if (!exchange.witnessSignature) return false;
    checks.push(
      verifyExchangeSignature(
        exchange.witnessDid,
        witnessApprovalPayload(exchange),
        exchange.witnessSignature,
      ),
    );
  }
  const results = await Promise.all(checks);
  return results.every(Boolean);
}

async function commitGroupAmountExchange(exchange) {
  const response = await fetch("/api/group-exchange/commit", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      exchange_id: exchange.id,
      group_id: exchange.groupId,
      amount: String(exchange.groupAmount),
      disclosure_commitment: exchange.disclosureCommitment,
      subject_did: exchange.sourceDid,
      participant_did: exchange.targetDid,
      ...(exchange.witnessDid ? { witness_did: exchange.witnessDid } : {}),
      ...(exchange.witnessDid
        ? {
            witness_approval_payload: witnessApprovalPayload(exchange),
            witness_approval_signature: exchange.witnessSignature,
          }
        : {}),
    }),
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error || "Group amount commitment failed.");
  return result;
}

async function verifyGroupReceiptAggregate(receipt, disclosureCommitment) {
  if (!receipt?.degreeThreePhiToken) return false;
  const response = await fetch("/api/group-exchange/verify-receipt", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      degree_three_phi_token: receipt.degreeThreePhiToken,
      disclosure_commitment: disclosureCommitment,
      group_id: receipt.groupId || "",
      hop: String(receipt.hop ?? ""),
      max_depth: String(receipt.maxDepth ?? ""),
      subject_signature: receipt.subjectRoleSignature || "",
      witness_signature: receipt.witnessRoleSignature || "",
      participant_signature: receipt.participantRoleSignature || "",
      authority_did: receipt.authorityDid || "",
      authority_challenge: receipt.authorityChallenge || "",
      authority_signature: receipt.authoritySignature || "",
    }),
  });
  if (!response.ok) return false;
  const result = await response.json();
  return result.valid === true;
}

document.addEventListener("click", async (event) => {
  const target = event.target.closest("[data-action],[data-nav]");
  if (!target) return;
  if (target.dataset.nav) {
    currentPage = target.dataset.nav;
    location.hash = currentPage;
    render();
    return;
  }
  const action = target.dataset.action;
  if (action === "close-modal" && (target.dataset.modal !== undefined || !event.target.closest("[data-modal]") || target.classList.contains("close-button") || target.textContent === "Cancel")) closeModal();
  if (action === "toggle-nav") document.body.classList.toggle("nav-open");
  if (action === "new-identity") openIdentityModal();
  if (action === "forward-exchange") openForwardExchange(target.dataset.id);
  if (action === "inspect-receipt") openReceiptInspector(target.dataset.id);
  if (action === "apply-party-reveal") {
    const selected = new Set(
      [...modalRoot.querySelectorAll('input[name="partyReveal"]:checked')].map(
        (input) => input.value,
      ),
    );
    receiptRevealedParties.set(target.dataset.id, selected);
    const exchange = state.exchanges.find((item) => item.id === target.dataset.id);
    if (exchange) {
      target.disabled = true;
      target.textContent = "Revealing & verifying…";
      const allResults = await verifyReceiptParties(exchange);
      const results = {
        ...(receiptVerificationResults.get(exchange.id) || {}),
        ...Object.fromEntries(
          [...selected]
            .filter((key) => allResults[key])
            .map((key) => [key, allResults[key]]),
        ),
      };
      receiptVerificationResults.set(exchange.id, results);
      openReceiptInspector(exchange.id, selected, results);
    }
  }
  if (action === "hide-receipt-parties") {
    receiptRevealedParties.set(target.dataset.id, new Set());
    openReceiptInspector(target.dataset.id, new Set());
  }
  if (action === "verify-receipt-parties") {
    const exchange = state.exchanges.find((item) => item.id === target.dataset.id);
    if (exchange) {
      const revealed = receiptRevealedParties.get(exchange.id) || new Set();
      if (!revealed.size) {
        toast("Reveal at least one party or provide a candidate DID.");
        return;
      }
      target.disabled = true;
      target.textContent = "Verifying revealed…";
      const allResults = await verifyReceiptParties(exchange);
      const results = {
        ...(receiptVerificationResults.get(exchange.id) || {}),
        ...Object.fromEntries(
          [...revealed]
            .filter((key) => allResults[key])
            .map((key) => [key, allResults[key]]),
        ),
      };
      receiptVerificationResults.set(exchange.id, results);
      openReceiptInspector(exchange.id, revealed, results);
    }
  }
  if (action === "verify-party-candidate") {
    const exchange = state.exchanges.find((item) => item.id === target.dataset.id);
    const input = modalRoot.querySelector(
      `[data-candidate-party="${target.dataset.party}"]`,
    );
    const candidateDid = input?.value.trim();
    if (!candidateDid) {
      toast("Paste a candidate DID first.");
      return;
    }
    if (exchange) {
      target.disabled = true;
      target.textContent = "Checking…";
      const result = await verifyCandidateParty(
        exchange,
        target.dataset.party,
        candidateDid,
      );
      const results = {
        ...(receiptVerificationResults.get(exchange.id) || {}),
        [target.dataset.party]: result,
      };
      receiptVerificationResults.set(exchange.id, results);
      openReceiptInspector(
        exchange.id,
        receiptRevealedParties.get(exchange.id) || new Set(),
        results,
      );
    }
  }
  if (action === "view-identity" || action === "identity-menu") openIdentityDetails(target.dataset.id);
  if (action === "open-settings") openSettings();
  if (action === "copy-value") {
    await navigator.clipboard.writeText(target.dataset.value);
    toast("Copied to clipboard.");
  }
  if (action === "copy-workspace") {
    await navigator.clipboard.writeText(`${state.identities.length} identities · ${state.exchanges.length} exchanges`);
    toast("Workspace summary copied.");
  }
  if (action === "delete-identity") {
    const id = target.dataset.id;
    const snapshot = structuredClone(state);
    deleteWithUndo("Identity and related records deleted.", () => {
      state.identities = state.identities.filter((item) => item.id !== id);
      state.identities.forEach((identity) => {
        identity.traits = identity.traits.filter((trait) => trait.subjectId !== id);
      });
      state.exchanges = state.exchanges.filter(
        (item) =>
          item.sourceId !== id &&
          item.targetId !== id &&
          item.claimSubjectId !== id &&
          item.witnessId !== id,
      );
    }, () => {
      state = snapshot;
    });
  }
  if (action === "delete-trait") {
    const identity = identityById(target.dataset.id);
    const index = identity?.traits.findIndex((trait) => trait.id === target.dataset.traitId) ?? -1;
    if (identity && index >= 0) {
      const [removed] = identity.traits.splice(index, 1);
      deleteWithUndo(
        "Source record deleted. Existing signed receipt snapshots are unchanged.",
        () => {},
        () => identity.traits.splice(index, 0, removed),
      );
    }
  }
  if (action === "revoke-exchange") {
    const exchange = state.exchanges.find((item) => item.id === target.dataset.id);
    if (exchange) {
      const previous = { status: exchange.status, revokedAt: exchange.revokedAt };
      deleteWithUndo(
        "Information exchange revoked.",
        () => {
          exchange.status = "revoked";
          exchange.revokedAt = new Date().toISOString();
        },
        () => Object.assign(exchange, previous),
      );
    }
  }
  if (action === "approve-witness") {
    const exchange = state.exchanges.find((item) => item.id === target.dataset.id);
    if (exchange?.witnessDid) {
      target.disabled = true;
      target.textContent = "Witness signing…";
      try {
        exchange.witnessSignature = await signExchangePayload(
          exchange.witnessDid,
          witnessApprovalPayload(exchange),
        );
        exchange.witnessVerified = await verifyExchangeSignature(
          exchange.witnessDid,
          witnessApprovalPayload(exchange),
          exchange.witnessSignature,
        );
        if (!exchange.witnessVerified) {
          exchange.witnessSignature = null;
          throw new Error("The witness approval signature could not be verified.");
        }
        exchange.status = "pending_recipient";
        exchange.witnessedAt = new Date().toISOString();
        save();
        render();
        toast("Witness explicitly approved and signed.");
      } catch (error) {
        render();
        toast(error.message);
      }
    }
  }
  if (action === "accept-exchange") {
    const exchange = state.exchanges.find((item) => item.id === target.dataset.id);
    if (exchange) {
      target.disabled = true;
      target.textContent = "Signing…";
      try {
        exchange.recipientSignature = await signExchangePayload(
          exchange.targetDid,
          recipientAcceptancePayload(exchange),
        );
        exchange.signaturesVerified = await verifyDualSignedExchange(exchange);
        if (!exchange.signaturesVerified) {
          exchange.recipientSignature = null;
          throw new Error("The dual signatures could not be verified.");
        }
        exchange.groupReceipt = await commitGroupAmountExchange(exchange);
        exchange.status = "accepted";
        exchange.acceptedAt = new Date().toISOString();
        save();
        render();
        toast("Recipient accepted; both BLS signatures verified.");
      } catch (error) {
        render();
        toast(error.message);
      }
    }
  }
  if (action === "restore-exchange") {
    const exchange = state.exchanges.find((item) => item.id === target.dataset.id);
    if (exchange) {
      exchange.status =
        exchange.senderSignature && exchange.recipientSignature
          ? "accepted"
          : exchange.witnessDid && !exchange.witnessSignature
            ? "pending_witness"
            : "pending_recipient";
      exchange.revokedAt = null;
      save();
      render();
      toast("Information exchange restored.");
    }
  }
  if (action === "undo" && pendingUndo) {
    pendingUndo();
    pendingUndo = null;
    save();
    render();
    target.closest(".toast")?.remove();
    toast("Change restored.");
  }
  if (action === "clear-workspace") {
    state = emptyState();
    save();
    closeModal();
    render();
    toast("Workspace cleared.");
  }
  if (action === "load-demo") {
    state = demoState();
    save();
    closeModal();
    render();
    toast("Example workspace loaded.");
  }
  if (action === "export-workspace") {
    const blob = new Blob([JSON.stringify(state, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = Object.assign(document.createElement("a"), { href: url, download: "phi-identity-workspace.json" });
    link.click();
    URL.revokeObjectURL(url);
  }
});

document.addEventListener("input", (event) => {
  if (event.target.name === "handle") event.target.setCustomValidity("");
  if (event.target.id === "exchange-source") {
    updateExchangeFields();
  }
});

document.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  if (form.id === "identity-form") await generateIdentity(form);
  if (form.id === "trait-form") {
    const data = new FormData(form);
    const identity = identityById(data.get("ownerId"));
    const subject = identityById(data.get("subjectId"));
    const name = data.get("name").trim();
    if (
      identity.traits.some(
        (trait) =>
          trait.name.toLocaleLowerCase() === name.toLocaleLowerCase() &&
          trait.subjectId === subject.id,
      )
    ) {
      return toast("This owner already holds that information type about the subject.");
    }
    const trait = {
      id: uid("trait"),
      name,
      value: data.get("value").trim(),
      classification: data.get("classification"),
      subjectId: subject.id,
      subjectDid: subject.did,
    };
    try {
      await protectTrait(trait, identity.did, false);
      identity.traits.push(trait);
      save();
      render();
      toast(
        trait.classification === "private"
          ? "Private information encrypted and added."
          : trait.classification === "verified"
            ? "Verified information signed and added."
            : "Public information added in cleartext.",
      );
    } catch (error) {
      toast(error.message || "Information protection failed.");
    }
  }
  if (form.id === "exchange-form") {
    const data = new FormData(form);
    const source = identityById(data.get("sourceId"));
    const target = identityById(data.get("targetId"));
    const witness = identityById(data.get("witnessId"));
    try {
      const exchange = createTraitExchange({
        sourceId: data.get("sourceId"),
        targetId: data.get("targetId"),
        sourceDid: source?.did,
        targetDid: target?.did,
        witnessId: witness?.id || null,
        witnessDid: witness?.did || null,
        sourceTraits: source?.traits || [],
        traitIds: data.getAll("traitIds"),
        purpose: data.get("purpose"),
        expiresAt: new Date(`${data.get("expiresAt")}T23:59:59`).toISOString(),
        consent: data.get("consent") === "on",
        allowRedisclosure: data.get("allowRedisclosure") === "on",
        maxDepth: data.get("maxDepth"),
      });
      exchange.senderSignature = await signExchangePayload(source.did, exchange.payload);
      const senderVerified = await verifyExchangeSignature(
        source.did,
        exchange.payload,
        exchange.senderSignature,
      );
      if (!senderVerified) throw new Error("The sender BLS signature could not be verified.");
      state.exchanges.push(exchange);
      save();
      render();
      toast(
        exchange.witnessDid
          ? "Sender signed. Awaiting explicit witness approval."
          : "Sender signed. Awaiting recipient acceptance.",
      );
    } catch (error) {
      toast(error.message);
    }
  }
  if (form.id === "forward-exchange-form") {
    const data = new FormData(form);
    const parent = state.exchanges.find((item) => item.id === data.get("parentId"));
    const source = identityById(parent?.targetId);
    const target = identityById(data.get("targetId"));
    const witness = identityById(data.get("witnessId"));
    try {
      const exchange = createForwardExchange({
        parentExchange: parent,
        sourceId: source?.id,
        targetId: target?.id,
        sourceDid: source?.did,
        targetDid: target?.did,
        witnessId: witness?.id || null,
        witnessDid: witness?.did || null,
        purpose: data.get("purpose"),
        expiresAt: new Date(`${data.get("expiresAt")}T23:59:59`).toISOString(),
        consent: data.get("consent") === "on",
      });
      exchange.senderSignature = await signExchangePayload(source.did, exchange.payload);
      const senderVerified = await verifyExchangeSignature(
        source.did,
        exchange.payload,
        exchange.senderSignature,
      );
      if (!senderVerified) throw new Error("The holder BLS signature could not be verified.");
      state.exchanges.push(exchange);
      save();
      closeModal();
      render();
      toast(
        exchange.witnessDid
          ? "Holder signed the next hop. Awaiting explicit witness approval."
          : "Holder signed the next group hop. Awaiting recipient acceptance.",
      );
    } catch (error) {
      toast(error.message);
    }
  }
});

window.addEventListener("hashchange", () => {
  currentPage = location.hash.slice(1) || "overview";
  render();
});

async function checkRuntime() {
  try {
    const response = await fetch("/api/chain-status");
    if (!response.ok) throw new Error();
    const runtime = await response.json();
    document.querySelector("#network-label").textContent = "Phi local chain";
    document.querySelector("#network-status").textContent = runtime.chain_valid ? "Chain verified" : "Validation warning";
    document.querySelector("#authority-short").textContent = shortDid(runtime.authority_did_key);
    let changed = false;
    for (const exchange of state.exchanges.filter(
      (item) => item.senderSignature && item.recipientSignature,
    )) {
      const verified = await verifyDualSignedExchange(exchange);
      if (exchange.signaturesVerified !== verified) {
        exchange.signaturesVerified = verified;
        changed = true;
      }
    }
    if (changed) {
      save();
      if (currentPage === "administration") render();
    }
  } catch {
    document.querySelector("#network-status").textContent = "Browser-only mode";
  }
}

try {
  await hydratePrivateInformation();
} catch (error) {
  console.error("Private information hydration failed.", error);
}
render();
checkRuntime();
