import {
  ROLE_LEVELS,
  amountTokenEntries,
  createForwardExchange,
  createTraitExchange,
  exchangeValidity,
  identityWalletUrl,
  informationHoldingsFor,
  maxDepthFromGroupAmount,
  recipientAcceptancePayload,
  walletSignatureRequests,
  witnessApprovalPayload,
} from "./core.mjs";

const STORAGE_KEY = "phi.identity.workspace.v1";
const app = document.querySelector("#wallet-app");
const toastRoot = document.querySelector("#wallet-toast");
const walletQuery = new URLSearchParams(location.search);
const identityId = walletQuery.get("identity");
const requestedView = walletQuery.get("view");
const activeView = ["exchange", "sign"].includes(requestedView)
  ? requestedView
  : "overview";
let state = loadWorkspace();

function loadWorkspace() {
  try {
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY));
    if (
      stored?.version === 1 &&
      Array.isArray(stored.identities) &&
      Array.isArray(stored.exchanges)
    ) {
      return stored;
    }
  } catch {
    // The wallet reports unavailable storage without changing it.
  }
  return { identities: [], exchanges: [] };
}

function escapeHtml(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function initials(name = "") {
  return name
    .split(/\s+/)
    .map((part) => part[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();
}

function identityById(id) {
  return state.identities.find((identity) => identity.id === id);
}

function traitValue(trait) {
  if (trait.classification === "private") return "Encrypted value";
  return trait.value ?? "";
}

function protectionLabel(trait) {
  if (trait.classification === "private") return "private · AES-GCM";
  if (trait.classification === "verified") return "verified · BLS";
  return "public · cleartext";
}

function tokensFor(identity) {
  return state.exchanges.flatMap((exchange) => {
    const allowed = new Set();
    if (exchange.sourceId === identity.id) allowed.add("subject");
    if (exchange.witnessId === identity.id) allowed.add("witness");
    if (exchange.targetId === identity.id) {
      allowed.add("participantBase");
      allowed.add("participant");
    }
    return amountTokenEntries(exchange.groupReceipt)
      .filter(({ key }) => allowed.has(key))
      .map((entry) => ({ ...entry, exchange }));
  });
}

function informationCard(trait, subjectName, detail, valid = true) {
  return `<article class="information-card">
    <div><span class="tag">About ${escapeHtml(subjectName)}</span><span class="state ${valid ? "" : "invalid"}">${valid ? "active" : "inactive"}</span></div>
    <h3>${escapeHtml(trait.name)}</h3>
    <strong>${escapeHtml(traitValue(trait))}</strong>
    <small>${escapeHtml(detail)}</small>
  </article>`;
}

function walletNavigation(identity, requestCount) {
  const base = `/wallet?identity=${encodeURIComponent(identity.id)}`;
  return `<nav class="wallet-tabs" aria-label="Wallet pages">
    <a class="${activeView === "overview" ? "active" : ""}" href="${base}">Overview</a>
    <a class="${activeView === "exchange" ? "active" : ""}" href="${base}&view=exchange">Exchange</a>
    <a class="${activeView === "sign" ? "active" : ""}" href="${base}&view=sign">Sign requests${requestCount ? `<span>${requestCount}</span>` : ""}</a>
  </nav>`;
}

function receivedGroupTipsFor(identity) {
  const tips = new Map();
  for (const exchange of state.exchanges) {
    if (exchange.status !== "accepted" || !exchange.groupReceipt) continue;
    const previous = tips.get(exchange.groupId);
    if (!previous || Number(exchange.depth) >= Number(previous.depth)) {
      tips.set(exchange.groupId, exchange);
    }
  }
  return [...tips.values()].filter((exchange) => exchange.targetId === identity.id);
}

function exchangePage(identity) {
  const recipients = state.identities.filter(({ id }) => id !== identity.id);
  const defaultExpiry = new Date(Date.now() + 30 * 86400000)
    .toISOString()
    .slice(0, 10);
  if (!recipients.length) {
    return `<section class="wallet-empty exchange-empty"><span>⇄</span><h3>Exchange unavailable</h3><p>Add another identity to the workspace before initiating an exchange.</p><a href="/#identities">Open identity console</a></section>`;
  }
  const recipientOptions = recipients
    .map(
      (candidate) =>
        `<option value="${escapeHtml(candidate.id)}">${escapeHtml(candidate.name)} · ${escapeHtml(candidate.role)}</option>`,
    )
    .join("");
  const witnessOptions = `<option value="">No witness</option>${recipientOptions}`;
  const receivedGroups = receivedGroupTipsFor(identity);
  const registeredTraits = identity.traits || [];
  const ownedInformationCount =
    registeredTraits.length +
    receivedGroups.reduce(
      (count, exchange) => count + exchange.disclosures.length,
      0,
    );
  const registeredInformation = registeredTraits.length
    ? `<article class="received-group registered-group"><header><div><span class="tag">Registered here</span><h4>Directly owned information</h4><p>${registeredTraits.length} information item${registeredTraits.length === 1 ? "" : "s"} · creates a new amount-token group</p></div></header>
      <form id="wallet-exchange-form" class="exchange-form">
        <div class="exchange-field-pair"><label><span>Recipient identity</span><select name="targetId" required>${recipientOptions}</select></label><label><span>Witness (optional)</span><select name="witnessId">${witnessOptions}</select></label></div>
        <fieldset><legend>Information to disclose</legend><div class="exchange-traits">${registeredTraits.map((trait, index) => `<label><input type="checkbox" name="traitIds" value="${escapeHtml(trait.id)}" ${index === 0 ? "checked" : ""} /><span><strong>${escapeHtml(trait.name)}: ${escapeHtml(traitValue(trait))}</strong><small>About ${escapeHtml(identityById(trait.subjectId)?.name || identity.name)} · ${escapeHtml(protectionLabel(trait))}</small></span></label>`).join("")}</div></fieldset>
        <label><span>Exchange purpose</span><input name="purpose" required maxlength="100" placeholder="Why does the recipient need this information?" /></label>
        <div class="exchange-field-pair"><label><span>Receipt expiry</span><input name="expiresAt" type="date" min="${new Date(Date.now() + 86400000).toISOString().slice(0, 10)}" value="${defaultExpiry}" required /></label><label><span>Maximum redisclosure depth</span><input name="maxDepth" type="number" min="1" max="6" value="1" /></label></div>
        <label class="sign-consent"><input name="allowRedisclosure" type="checkbox" /> <span>Allow the recipient to redisclose through the exponentiated group amount chain.</span></label>
        <label class="sign-consent"><input name="confirmRequest" type="checkbox" required /> <span>I reviewed these request details and want to continue to sender consent.</span></label>
        <footer><small>A new amount-token group is created after every required wallet signature is verified.</small><button>Continue to sign</button></footer>
      </form>
    </article>`
    : "";
  const receivedInformation = receivedGroups
    .map((parent) => {
      const validity = exchangeValidity(parent);
      const maxDepth = maxDepthFromGroupAmount(parent.groupAmount) ?? 0;
      const canForward =
        validity.valid &&
        parent.allowRedisclosure === true &&
        Number(parent.depth) < maxDepth;
      const blockedReason = !validity.valid
        ? validity.reason
        : !parent.allowRedisclosure
          ? "Original subject did not permit redisclosure"
          : `Maximum depth ${maxDepth} reached`;
      const latestExpiry = new Date(parent.expiresAt)
        .toISOString()
        .slice(0, 10);
      const suggestedExpiry = new Date(
        Math.min(
          new Date(parent.expiresAt).getTime(),
          Date.now() + 14 * 86400000,
        ),
      )
        .toISOString()
        .slice(0, 10);
      return `<article class="received-group ${canForward ? "" : "blocked"}"><header><div><span class="tag">Received · Group ${escapeHtml(parent.groupId)}</span><h4>About ${escapeHtml(identityById(parent.claimSubjectId || parent.sourceId)?.name || "original subject")}</h4><p>Hop ${parent.depth || 0} of ${maxDepth} · ${parent.disclosures.length} information item${parent.disclosures.length === 1 ? "" : "s"}</p></div></header><div class="exchange-traits">${parent.disclosures.map((trait) => `<label><span><strong>${escapeHtml(trait.name)}: ${escapeHtml(traitValue(trait))}</strong><small>${escapeHtml(protectionLabel(trait))}</small></span></label>`).join("")}</div>${
        canForward
          ? `<form class="exchange-form wallet-forward-form"><input type="hidden" name="parentId" value="${escapeHtml(parent.id)}" /><div class="exchange-field-pair"><label><span>New recipient</span><select name="targetId" required>${recipientOptions}</select></label><label><span>Witness (optional)</span><select name="witnessId">${witnessOptions}</select></label></div><label><span>Redisclosure purpose</span><input name="purpose" required maxlength="100" placeholder="Why should the next recipient receive this information?" /></label><label><span>Expiry</span><input name="expiresAt" type="date" min="${new Date(Date.now() + 86400000).toISOString().slice(0, 10)}" max="${latestExpiry}" value="${suggestedExpiry}" required /></label><label class="sign-consent"><input name="confirmRequest" type="checkbox" required /> <span>I reviewed this continuation of the existing amount-token group.</span></label><footer><small>The original commitment, amount, subject, and depth limit remain unchanged.</small><button>Continue group</button></footer></form>`
          : `<div class="group-blocked-reason">${escapeHtml(blockedReason)}</div>`
      }</article>`;
    })
    .join("");
  return `<section class="exchange-page">
    <div class="signing-heading"><div class="signing-copy"><p>Wallet initiated</p><h2>Exchange owned information</h2><span>Registered records and received amount-token groups are held in one exchange inventory.</span></div><div class="signer-chip"><span>${initials(identity.name)}</span><div><strong>${escapeHtml(identity.name)}</strong><small>${escapeHtml(identity.did)}</small></div></div></div>
    <section class="exchange-source"><header><div><h3>Owned information</h3><p>Select registered information or continue an authorized received group.</p></div><span>${ownedInformationCount}</span></header>
      <div class="received-group-list">${
        registeredInformation || receivedInformation
          ? `${registeredInformation}${receivedInformation}`
          : `<div class="wallet-empty">This wallet does not currently own information it can exchange.</div>`
      }</div>
    </section>
  </section>`;
}

function signingPage(identity, requests) {
  return `<section class="signing-page">
    <div class="signing-heading"><div class="signing-copy"><p>Explicit consent</p><h2>Exchange signature requests</h2><span>Review the parties, purpose, disclosed information, and commitment before using this identity's BLS key.</span></div><div class="signer-chip"><span>${initials(identity.name)}</span><div><strong>${escapeHtml(identity.name)}</strong><small>${escapeHtml(identity.did)}</small></div></div></div>
    ${
      requests.length
        ? `<div class="sign-request-list">${requests
            .map(({ exchange, role }) => {
              const source = identityById(exchange.sourceId);
              const recipient = identityById(exchange.targetId);
              const requestLabel =
                role === "sender"
                  ? "Sender authorization"
                  : role === "witness"
                    ? "Witness approval"
                    : "Recipient acceptance";
              return `<article class="sign-card" data-request="${escapeHtml(exchange.id)}"><header><div><span class="tag">${requestLabel}</span><h3>${escapeHtml(source?.name || "Unknown sender")} → ${escapeHtml(recipient?.name || "Unknown recipient")}</h3><p>${escapeHtml(exchange.purpose)}</p></div><span class="signature-status"><i></i><span><strong>Signature requested</strong><small>Awaiting your consent</small></span></span></header>
                <div class="sign-facts"><div><small>Expires</small><strong>${new Date(exchange.expiresAt).toLocaleDateString()}</strong></div><div><small>Group / hop</small><strong>${escapeHtml(exchange.groupId)} · ${exchange.depth || 0}</strong></div><div><small>Disclosure commitment</small><code title="${escapeHtml(exchange.disclosureCommitment)}">${escapeHtml(exchange.disclosureCommitment)}</code></div></div>
                <div class="sign-disclosures">${exchange.disclosures.map((trait) => `<div><span><small>About ${escapeHtml(identityById(trait.subjectId)?.name || source?.name || "Unknown subject")}</small><strong>${escapeHtml(trait.name)}: ${escapeHtml(traitValue(trait))}</strong></span><em>${escapeHtml(protectionLabel(trait))}</em></div>`).join("")}</div>
                <label class="sign-consent"><input type="checkbox" /> <span>I reviewed this exchange and explicitly consent for ${escapeHtml(identity.name)} to sign as ${role}.</span></label>
                <footer><small>The signature binds the exchange payload and cannot be moved to another exchange.</small><button data-sign-exchange="${escapeHtml(exchange.id)}" data-sign-role="${role}">Consent & sign</button></footer>
              </article>`;
            })
            .join("")}</div>`
        : `<div class="wallet-empty sign-empty"><span>✓</span><h3>No signatures requested</h3><p>This identity has no pending witness or recipient approvals.</p><a href="/#administration">View Exchange ledger</a></div>`
    }
  </section>`;
}

function render() {
  const identity = identityById(identityId);
  if (!identity) {
    document.title = "Wallet unavailable · Phi";
    app.innerHTML = `<section class="wallet-error"><span>φ</span><h1>Wallet unavailable</h1><p>This endpoint does not reference an identity in this browser workspace.</p><a href="/#identities">Return to identity console</a></section>`;
    return;
  }

  document.title = `${identity.name} · Phi Wallet`;
  const holdings = informationHoldingsFor(identity.id, state.exchanges);
  const validHoldings = holdings.filter(({ valid }) => valid);
  const tokens = tokensFor(identity);
  const relatedExchanges = state.exchanges.filter(
    (exchange) =>
      exchange.sourceId === identity.id ||
      exchange.targetId === identity.id ||
      exchange.witnessId === identity.id,
  );
  const signatureRequests = walletSignatureRequests(identity.id, state.exchanges);

  const hero = `<section class="wallet-hero">
    <div class="identity-heading"><span class="identity-mark">${initials(identity.name)}</span><div><span class="tag">Level ${ROLE_LEVELS[identity.role]} · ${escapeHtml(identity.role)}</span><h1>${escapeHtml(identity.name)}</h1><p>${escapeHtml(identity.handle)} · ${escapeHtml(identity.context)}</p></div></div>
    <div class="did-card"><small>Decentralized identifier</small><code title="${escapeHtml(identity.did)}">${escapeHtml(identity.did)}</code><button data-copy="${escapeHtml(identity.did)}">Copy DID</button></div>
  </section>`;
  const overview = `<section class="balance-grid">
    <article><small>Owned records</small><strong>${identity.traits?.length || 0}</strong><span>Registered at source</span></article>
    <article><small>Received holdings</small><strong>${validHoldings.length}</strong><span>Verified receipts</span></article>
    <article><small>Amount tokens</small><strong>${tokens.length}</strong><span>BLS group points</span></article>
    <article><small>Transactions</small><strong>${relatedExchanges.length}</strong><span>Identity exchanges</span></article>
  </section>
  <section class="wallet-columns">
    <div class="wallet-panel"><header><div><h2>Owned information</h2><p>Records held directly by this identity</p></div><span>${identity.traits?.length || 0}</span></header>
      <div class="information-list">${
        (identity.traits || []).length
          ? identity.traits
              .map((trait) =>
                informationCard(
                  trait,
                  identityById(trait.subjectId)?.name || "Unknown subject",
                  protectionLabel(trait),
                ),
              )
              .join("")
          : `<div class="wallet-empty">No directly owned information.</div>`
      }</div>
    </div>
    <div class="wallet-panel"><header><div><h2>Received information</h2><p>Custody acquired through signed receipts</p></div><span>${holdings.length}</span></header>
      <div class="information-list">${
        holdings.length
          ? holdings
              .map((holding) =>
                informationCard(
                  holding.trait,
                  identityById(holding.subjectId)?.name || "Deleted subject",
                  `${holding.purpose} · hop ${holding.depth} · ${holding.valid ? "receipt verified" : holding.validityReason}`,
                  holding.valid,
                ),
              )
              .join("")
          : `<div class="wallet-empty">No information received from another identity.</div>`
      }</div>
    </div>
  </section>
  <section class="token-vault wallet-panel"><header><div><h2>Amount-token vault</h2><p>Compact disclosure-bound and custody BLS points</p></div><span>${tokens.length}</span></header>
    ${
      tokens.length
        ? `<div class="token-grid">${tokens
            .map(({ label, kind, token, exchange }) => {
              const validity = exchangeValidity(exchange);
              return `<article class="token-card"><div class="token-heading"><span class="token-icon">${kind === "base" ? "B" : "φ"}</span><div><strong>${escapeHtml(label)}</strong><small>Hop ${exchange.depth || 0} · ${validity.valid ? "verified" : validity.reason}</small></div><span class="state ${validity.valid ? "" : "invalid"}">${validity.valid ? "active" : "inactive"}</span></div><code title="${escapeHtml(token)}">${escapeHtml(token)}</code><footer><span>Receipt ${escapeHtml(exchange.id)}</span><button data-copy="${escapeHtml(token)}">Copy token</button></footer></article>`;
            })
            .join("")}</div>`
        : `<div class="wallet-empty token-empty"><span>◇</span><h3>No amount tokens yet</h3><p>Tokens appear after this identity participates in an accepted exchange.</p><a href="/#administration">Open Exchange</a></div>`
    }
  </section>`;
  app.innerHTML = `${hero}${walletNavigation(identity, signatureRequests.length)}${
    activeView === "sign"
      ? signingPage(identity, signatureRequests)
      : activeView === "exchange"
        ? exchangePage(identity)
        : overview
  }`;
}

async function signPayload(did, payload) {
  const response = await fetch("/api/exchange/sign", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ did, payload }),
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || !result.signature) {
    throw new Error(result.error || "The wallet could not create the BLS signature.");
  }
  return result.signature;
}

async function verifySignature(did, payload, signature) {
  const response = await fetch("/api/exchange/verify", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ did, payload, signature }),
  });
  if (!response.ok) return false;
  const result = await response.json().catch(() => ({}));
  return result.valid === true;
}

async function verifyAllExchangeSignatures(exchange) {
  const checks = [
    verifySignature(exchange.sourceDid, exchange.payload, exchange.senderSignature),
    verifySignature(
      exchange.targetDid,
      recipientAcceptancePayload(exchange),
      exchange.recipientSignature,
    ),
  ];
  if (exchange.witnessDid) {
    checks.push(
      verifySignature(
        exchange.witnessDid,
        witnessApprovalPayload(exchange),
        exchange.witnessSignature,
      ),
    );
  }
  return (await Promise.all(checks)).every(Boolean);
}

async function commitGroupReceipt(exchange) {
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
  const receipt = await response.json().catch(() => null);
  if (!response.ok || !receipt?.degreeThreePhiToken) {
    throw new Error(receipt?.error || "The chain returned an invalid exchange receipt.");
  }
  return receipt;
}

async function consentAndSign(exchange, role) {
  if (role === "sender") {
    const signature = await signPayload(exchange.sourceDid, exchange.payload);
    if (!(await verifySignature(exchange.sourceDid, exchange.payload, signature))) {
      throw new Error("The sender signature could not be verified.");
    }
    exchange.senderSignature = signature;
    exchange.consentedAt = new Date().toISOString();
    exchange.walletConsentAt = exchange.consentedAt;
    exchange.status = exchange.witnessDid ? "pending_witness" : "pending_recipient";
  } else if (role === "witness") {
    const payload = witnessApprovalPayload(exchange);
    const signature = await signPayload(exchange.witnessDid, payload);
    if (!(await verifySignature(exchange.witnessDid, payload, signature))) {
      throw new Error("The witness signature could not be verified.");
    }
    exchange.witnessSignature = signature;
    exchange.witnessVerified = true;
    exchange.witnessedAt = new Date().toISOString();
    exchange.walletConsentAt = exchange.witnessedAt;
    exchange.status = "pending_recipient";
  } else if (role === "recipient") {
    const payload = recipientAcceptancePayload(exchange);
    exchange.recipientSignature = await signPayload(exchange.targetDid, payload);
    exchange.signaturesVerified = await verifyAllExchangeSignatures(exchange);
    if (!exchange.signaturesVerified) {
      throw new Error("The completed exchange signatures could not be verified.");
    }
    exchange.groupReceipt = await commitGroupReceipt(exchange);
    exchange.acceptedAt = new Date().toISOString();
    exchange.walletConsentAt = exchange.acceptedAt;
    exchange.status = "accepted";
  } else {
    throw new Error("Unsupported wallet signature role.");
  }

  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

function toast(message) {
  toastRoot.textContent = message;
  toastRoot.classList.add("visible");
  setTimeout(() => toastRoot.classList.remove("visible"), 1800);
}

document.addEventListener("submit", (event) => {
  if (
    event.target.id !== "wallet-exchange-form" &&
    !event.target.classList.contains("wallet-forward-form")
  ) {
    return;
  }
  event.preventDefault();
  const identity = identityById(identityId);
  const data = new FormData(event.target);
  const recipient = identityById(data.get("targetId"));
  const witness = identityById(data.get("witnessId"));
  try {
    const shared = {
      sourceId: identity.id,
      targetId: recipient?.id,
      sourceDid: identity.did,
      targetDid: recipient?.did,
      witnessId: witness?.id || null,
      witnessDid: witness?.did || null,
      purpose: data.get("purpose"),
      expiresAt: new Date(`${data.get("expiresAt")}T23:59:59`).toISOString(),
      consent: data.get("confirmRequest") === "on",
    };
    const exchange = event.target.classList.contains("wallet-forward-form")
      ? createForwardExchange({
          parentExchange: state.exchanges.find(
            ({ id }) => id === data.get("parentId"),
          ),
          ...shared,
        })
      : createTraitExchange({
          ...shared,
          sourceTraits: identity.traits || [],
          traitIds: data.getAll("traitIds"),
          allowRedisclosure: data.get("allowRedisclosure") === "on",
          maxDepth: data.get("maxDepth"),
        });
    state.exchanges.push(exchange);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    window.location.assign(identityWalletUrl(identity.id, "sign"));
  } catch (error) {
    toast(error.message);
  }
});

document.addEventListener("click", async (event) => {
  const signButton = event.target.closest("[data-sign-exchange]");
  if (signButton) {
    const card = signButton.closest(".sign-card");
    if (!card?.querySelector('input[type="checkbox"]')?.checked) {
      toast("Review and confirm explicit consent first");
      return;
    }
    const exchange = state.exchanges.find(
      ({ id }) => id === signButton.dataset.signExchange,
    );
    if (!exchange) {
      toast("This exchange request is no longer available");
      return;
    }
    signButton.disabled = true;
    signButton.textContent = "Signing…";
    try {
      await consentAndSign(exchange, signButton.dataset.signRole);
      state = loadWorkspace();
      render();
      toast("Exchange signed and verified");
    } catch (error) {
      state = loadWorkspace();
      render();
      toast(error.message);
    }
    return;
  }

  const button = event.target.closest("[data-copy]");
  if (!button) return;
  await navigator.clipboard.writeText(button.dataset.copy);
  toast("Copied to clipboard");
});

window.addEventListener("storage", (event) => {
  if (event.key !== STORAGE_KEY) return;
  state = loadWorkspace();
  render();
});

window.addEventListener("focus", () => {
  state = loadWorkspace();
  render();
});

async function checkChain() {
  try {
    const response = await fetch("/api/chain-status");
    const result = await response.json();
    if (!response.ok || !result.chain_valid) throw new Error();
    document.querySelector("#network-state").textContent = "Local chain verified";
  } catch {
    document.querySelector("#network-state").textContent = "Browser wallet";
    document.querySelector(".network-state").classList.add("offline");
  }
}

render();
checkChain();
