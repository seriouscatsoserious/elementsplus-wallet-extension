import type { LwkCapabilities, WalletAsset, WalletSnapshot } from "../adapters/lwk.js";
import { EcxAlphaEsploraClient, resolveEcxAlphaAddress } from "../network/ecx-alpha.js";
import { ECX_ALPHA_IDENTITY } from "../network/identity.js";
import { sendExtensionMessage } from "../platform/browser.js";
import { isPlainRecord } from "../shared/validation.js";
import {
  element,
  initializeShell,
  renderSnapshot,
  setNotice,
  setText,
  setWalletActionsEnabled,
  showView,
} from "./shell.js";
import {
  parseBroadcastTransactionResult,
  parsePreparedSendApproval,
  parseSendDraft,
  type PreparedSendApproval,
} from "./send-flow.js";

interface WalletStatus {
  readonly initialized: boolean;
  readonly unlocked: boolean;
  readonly adapter: {
    readonly available: boolean;
    readonly implementation: string;
    readonly capabilities: LwkCapabilities;
  };
}

interface ResponseEnvelope {
  readonly ok: boolean;
  readonly result?: unknown;
  readonly error?: { readonly code: string; readonly message: string };
}

let statusCache: WalletStatus | undefined;
let generatedMnemonic = "";
let restoreMode = false;
let networkRequestRunning = false;
let latestSnapshot: WalletSnapshot | undefined;
let pendingApproval: PreparedSendApproval | undefined;
let approvalExpiryTimer: ReturnType<typeof setTimeout> | undefined;
let prepareRequestRunning = false;
let approvalRequestRunning = false;

function unwrap(value: unknown): unknown {
  if (!isPlainRecord(value) || typeof value["ok"] !== "boolean") throw new Error("Background returned a malformed response");
  const envelope = value as unknown as ResponseEnvelope;
  if (envelope.ok) return envelope.result;
  throw new Error(envelope.error?.message ?? "Wallet operation failed");
}

function capabilities(value: unknown): LwkCapabilities {
  if (!isPlainRecord(value)) throw new Error("Adapter capabilities are malformed");
  const mnemonic = value["mnemonic"];
  const walletSync = value["walletSync"];
  const explicitTransactions = value["explicitTransactions"];
  const issuance = value["issuance"];
  const reissuance = value["reissuance"];
  const burning = value["burning"];
  if (
    typeof mnemonic !== "boolean"
    || typeof walletSync !== "boolean"
    || typeof explicitTransactions !== "boolean"
    || typeof issuance !== "boolean"
    || typeof reissuance !== "boolean"
    || typeof burning !== "boolean"
    || typeof value["confidentialTransactions"] !== "boolean"
    || typeof value["dex"] !== "boolean"
  ) throw new Error("Adapter capabilities are malformed");
  if (value["confidentialTransactions"] !== false || value["dex"] !== false) {
    throw new Error("This build refuses confidential or DEX capabilities");
  }
  return {
    mnemonic,
    walletSync,
    explicitTransactions,
    issuance,
    reissuance,
    burning,
    confidentialTransactions: false,
    dex: false,
  };
}

function parseStatus(value: unknown): WalletStatus {
  if (!isPlainRecord(value) || typeof value["initialized"] !== "boolean" || typeof value["unlocked"] !== "boolean" || !isPlainRecord(value["adapter"]) || !isPlainRecord(value["network"])) {
    throw new Error("Wallet status is malformed");
  }
  const network = value["network"];
  if (
    network["genesisHash"] !== ECX_ALPHA_IDENTITY.genesisHash
    || network["nativeAssetId"] !== ECX_ALPHA_IDENTITY.nativeAssetId
    || network["sidechainSlot"] !== ECX_ALPHA_IDENTITY.sidechainSlot
  ) throw new Error("Background network identity does not match pinned ECX Alpha");
  const adapter = value["adapter"];
  if (typeof adapter["available"] !== "boolean" || typeof adapter["implementation"] !== "string") {
    throw new Error("Wallet adapter status is malformed");
  }
  return {
    initialized: value["initialized"],
    unlocked: value["unlocked"],
    adapter: {
      available: adapter["available"],
      implementation: adapter["implementation"],
      capabilities: capabilities(adapter["capabilities"]),
    },
  };
}

function parseAsset(value: unknown): WalletAsset {
  if (
    !isPlainRecord(value)
    || typeof value["assetId"] !== "string" || !/^[0-9a-f]{64}$/.test(value["assetId"])
    || !(value["ticker"] === null || typeof value["ticker"] === "string")
    || !(value["name"] === null || typeof value["name"] === "string")
    || typeof value["amountAtomic"] !== "string" || !/^\d+$/.test(value["amountAtomic"])
    || typeof value["confirmedAtomic"] !== "string" || !/^\d+$/.test(value["confirmedAtomic"])
    || typeof value["isNative"] !== "boolean"
  ) throw new Error("Wallet returned malformed asset data");
  return {
    assetId: value["assetId"], ticker: value["ticker"], name: value["name"],
    amountAtomic: value["amountAtomic"], confirmedAtomic: value["confirmedAtomic"], isNative: value["isNative"],
  };
}

function parseSnapshot(value: unknown): WalletSnapshot {
  if (
    !isPlainRecord(value)
    || !isPlainRecord(value["chain"])
    || value["chain"]["genesisHash"] !== ECX_ALPHA_IDENTITY.genesisHash
    || value["chain"]["nativeAssetId"] !== ECX_ALPHA_IDENTITY.nativeAssetId
    || value["chain"]["backend"] !== "explorer"
    || value["chain"]["headerChainVerified"] !== false
    || value["chain"]["transactionPolicy"] !== "explicit-only"
    || typeof value["tipHeight"] !== "number" || !Number.isSafeInteger(value["tipHeight"]) || value["tipHeight"] < 0
    || typeof value["tipHash"] !== "string" || !/^[0-9a-f]{64}$/.test(value["tipHash"])
    || typeof value["receiveAddress"] !== "string" || value["receiveAddress"].length === 0
    || typeof value["syncedAt"] !== "string" || !Array.isArray(value["assets"])
  ) throw new Error("Wallet snapshot is malformed");
  const receiveAddress = resolveEcxAlphaAddress(value["receiveAddress"]);
  if (receiveAddress.confidential) throw new Error("Wallet snapshot receive address must be explicit");
  return {
    chain: {
      genesisHash: ECX_ALPHA_IDENTITY.genesisHash,
      nativeAssetId: ECX_ALPHA_IDENTITY.nativeAssetId,
      backend: "explorer",
      headerChainVerified: false,
      transactionPolicy: "explicit-only",
    },
    tipHeight: value["tipHeight"], tipHash: value["tipHash"], receiveAddress: receiveAddress.canonical,
    assets: value["assets"].map(parseAsset), syncedAt: value["syncedAt"],
  };
}

function walletCanTransact(status: WalletStatus | undefined): boolean {
  return status?.adapter.available === true
    && status.unlocked
    && status.adapter.capabilities.walletSync
    && status.adapter.capabilities.explicitTransactions;
}

function clearPendingApproval(message = "No transaction is awaiting approval."): void {
  if (approvalExpiryTimer !== undefined) clearTimeout(approvalExpiryTimer);
  approvalExpiryTimer = undefined;
  pendingApproval = undefined;
  approvalRequestRunning = false;
  element<HTMLButtonElement>("approve-broadcast").disabled = true;
  setText("approval-status", message);
}

function configureTransactionStatus(status: WalletStatus): void {
  const message = element<HTMLElement>("send-capability-status");
  if (walletCanTransact(status)) {
    message.className = "subtle-notice";
    message.textContent = "Native ECX only. Amounts are whole atomic units; outputs are explicit / non-confidential.";
    return;
  }
  message.className = "warning-banner";
  message.textContent = status.unlocked
    ? "This wallet engine does not support synchronized explicit transfers."
    : "Unlock a wallet engine with synchronized explicit-transfer support to send.";
}

function applySnapshot(snapshot: WalletSnapshot): void {
  latestSnapshot = snapshot;
  renderSnapshot(snapshot);
  const native = snapshot.assets.find((asset) => asset.isNative);
  setText("send-available", native === undefined ? "Available —" : `Available ${native.amountAtomic} atomic units`);
}

async function synchronizeWalletSnapshot(): Promise<WalletSnapshot> {
  const snapshot = parseSnapshot(unwrap(await sendExtensionMessage({ type: "wallet.snapshot" })));
  applySnapshot(snapshot);
  return snapshot;
}

function configureSetup(status: WalletStatus): void {
  const enabled = status.adapter.available && status.adapter.capabilities.mnemonic && !status.initialized;
  for (const id of ["generate-phrase", "restore-phrase", "setup-password", "setup-confirm", "backup-ack", "identity-ack", "create-vault"]) {
    element<HTMLInputElement | HTMLTextAreaElement | HTMLButtonElement>(id).disabled = !enabled;
  }
  if (status.initialized) setText("setup-status", "A vault already exists. This build will not overwrite it.");
  else if (!enabled) setText("setup-status", "Waiting for the reviewed wallet adapter.");
}

async function refreshStatus(): Promise<void> {
  const status = parseStatus(unwrap(await sendExtensionMessage({ type: "wallet.status" })));
  statusCache = status;
  setText("vault-state", status.initialized ? (status.unlocked ? "Unlocked" : "Locked") : "Not initialized");
  setText("account-state", status.initialized ? (status.unlocked ? "Unlocked" : "Locked") : "Not set up");
  setText("adapter-state", status.adapter.available ? status.adapter.implementation : "Not installed");
  setText("footer-status", status.adapter.available ? (status.unlocked ? "Auto-lock active" : "Wallet locked") : "Chain actions disabled");
  const unlockInput = element<HTMLInputElement>("unlock-password");
  const unlockButton = element<HTMLButtonElement>("unlock-wallet");
  const lockButton = element<HTMLButtonElement>("lock-wallet");
  unlockInput.disabled = !(status.initialized && status.adapter.available && !status.unlocked);
  unlockButton.disabled = unlockInput.disabled;
  lockButton.disabled = !status.unlocked;
  configureSetup(status);
  setWalletActionsEnabled(status.adapter.capabilities, status.unlocked);
  configureTransactionStatus(status);
  if (!walletCanTransact(status)) {
    latestSnapshot = undefined;
    clearPendingApproval(status.unlocked ? "Explicit transfers are unavailable." : "Wallet locked; approval cleared.");
  }
  if (!status.adapter.available) {
    setNotice("Wallet engine not installed. Keys, addresses, balances, and transactions remain disabled.", "danger");
  } else if (!status.initialized) {
    setNotice("No local wallet yet. Create or import a disposable ECX Alpha wallet to continue.", "info");
  } else if (!status.unlocked) {
    setNotice("Wallet locked. It locks again after five minutes without activity.");
  } else {
    setNotice("Wallet unlocked. Synchronizing explorer-backed explicit UTXOs…", "success");
    await synchronizeWalletSnapshot();
    setNotice("Wallet unlocked. ECX Alpha explorer snapshot loaded.", "success");
  }
}

async function refreshNetwork(): Promise<void> {
  if (networkRequestRunning) return;
  networkRequestRunning = true;
  const badge = element<HTMLElement>("network-live");
  try {
    const network = await new EcxAlphaEsploraClient().getNetworkStatus();
    setText("chain-tip", network.tip.height.toLocaleString("en-US"));
    setText("mempool-count", `${network.mempool.count.toLocaleString("en-US")} TX / ${network.mempool.virtualSize.toLocaleString("en-US")} vB`);
    setText("footer-net", `PINS MATCH @ ${network.tip.height}`);
    badge.textContent = "PINS MATCH";
    badge.dataset["state"] = "ready";
  } catch {
    setText("chain-tip", "—");
    setText("mempool-count", "—");
    setText("footer-net", "PINS: MATCH FAILED");
    badge.textContent = "PINS FAIL";
    badge.dataset["state"] = "error";
  } finally {
    networkRequestRunning = false;
  }
}

function inputNamed(form: HTMLFormElement, name: string): HTMLInputElement {
  const control = form.elements.namedItem(name);
  if (!(control instanceof HTMLInputElement)) throw new Error(`Missing send input: ${name}`);
  return control;
}

function renderPreparedApproval(approval: PreparedSendApproval): void {
  const summary = approval.summary;
  setText("review-destination", summary.destination);
  setText("review-amount", `${summary.amountAtomic} atomic units ECX`);
  setText("review-asset", summary.assetId);
  setText("review-fee", `${summary.networkFeeAtomic} atomic units ECX`);
  setText("review-fee-asset", summary.networkFeeAssetId);
  setText("review-fee-rate", `${summary.feeRate} atomic units / vbyte`);
  setText("review-policy", summary.transactionPolicy);
  setText("review-expiry", approval.expiresAt);
  setText("review-summary-hash", approval.summaryHash);
  setText("approval-status", "Review every value, then explicitly approve before the deadline.");
  element<HTMLButtonElement>("approve-broadcast").disabled = false;

  if (approvalExpiryTimer !== undefined) clearTimeout(approvalExpiryTimer);
  const delay = Math.max(0, Date.parse(approval.expiresAt) - Date.now());
  approvalExpiryTimer = setTimeout(() => {
    if (pendingApproval !== approval || approvalRequestRunning) return;
    clearPendingApproval("Approval expired. Return to Send and prepare the transaction again.");
  }, Math.min(delay + 25, 2_147_483_647));
}

async function copyReceiveAddress(): Promise<void> {
  const address = latestSnapshot?.receiveAddress;
  if (address === undefined) throw new Error("No synchronized receive address is available");
  const resolved = resolveEcxAlphaAddress(address);
  if (resolved.confidential || resolved.canonical !== address) {
    throw new Error("Receive address failed canonical explicit-address validation");
  }

  if (navigator.clipboard !== undefined) {
    try {
      await navigator.clipboard.writeText(address);
      return;
    } catch {
      // The legacy copy path below remains scoped to this explicit click.
    }
  }
  const scratch = document.createElement("textarea");
  scratch.value = address;
  scratch.readOnly = true;
  scratch.style.position = "fixed";
  scratch.style.opacity = "0";
  document.body.append(scratch);
  scratch.select();
  const copied = document.execCommand("copy");
  scratch.remove();
  if (!copied) throw new Error("Browser denied clipboard access; select and copy the address manually");
}

initializeShell({ preview: false });

element<HTMLFormElement>("send-form").addEventListener("submit", (event) => {
  event.preventDefault();
  if (prepareRequestRunning) return;
  void (async () => {
    const form = element<HTMLFormElement>("send-form");
    const reviewButton = element<HTMLButtonElement>("review-transaction");
    prepareRequestRunning = true;
    reviewButton.disabled = true;
    clearPendingApproval("Preparing transaction…");
    setText("send-status", "Preparing an exact transaction for review…");
    try {
      if (!walletCanTransact(statusCache)) throw new Error("Wallet is locked or explicit transfers are unavailable");
      const draft = parseSendDraft({
        destination: inputNamed(form, "destination").value,
        amountAtomic: inputNamed(form, "amount").value,
        feeRate: inputNamed(form, "fee-rate").value,
      });
      inputNamed(form, "destination").value = draft.destination;
      const prepared = unwrap(await sendExtensionMessage({
        type: "transaction.prepare-send",
        assetId: draft.assetId,
        destination: draft.destination,
        amountAtomic: draft.amountAtomic,
        feeRate: draft.feeRate,
      }));
      const approval = parsePreparedSendApproval(prepared, draft);
      pendingApproval = approval;
      renderPreparedApproval(approval);
      setText("send-status", "Transaction prepared. No signature has been made yet.");
      showView("review");
    } catch (error) {
      clearPendingApproval("Preparation failed. Correct the send details and try again.");
      setText("send-status", error instanceof Error ? error.message : "Transaction preparation failed");
      showView("send");
    } finally {
      prepareRequestRunning = false;
      reviewButton.disabled = !walletCanTransact(statusCache);
    }
  })();
});

element<HTMLButtonElement>("approve-broadcast").addEventListener("click", () => {
  if (approvalRequestRunning) return;
  void (async () => {
    const approval = pendingApproval;
    const button = element<HTMLButtonElement>("approve-broadcast");
    if (approval === undefined) {
      clearPendingApproval("Approval expired or was already used. Return to Send and prepare again.");
      return;
    }
    if (Date.parse(approval.expiresAt) <= Date.now()) {
      clearPendingApproval("Approval expired. Return to Send and prepare again.");
      return;
    }
    approvalRequestRunning = true;
    pendingApproval = undefined;
    if (approvalExpiryTimer !== undefined) clearTimeout(approvalExpiryTimer);
    approvalExpiryTimer = undefined;
    button.disabled = true;
    setText("approval-status", "Signing locally and submitting to the ECX Alpha explorer…");
    try {
      if (!walletCanTransact(statusCache)) throw new Error("Wallet locked before approval");
      const result = parseBroadcastTransactionResult(unwrap(await sendExtensionMessage({
        type: "transaction.approve-and-broadcast",
        approvalToken: approval.approvalToken,
        summaryHash: approval.summaryHash,
      })));
      setText("broadcast-txid", result.txid);
      setText("post-broadcast-status", "Refreshing the explorer-backed wallet snapshot…");
      showView("sent");
      try {
        await synchronizeWalletSnapshot();
        setText("post-broadcast-status", "Wallet snapshot refreshed. Explorer state may lag until relay or confirmation.");
      } catch {
        setText("post-broadcast-status", "Transaction ID retained. Snapshot refresh failed; check the explorer before retrying anything.");
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : "Transaction approval failed";
      setText("approval-status", `${detail} Approval is consumed; prepare again only after checking network state.`);
      showView("review");
    } finally {
      approvalRequestRunning = false;
    }
  })();
});

for (const id of ["edit-transaction", "cancel-review"]) {
  element<HTMLButtonElement>(id).addEventListener("click", () => {
    clearPendingApproval("Review cancelled. Prepare the transaction again after editing.");
  });
}

element<HTMLButtonElement>("copy-receive-address").addEventListener("click", () => {
  void copyReceiveAddress().then(
    () => setText("receive-status", "Address copied to clipboard."),
    (error: unknown) => setText("receive-status", error instanceof Error ? error.message : "Unable to copy address"),
  );
});

element<HTMLFormElement>("issue-form").addEventListener("submit", (event) => {
  event.preventDefault();
  setNotice("Asset issuance is not enabled by the current reviewed adapter.", "danger");
});

for (const tab of document.querySelectorAll<HTMLButtonElement>("[data-setup-target]")) {
  tab.addEventListener("click", () => { restoreMode = tab.dataset["setupTarget"] === "restore"; });
}

element<HTMLButtonElement>("generate-phrase").addEventListener("click", () => {
  void (async () => {
    try {
      const value = unwrap(await sendExtensionMessage({ type: "mnemonic.generate" }));
      if (!isPlainRecord(value) || typeof value["mnemonic"] !== "string") throw new Error("Mnemonic response is malformed");
      generatedMnemonic = value["mnemonic"];
      setText("generated-phrase", generatedMnemonic);
      setText("setup-status", "WRITE THE PHRASE DOWN OFFLINE. THE NEXT STEP ENCRYPTS A LOCAL COPY.");
    } catch (error) {
      setText("setup-status", error instanceof Error ? error.message.toUpperCase() : "PHRASE GENERATION FAILED");
    }
  })();
});

element<HTMLFormElement>("setup-form").addEventListener("submit", (event) => {
  event.preventDefault();
  void (async () => {
    try {
      const password = element<HTMLInputElement>("setup-password").value;
      if (password !== element<HTMLInputElement>("setup-confirm").value) throw new Error("Passwords do not match");
      if (!element<HTMLInputElement>("backup-ack").checked) throw new Error("Offline backup confirmation is required");
      const phrase = restoreMode ? element<HTMLTextAreaElement>("restore-phrase").value : generatedMnemonic;
      if (phrase.length === 0) throw new Error("No recovery phrase is available");
      unwrap(await sendExtensionMessage({
        type: "vault.create",
        password,
        mnemonic: phrase,
        identityAcknowledged: element<HTMLInputElement>("identity-ack").checked,
      }));
      generatedMnemonic = "";
      setText("generated-phrase", "PHRASE CLEARED FROM THIS PAGE");
      element<HTMLInputElement>("setup-password").value = "";
      element<HTMLInputElement>("setup-confirm").value = "";
      element<HTMLTextAreaElement>("restore-phrase").value = "";
      await refreshStatus();
      showView("dashboard");
    } catch (error) {
      setText("setup-status", error instanceof Error ? error.message.toUpperCase() : "VAULT CREATION FAILED");
    }
  })();
});

element<HTMLFormElement>("unlock-form").addEventListener("submit", (event) => {
  event.preventDefault();
  void (async () => {
    const input = element<HTMLInputElement>("unlock-password");
    try {
      unwrap(await sendExtensionMessage({ type: "wallet.unlock", password: input.value }));
      input.value = "";
      await refreshStatus();
    } catch (error) {
      input.value = "";
      setNotice(error instanceof Error ? error.message.toUpperCase() : "UNLOCK FAILED", "danger");
    }
  })();
});

element<HTMLButtonElement>("lock-wallet").addEventListener("click", () => {
  void (async () => {
    unwrap(await sendExtensionMessage({ type: "wallet.lock" }));
    await refreshStatus();
  })();
});

let lastActivitySent = 0;
const activity = (event: Event): void => {
  if (!event.isTrusted || !statusCache?.unlocked || Date.now() - lastActivitySent < 30_000) return;
  lastActivitySent = Date.now();
  void sendExtensionMessage({ type: "wallet.activity" });
};
document.addEventListener("pointerdown", activity);
document.addEventListener("keydown", activity);

void refreshStatus().catch((error: unknown) => {
  setNotice(error instanceof Error ? error.message.toUpperCase() : "EXTENSION INITIALIZATION FAILED", "danger");
  setText("vault-state", "ERROR");
  setText("adapter-state", "ERROR");
  setText("footer-status", "FAIL-CLOSED / BACKGROUND UNAVAILABLE");
});

void refreshNetwork();
setInterval(() => void refreshNetwork(), 30_000);
