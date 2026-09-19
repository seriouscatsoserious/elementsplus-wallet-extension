import type { LwkCapabilities, WalletSnapshot } from "../adapters/lwk.js";

export type ViewName = "dashboard" | "assets" | "send" | "receive" | "issue" | "manage" | "setup" | "network";

const VIEWS = new Set<ViewName>(["dashboard", "assets", "send", "receive", "issue", "manage", "setup", "network"]);

export function element<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (found === null) throw new Error(`Missing required element: ${id}`);
  return found as T;
}

export function setText(id: string, value: string): void {
  element(id).textContent = value;
}

export function setNotice(message: string, state: "idle" | "info" | "danger" | "success" = "idle"): void {
  const notice = element("runtime-notice");
  notice.textContent = message;
  notice.className = state === "idle" ? "notice" : `notice ${state}`;
  notice.dataset["state"] = state;
}

export function showView(view: ViewName): void {
  for (const section of document.querySelectorAll<HTMLElement>("[data-view]")) {
    section.hidden = section.dataset["view"] !== view;
  }
  for (const button of document.querySelectorAll<HTMLButtonElement>("[data-view-target]")) {
    if (button.dataset["viewTarget"] === view) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
  history.replaceState(null, "", `#${view}`);
}

export function initializeShell(options: { readonly preview: boolean }): void {
  for (const button of document.querySelectorAll<HTMLButtonElement>("[data-view-target], [data-view-link]")) {
    button.addEventListener("click", () => {
      const target = button.dataset["viewTarget"] ?? button.dataset["viewLink"];
      if (target !== undefined && VIEWS.has(target as ViewName)) showView(target as ViewName);
    });
  }
  for (const tab of document.querySelectorAll<HTMLButtonElement>("[data-setup-target]")) {
    tab.addEventListener("click", () => {
      const target = tab.dataset["setupTarget"];
      for (const candidate of document.querySelectorAll<HTMLButtonElement>("[data-setup-target]")) {
        candidate.setAttribute("aria-selected", String(candidate === tab));
      }
      for (const pane of document.querySelectorAll<HTMLElement>("[data-setup-pane]")) {
        pane.hidden = pane.dataset["setupPane"] !== target;
      }
    });
  }
  for (const form of document.querySelectorAll<HTMLFormElement>("form")) {
    if (options.preview) form.addEventListener("submit", (event) => event.preventDefault());
  }
  const requested = location.hash.slice(1);
  showView(VIEWS.has(requested as ViewName) ? requested as ViewName : "dashboard");
  if (options.preview) {
    setText("footer-clock", "STATIC PREVIEW");
  } else {
    const updateClock = (): void => setText("footer-clock", `${new Date().toISOString().slice(11, 19)} UTC`);
    updateClock();
    setInterval(updateClock, 1_000);
  }
}

export function setWalletActionsEnabled(capabilities: LwkCapabilities, unlocked: boolean): void {
  // No transaction controller is connected in this scaffold. Capability bits
  // from a future adapter must not make inert forms appear operational.
  const transactionControllersInstalled = false;
  const anyChainAction = transactionControllersInstalled
    && unlocked
    && capabilities.walletSync
    && capabilities.explicitTransactions;
  for (const button of document.querySelectorAll<HTMLButtonElement>("[data-wallet-action]")) {
    button.disabled = !anyChainAction;
  }
  const capabilityByForm = [
    { id: "send-form", enabled: anyChainAction },
    { id: "issue-form", enabled: transactionControllersInstalled && unlocked && capabilities.issuance },
  ];
  for (const form of capabilityByForm) {
    const root = document.getElementById(form.id);
    const fieldset = root?.querySelector<HTMLFieldSetElement>("[data-chain-fieldset]");
    if (fieldset !== null && fieldset !== undefined) fieldset.disabled = !form.enabled;
  }
  const manageFieldsets = document.querySelectorAll<HTMLFieldSetElement>("[data-view='manage'] [data-chain-fieldset]");
  if (manageFieldsets[0] !== undefined) manageFieldsets[0].disabled = !(transactionControllersInstalled && unlocked && capabilities.reissuance);
  if (manageFieldsets[1] !== undefined) manageFieldsets[1].disabled = !(transactionControllersInstalled && unlocked && capabilities.burning);
}

function assetLabel(asset: WalletSnapshot["assets"][number]): string {
  return asset.ticker ?? asset.name ?? `${asset.assetId.slice(0, 8)}…${asset.assetId.slice(-8)}`;
}

export function renderSnapshot(snapshot: WalletSnapshot): void {
  const native = snapshot.assets.find((asset) => asset.isNative);
  setText("ecx-balance", native === undefined ? "—" : `${native.amountAtomic} atomic`);
  setText("balance-caption", native === undefined ? "Native asset was not returned by wallet sync" : "Verified explicit UTXO total");
  setText("chain-tip", snapshot.tipHeight.toLocaleString("en-US"));
  setText("receive-address", snapshot.receiveAddress);
  const dashboard = element<HTMLTableSectionElement>("dashboard-assets");
  dashboard.replaceChildren();
  for (const asset of snapshot.assets) {
    const row = dashboard.insertRow();
    const label = row.insertCell();
    label.textContent = assetLabel(asset);
    if (asset.isNative) label.className = "native";
    row.insertCell().textContent = `${asset.assetId.slice(0, 8)}…${asset.assetId.slice(-8)}`;
    const amount = row.insertCell();
    amount.className = "amount";
    amount.textContent = `${asset.amountAtomic} atomic`;
  }
  const inventory = element<HTMLTableSectionElement>("asset-inventory");
  inventory.replaceChildren();
  if (snapshot.assets.length === 0) {
    const row = inventory.insertRow();
    row.className = "empty-row";
    const cell = row.insertCell();
    cell.colSpan = 4;
    cell.textContent = "VERIFIED SYNC RETURNED NO ASSETS";
    return;
  }
  for (const asset of snapshot.assets) {
    const row = inventory.insertRow();
    const ticker = row.insertCell();
    ticker.textContent = assetLabel(asset);
    if (asset.isNative) ticker.className = "native";
    row.insertCell().textContent = asset.assetId;
    const confirmed = row.insertCell();
    confirmed.className = "amount";
    confirmed.textContent = `${asset.confirmedAtomic} atomic`;
    const available = row.insertCell();
    available.className = "amount";
    available.textContent = `${asset.amountAtomic} atomic`;
  }
}

export function renderStaticPreview(): void {
  setNotice("STATIC UI PREVIEW — NO WALLET, KEYS, ADDRESSES, BALANCES, OR NODE DATA ARE LOADED.", "info");
  setText("vault-state", "NOT INITIALIZED");
  setText("adapter-state", "LWK NOT CONNECTED");
  setText("footer-status", "PREVIEW / ALL CHAIN ACTIONS DISABLED");
  setText("footer-net", "NET: NOT QUERIED");
  const badge = element("network-live");
  badge.textContent = "NET OFFLINE";
  badge.dataset["state"] = "idle";
  setWalletActionsEnabled({
    mnemonic: false,
    walletSync: false,
    explicitTransactions: false,
    issuance: false,
    reissuance: false,
    burning: false,
    confidentialTransactions: false,
    dex: false,
  }, false);
}
