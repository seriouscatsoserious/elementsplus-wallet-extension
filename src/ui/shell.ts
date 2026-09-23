import type { LwkCapabilities, WalletSnapshot } from "../adapters/lwk.js";

export type ViewName = "dashboard" | "assets" | "send" | "review" | "sent" | "receive" | "issue" | "manage" | "setup" | "network";

const VIEWS = new Set<ViewName>(["dashboard", "assets", "send", "review", "sent", "receive", "issue", "manage", "setup", "network"]);

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
  document.querySelector<HTMLElement>(".app-content")?.scrollTo(0, 0);
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
  const explicitWalletReady = unlocked
    && capabilities.walletSync
    && capabilities.explicitTransactions;
  // These controller routes do not exist yet. Capability bits alone must not
  // expose inert or unsafe issuance controls.
  const issuanceControllerInstalled = false;
  const reissuanceControllerInstalled = false;
  const burnControllerInstalled = false;
  for (const button of document.querySelectorAll<HTMLButtonElement>("[data-wallet-action]")) {
    const action = button.dataset["walletAction"];
    button.disabled = action === "issue"
      ? !(explicitWalletReady && issuanceControllerInstalled && capabilities.issuance)
      : !explicitWalletReady;
  }
  const capabilityByForm = [
    { id: "send-form", enabled: explicitWalletReady },
    { id: "issue-form", enabled: explicitWalletReady && issuanceControllerInstalled && capabilities.issuance },
  ];
  for (const form of capabilityByForm) {
    const root = document.getElementById(form.id);
    const fieldset = root?.querySelector<HTMLFieldSetElement>("[data-chain-fieldset]");
    if (fieldset !== null && fieldset !== undefined) fieldset.disabled = !form.enabled;
  }
  const manageFieldsets = document.querySelectorAll<HTMLFieldSetElement>("[data-view='manage'] [data-chain-fieldset]");
  if (manageFieldsets[0] !== undefined) manageFieldsets[0].disabled = !(explicitWalletReady && reissuanceControllerInstalled && capabilities.reissuance);
  if (manageFieldsets[1] !== undefined) manageFieldsets[1].disabled = !(explicitWalletReady && burnControllerInstalled && capabilities.burning);
}

function assetLabel(asset: WalletSnapshot["assets"][number]): string {
  return asset.ticker ?? asset.name ?? `${asset.assetId.slice(0, 8)}…${asset.assetId.slice(-8)}`;
}

function renderAssetIdentity(
  cell: HTMLTableCellElement,
  asset: WalletSnapshot["assets"][number],
): void {
  const identity = document.createElement("span");
  identity.className = "asset-name";
  const icon = document.createElement("span");
  icon.className = "token-icon";
  icon.textContent = asset.isNative ? "E" : assetLabel(asset).slice(0, 1).toUpperCase();
  const copy = document.createElement("span");
  const label = document.createElement("strong");
  label.textContent = assetLabel(asset);
  const detail = document.createElement("small");
  detail.textContent = asset.isNative ? "Alpha ECX" : "Issued asset";
  copy.append(label, detail);
  identity.append(icon, copy);
  cell.append(identity);
}

function renderAmount(cell: HTMLTableCellElement, amount: string, caption: string): void {
  cell.className = "amount";
  const value = document.createElement("strong");
  value.textContent = `${amount} atomic`;
  const detail = document.createElement("small");
  detail.textContent = caption;
  cell.append(value, detail);
}

export function renderSnapshot(snapshot: WalletSnapshot): void {
  const native = snapshot.assets.find((asset) => asset.isNative);
  setText("ecx-balance", native === undefined ? "—" : `${native.amountAtomic} atomic`);
  setText("balance-caption", native === undefined ? "Native asset was not returned by wallet sync" : "Explorer-reported explicit UTXO total");
  setText("chain-tip", snapshot.tipHeight.toLocaleString("en-US"));
  setText("receive-address", snapshot.receiveAddress);
  const dashboard = element<HTMLTableSectionElement>("dashboard-assets");
  dashboard.replaceChildren();
  for (const asset of snapshot.assets) {
    const row = dashboard.insertRow();
    renderAssetIdentity(row.insertCell(), asset);
    const id = row.insertCell();
    id.className = "asset-id";
    id.textContent = `${asset.assetId.slice(0, 8)}…${asset.assetId.slice(-8)}`;
    renderAmount(row.insertCell(), asset.amountAtomic, "Available");
  }
  const inventory = element<HTMLTableSectionElement>("asset-inventory");
  inventory.replaceChildren();
  if (snapshot.assets.length === 0) {
    const row = inventory.insertRow();
    row.className = "empty-row";
    const cell = row.insertCell();
    cell.colSpan = 3;
    cell.textContent = "VERIFIED SYNC RETURNED NO ASSETS";
    return;
  }
  for (const asset of snapshot.assets) {
    const row = inventory.insertRow();
    renderAssetIdentity(row.insertCell(), asset);
    const id = row.insertCell();
    id.className = "asset-id";
    id.textContent = asset.assetId;
    renderAmount(row.insertCell(), asset.amountAtomic, `${asset.confirmedAtomic} confirmed`);
  }
}

export function renderStaticPreview(): void {
  setNotice("Preview mode — no wallet, keys, addresses, balances, or node data are loaded.", "info");
  setText("vault-state", "Not initialized");
  setText("account-state", "Not set up");
  setText("adapter-state", "Not connected");
  setText("footer-status", "All chain actions disabled");
  setText("footer-net", "Not queried");
  const badge = element("network-live");
  badge.textContent = "Preview offline";
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
