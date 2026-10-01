import { ElementsPlusWalletFactory } from "../adapters/elementsplus-wasm.js";
import { WalletCore } from "../adapters/wallet-core.js";
import { loadActivity } from "../network/activity.js";
import { ECX_ALPHA_IDENTITY } from "../network/identity.js";
import { getExtensionApi, restrictStorage, type ExtensionPort, type MessageSender } from "../platform/browser.js";
import { bytesToBase64 } from "../shared/base64.js";
import { isPlainRecord } from "../shared/validation.js";
import { VaultStore } from "../vault.js";
import initWalletCore, {
  decode_offer_json,
  generate_mnemonic,
  validate_mnemonic,
  verify_asset_issuance_json,
  WasmWalletCore,
} from "../wasm/elementsplus_wallet_core.js";
import { failure, WalletController } from "./controller.js";
import { ProviderRouter, ProviderErrorCode } from "./provider-router.js";
import { SettingsStore, SitePermissions, validateOrigin } from "./settings.js";
import { TokenRegistry } from "./token-registry.js";

export const PROVIDER_PORT_NAME = "elementsplus-provider";
const APPROVAL_WIDTH = 376;
const APPROVAL_HEIGHT = 640;

const api = getExtensionApi();
// MV3 wake-up events reach only listeners registered during the worker's first
// synchronous evaluation: gate on storage hardening without awaiting it first.
const storageReady = restrictStorage(api).then(() => true, () => false);
const fetchImpl = globalThis.fetch.bind(globalThis);

let walletCoreReady: Promise<void> | undefined;
const core = new WalletCore(async () => {
  walletCoreReady ??= initWalletCore().then(() => undefined);
  await walletCoreReady;
  return { WasmWalletCore, generate_mnemonic, validate_mnemonic, verify_asset_issuance_json, decode_offer_json };
});
const settings = new SettingsStore(api.storage.local);
const permissions = new SitePermissions(api.storage.local);
const tokens = new TokenRegistry({
  storage: api.storage.local,
  verifyIssuance: (request) => core.verifyAssetIssuance(request),
  fetchImpl,
  endpoints: async () => {
    const current = await settings.get();
    return { registryUrl: current.registryUrl, explorerUrl: current.explorerUrl };
  },
  nativeAsset: { assetId: ECX_ALPHA_IDENTITY.nativeAssetId, name: ECX_ALPHA_IDENTITY.displayName, ticker: "ECX" },
});
const controller = new WalletController({
  vaultStore: new VaultStore(api.storage.local),
  storage: api.storage.local,
  wallets: new ElementsPlusWalletFactory(core, { identity: ECX_ALPHA_IDENTITY, fetchImpl }),
  settings,
  identity: ECX_ALPHA_IDENTITY,
  tokens,
  activity: (options) => loadActivity({ ...options, fetchImpl }),
});

const ports = new Map<string, Set<ExtensionPort>>();

function randomId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return bytesToBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

const router = new ProviderRouter({
  controller,
  permissions,
  identity: ECX_ALPHA_IDENTITY,
  randomId,
  emit: (origin, event, data) => {
    for (const port of ports.get(origin) ?? []) {
      try {
        port.postMessage({ event, data });
      } catch {
        // Port already closed.
      }
    }
  },
  openApproval: async (requestId) => {
    const url = api.runtime.getURL(`src/ui/approve.html?id=${encodeURIComponent(requestId)}`);
    if (api.windows === undefined) {
      await api.tabs.create({ url });
      return undefined;
    }
    let position: { left?: number; top?: number } = {};
    try {
      const focused = await api.windows.getLastFocused?.();
      if (focused?.left !== undefined && focused.top !== undefined && focused.width !== undefined) {
        position = { left: Math.max(0, focused.left + focused.width - APPROVAL_WIDTH - 16), top: focused.top + 72 };
      }
    } catch {
      // Default placement.
    }
    const created = await api.windows.create({ url, type: "popup", width: APPROVAL_WIDTH, height: APPROVAL_HEIGHT, focused: true, ...position });
    return created.id;
  },
  closeWindow: (windowId) => {
    void api.windows?.remove(windowId).catch(() => undefined);
  },
});

api.windows?.onRemoved.addListener((windowId) => router.windowClosed(windowId));

function isExtensionPage(sender: MessageSender): boolean {
  return sender.id === api.runtime.id && typeof sender.url === "string" && sender.url.startsWith(api.runtime.getURL(""));
}

async function handleInternal(message: unknown): Promise<unknown> {
  if (isPlainRecord(message) && typeof message["type"] === "string") {
    try {
      switch (message["type"]) {
        case "approval.get":
          if (typeof message["requestId"] !== "string") break;
          return { ok: true, result: await router.describe(message["requestId"]) };
        case "approval.resolve": {
          const { type: _type, ...decision } = message;
          return { ok: true, result: await router.resolve(decision) };
        }
        case "sites.list":
          return { ok: true, result: { sites: await router.listSites() } };
        case "sites.revoke":
          return { ok: true, result: { revoked: await router.revokeSite(validateOrigin(message["origin"])) } };
        default:
          return controller.handle(message);
      }
    } catch (error) {
      return failure(error);
    }
  }
  return controller.handle(message);
}

api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!isExtensionPage(sender)) {
    sendResponse({ ok: false, error: { code: "UNTRUSTED_SENDER", message: "Request sender is not an extension page" } });
    return false;
  }
  void storageReady
    .then((ready) => ready
      ? handleInternal(message)
      : { ok: false as const, error: { code: "STORAGE_HARDENING_FAILED", message: "Wallet storage initialization failed" } })
    .then(sendResponse)
    .catch(() => sendResponse({ ok: false, error: { code: "INTERNAL", message: "Wallet background failed" } }));
  return true;
});

function portOrigin(port: ExtensionPort): string | null {
  const sender = port.sender;
  if (sender === undefined || sender.id !== api.runtime.id || sender.tab === undefined || typeof sender.url !== "string") return null;
  if (sender.frameId !== undefined && sender.frameId !== 0) return null;
  try {
    const origin = sender.origin ?? new URL(sender.url).origin;
    return validateOrigin(origin);
  } catch {
    return null;
  }
}

api.runtime.onConnect.addListener((port) => {
  if (port.name !== PROVIDER_PORT_NAME) return;
  const origin = portOrigin(port);
  if (origin === null) {
    port.disconnect();
    return;
  }
  const set = ports.get(origin) ?? new Set<ExtensionPort>();
  set.add(port);
  ports.set(origin, set);
  let open = true;
  port.onDisconnect.addListener(() => {
    open = false;
    set.delete(port);
    if (set.size === 0) ports.delete(origin);
  });
  port.onMessage.addListener((message) => {
    if (!isPlainRecord(message)) return;
    const id = message["id"];
    if (!((typeof id === "string" && id.length <= 64) || (typeof id === "number" && Number.isSafeInteger(id)))) return;
    const { id: _id, ...request } = message;
    void storageReady
      .then((ready) => ready
        ? router.request(origin, request)
        : { error: { code: ProviderErrorCode.INTERNAL, message: "Wallet storage initialization failed" } })
      .then((response) => {
        if (open) port.postMessage({ id, ...response });
      });
  });
});
