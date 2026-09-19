import { UnavailableLwkAdapter } from "../adapters/lwk.js";
import { WalletController } from "./controller.js";
import { getExtensionApi, restrictStorage } from "../platform/browser.js";
import { VaultStore } from "../vault.js";

const api = getExtensionApi();
// MV3 wake-up events are delivered only to listeners registered during the
// worker's initial synchronous evaluation. Gate requests on storage hardening,
// but never await it before installing the listener.
const storageReady = restrictStorage(api).then(
  () => true,
  () => false,
);
const controller = new WalletController({
  vaultStore: new VaultStore(api.storage.local),
  adapter: new UnavailableLwkAdapter(),
});

api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== api.runtime.id || (sender.url !== undefined && !sender.url.startsWith(api.runtime.getURL("")))) {
    sendResponse({ ok: false, error: { code: "UNTRUSTED_SENDER", message: "Request sender is not an extension page" } });
    return false;
  }
  void storageReady
    .then((ready) => ready
      ? controller.handle(message)
      : { ok: false as const, error: { code: "STORAGE_HARDENING_FAILED", message: "Wallet storage initialization failed" } })
    .then(sendResponse)
    .catch(() => sendResponse({
      ok: false,
      error: { code: "STORAGE_HARDENING_FAILED", message: "Wallet storage initialization failed" },
    }));
  return true;
});
