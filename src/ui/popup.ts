import { getExtensionApi, sendExtensionMessage } from "../platform/browser.js";
import { isPlainRecord } from "../shared/validation.js";

function required<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (found === null) throw new Error(`Missing required element: ${id}`);
  return found as T;
}

const api = getExtensionApi();

async function openWallet(view: string): Promise<void> {
  await api.tabs.create({ url: `${api.runtime.getURL("src/ui/wallet.html")}#${view}` });
  window.close();
}

required<HTMLButtonElement>("open-wallet").addEventListener("click", () => void openWallet("dashboard"));
required<HTMLButtonElement>("open-setup").addEventListener("click", () => void openWallet("setup"));

void (async () => {
  const notice = required<HTMLElement>("popup-status");
  try {
    const response = await sendExtensionMessage({ type: "wallet.status" });
    if (!isPlainRecord(response) || response["ok"] !== true || !isPlainRecord(response["result"])) {
      throw new Error("Background status is malformed");
    }
    const status = response["result"];
    if (typeof status["initialized"] !== "boolean" || typeof status["unlocked"] !== "boolean" || !isPlainRecord(status["adapter"]) || typeof status["adapter"]["available"] !== "boolean") {
      throw new Error("Wallet status is malformed");
    }
    required<HTMLOutputElement>("popup-vault").textContent = status["initialized"] ? (status["unlocked"] ? "UNLOCKED" : "LOCKED") : "NOT INITIALIZED";
    required<HTMLOutputElement>("popup-adapter").textContent = status["adapter"]["available"] ? "READY" : "NOT INSTALLED";
    if (!status["adapter"]["available"]) {
      notice.textContent = "LWK NOT INSTALLED. CHAIN ACTIONS ARE FAIL-CLOSED; NO BALANCE IS BEING CLAIMED.";
      notice.dataset["state"] = "error";
    } else {
      notice.textContent = status["unlocked"] ? "WALLET UNLOCKED / AUTO-LOCK ARMED." : "WALLET READY / VAULT LOCKED.";
      notice.dataset["state"] = "ready";
    }
  } catch (error) {
    notice.textContent = error instanceof Error ? error.message.toUpperCase() : "BACKGROUND UNAVAILABLE";
    notice.dataset["state"] = "error";
  }
})();
