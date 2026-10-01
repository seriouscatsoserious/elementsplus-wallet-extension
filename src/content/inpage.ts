/**
 * Page-world provider: `window.elementsplus` (EIP-1193 shaped, spec §3.3).
 * Loaded as a classic script (the build strips the module marker). It holds no
 * secrets and talks only to this extension's isolated content script.
 */
(() => {
  type Handler = (...args: unknown[]) => void;
  interface Pending {
    readonly resolve: (value: unknown) => void;
    readonly reject: (error: Error) => void;
  }
  const target = window as unknown as Record<string, unknown>;
  if (target["elementsplus"] !== undefined) return;

  const TO_CONTENT = "elementsplus-content";
  const FROM_CONTENT = "elementsplus-inpage";
  const EVENTS = new Set(["accountsChanged", "disconnect"]);
  const pending = new Map<number, Pending>();
  const listeners = new Map<string, Set<Handler>>();
  let nextId = 1;

  class ProviderRpcError extends Error {
    readonly code: number;
    constructor(code: number, message: string) {
      super(message);
      this.name = "ProviderRpcError";
      this.code = code;
    }
  }

  window.addEventListener("message", (event: MessageEvent) => {
    if (event.source !== window) return;
    const data = event.data as Record<string, unknown> | null;
    if (typeof data !== "object" || data === null || data["target"] !== FROM_CONTENT) return;
    if (typeof data["event"] === "string") {
      for (const handler of listeners.get(data["event"]) ?? []) {
        try {
          handler(data["data"]);
        } catch {
          // A dApp listener must not break the provider.
        }
      }
      return;
    }
    const id = data["id"];
    if (typeof id !== "number") return;
    const entry = pending.get(id);
    if (entry === undefined) return;
    pending.delete(id);
    const error = data["error"] as { code?: unknown; message?: unknown } | undefined;
    if (error !== undefined && error !== null) {
      entry.reject(new ProviderRpcError(
        typeof error.code === "number" ? error.code : -32603,
        typeof error.message === "string" ? error.message : "Wallet error",
      ));
    } else {
      entry.resolve(data["result"]);
    }
  });

  interface Provider {
    readonly isElementsPlus: true;
    request(args: { method: string; params?: unknown }): Promise<unknown>;
    on(event: string, handler: Handler): Provider;
    removeListener(event: string, handler: Handler): Provider;
  }
  const provider: Provider = Object.freeze({
    isElementsPlus: true as const,
    request(args: { method: string; params?: unknown }): Promise<unknown> {
      if (typeof args !== "object" || args === null || typeof args.method !== "string" || args.method.length > 64) {
        return Promise.reject(new ProviderRpcError(-32602, "request expects { method: string, params?: unknown }"));
      }
      return new Promise((resolve, reject) => {
        const id = nextId;
        nextId += 1;
        pending.set(id, { resolve, reject });
        try {
          window.postMessage({ target: TO_CONTENT, id, method: args.method, params: args.params }, window.location.origin);
        } catch {
          pending.delete(id);
          reject(new ProviderRpcError(-32602, "params must be structured-cloneable JSON data"));
        }
      });
    },
    on(event: string, handler: Handler): Provider {
      if (EVENTS.has(event) && typeof handler === "function") {
        const set = listeners.get(event) ?? new Set<Handler>();
        set.add(handler);
        listeners.set(event, set);
      }
      return provider;
    },
    removeListener(event: string, handler: Handler): Provider {
      listeners.get(event)?.delete(handler);
      return provider;
    },
  });

  Object.defineProperty(window, "elementsplus", { value: provider, writable: false, configurable: false, enumerable: true });
  window.dispatchEvent(new Event("elementsplus#initialized"));
})();
