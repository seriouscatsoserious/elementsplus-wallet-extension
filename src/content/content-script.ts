/**
 * Isolated-world bridge (spec §3.3): injects the inpage provider and relays
 * page requests to the service worker over a runtime port. The service worker
 * derives the requesting origin from the port sender, never from this payload.
 * Loaded as a classic script (the build strips the module marker).
 */
(() => {
  interface Port {
    postMessage(message: unknown): void;
    readonly onMessage: { addListener(listener: (message: unknown) => void): void };
    readonly onDisconnect: { addListener(listener: () => void): void };
  }
  interface Api {
    readonly runtime: { readonly id?: string; getURL(path: string): string; connect(info: { name: string }): Port };
  }
  const globals = globalThis as unknown as { browser?: Api; chrome?: Api };
  const api = globals.browser ?? globals.chrome;
  if (api?.runtime?.id === undefined) return;
  if (location.protocol !== "https:" && location.protocol !== "http:") return;
  if (window.top !== window) return;

  const TO_PAGE = "elementsplus-inpage";
  const FROM_PAGE = "elementsplus-content";
  const PORT_NAME = "elementsplus-provider";
  const inflight = new Set<number>();
  let port: Port | undefined;

  const toPage = (message: Record<string, unknown>): void => {
    window.postMessage({ ...message, target: TO_PAGE }, location.origin);
  };

  const connect = (): Port => {
    const next = api.runtime.connect({ name: PORT_NAME });
    next.onMessage.addListener((message) => {
      if (typeof message !== "object" || message === null) return;
      const data = message as Record<string, unknown>;
      if (data["event"] === "accountsChanged" || data["event"] === "disconnect") {
        toPage({ event: data["event"], data: data["data"] });
        return;
      }
      const id = data["id"];
      if (typeof id !== "number" || !inflight.has(id)) return;
      inflight.delete(id);
      toPage("error" in data ? { id, error: data["error"] } : { id, result: data["result"] });
    });
    next.onDisconnect.addListener(() => {
      if (port === next) port = undefined;
      for (const id of inflight) toPage({ id, error: { code: -32603, message: "Wallet disconnected; please retry" } });
      inflight.clear();
    });
    return next;
  };

  window.addEventListener("message", (event: MessageEvent) => {
    if (event.source !== window || event.origin !== location.origin) return;
    const data = event.data as Record<string, unknown> | null;
    if (typeof data !== "object" || data === null || data["target"] !== FROM_PAGE) return;
    const id = data["id"];
    const method = data["method"];
    if (typeof id !== "number" || !Number.isSafeInteger(id) || typeof method !== "string" || method.length > 64) return;
    if (inflight.has(id) || inflight.size >= 64) {
      toPage({ id, error: { code: -32603, message: "Too many pending requests" } });
      return;
    }
    inflight.add(id);
    try {
      port ??= connect();
      port.postMessage({ id, method, ...(data["params"] === undefined ? {} : { params: data["params"] }) });
    } catch {
      inflight.delete(id);
      port = undefined;
      toPage({ id, error: { code: -32603, message: "Wallet is unavailable" } });
    }
  });

  const script = document.createElement("script");
  script.src = api.runtime.getURL("src/content/inpage.js");
  script.async = false;
  script.addEventListener("load", () => script.remove());
  (document.head ?? document.documentElement).append(script);
})();
