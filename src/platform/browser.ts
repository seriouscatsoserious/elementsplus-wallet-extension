export interface ExtensionStorageArea {
  get(keys: string | readonly string[]): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | readonly string[]): Promise<void>;
  setAccessLevel?(options: { accessLevel: "TRUSTED_CONTEXTS" }): Promise<void>;
}

export interface ExtensionApi {
  readonly runtime: {
    readonly id: string;
    readonly onMessage: {
      addListener(listener: (
        message: unknown,
        sender: { readonly id?: string; readonly url?: string },
        sendResponse: (response: unknown) => void,
      ) => boolean | void): void;
    };
    getURL(path: string): string;
    sendMessage(message: unknown): Promise<unknown>;
  };
  readonly storage: {
    readonly local: ExtensionStorageArea;
    readonly session?: ExtensionStorageArea;
  };
  readonly tabs: {
    create(properties: { url: string }): Promise<unknown>;
  };
}

type ExtensionGlobal = typeof globalThis & { browser?: ExtensionApi; chrome?: ExtensionApi };

export function getExtensionApi(): ExtensionApi {
  const extensionGlobal = globalThis as ExtensionGlobal;
  const api = extensionGlobal.browser ?? extensionGlobal.chrome;
  if (api === undefined) throw new Error("WebExtension API is unavailable");
  return api;
}

export async function restrictStorage(api: ExtensionApi): Promise<void> {
  await api.storage.local.setAccessLevel?.({ accessLevel: "TRUSTED_CONTEXTS" });
  await api.storage.session?.setAccessLevel?.({ accessLevel: "TRUSTED_CONTEXTS" });
}

export async function sendExtensionMessage<T>(message: unknown): Promise<T> {
  return getExtensionApi().runtime.sendMessage(message) as Promise<T>;
}
