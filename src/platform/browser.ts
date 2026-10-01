export interface ExtensionStorageArea {
  get(keys: string | readonly string[]): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | readonly string[]): Promise<void>;
  setAccessLevel?(options: { accessLevel: "TRUSTED_CONTEXTS" }): Promise<void>;
}

export interface MessageSender {
  readonly id?: string;
  readonly url?: string;
  readonly origin?: string;
  readonly frameId?: number;
  readonly tab?: { readonly id?: number; readonly windowId?: number };
}

export interface ExtensionPort {
  readonly name: string;
  readonly sender?: MessageSender;
  postMessage(message: unknown): void;
  disconnect(): void;
  readonly onMessage: { addListener(listener: (message: unknown) => void): void };
  readonly onDisconnect: { addListener(listener: () => void): void };
}

export interface ExtensionApi {
  readonly runtime: {
    readonly id: string;
    readonly onMessage: {
      addListener(listener: (
        message: unknown,
        sender: MessageSender,
        sendResponse: (response: unknown) => void,
      ) => boolean | void): void;
    };
    readonly onConnect: { addListener(listener: (port: ExtensionPort) => void): void };
    connect(info: { name: string }): ExtensionPort;
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
  readonly windows?: {
    create(options: { url: string; type: "popup"; width: number; height: number; focused?: boolean; left?: number; top?: number }): Promise<{ readonly id?: number }>;
    remove(windowId: number): Promise<void>;
    getLastFocused?(): Promise<{ readonly left?: number; readonly top?: number; readonly width?: number }>;
    readonly onRemoved: { addListener(listener: (windowId: number) => void): void };
  };
}

type ExtensionGlobal = typeof globalThis & { browser?: ExtensionApi; chrome?: ExtensionApi };

export function getExtensionApi(): ExtensionApi {
  const extensionGlobal = globalThis as ExtensionGlobal;
  const api = extensionGlobal.browser ?? extensionGlobal.chrome;
  if (api === undefined) throw new Error("WebExtension API is unavailable");
  return api;
}

export function hasExtensionApi(): boolean {
  const extensionGlobal = globalThis as ExtensionGlobal;
  return (extensionGlobal.browser ?? extensionGlobal.chrome)?.runtime?.id !== undefined;
}

export async function restrictStorage(api: ExtensionApi): Promise<void> {
  await api.storage.local.setAccessLevel?.({ accessLevel: "TRUSTED_CONTEXTS" });
  await api.storage.session?.setAccessLevel?.({ accessLevel: "TRUSTED_CONTEXTS" });
}

export async function sendExtensionMessage<T>(message: unknown): Promise<T> {
  return getExtensionApi().runtime.sendMessage(message) as Promise<T>;
}
