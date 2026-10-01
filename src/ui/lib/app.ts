/** Minimal screen router + shared state for the wallet popup. */
import type { WalletSnapshot } from "../../adapters/elementsplus-wasm.js";
import type { ApprovalView } from "../../background/controller.js";
import { BackendError, type Backend, type Tokens, type WalletStatus } from "./backend.js";
import { h, replaceChildren } from "./dom.js";

export type ScreenName =
  | "loading" | "lock" | "welcome" | "show-phrase" | "confirm-phrase" | "import" | "password"
  | "home" | "manage" | "activity" | "send" | "confirm" | "sent" | "receive"
  | "settings" | "settings-network" | "settings-sites" | "settings-phrase" | "settings-advanced";

export type ScreenParams = Record<string, unknown>;
export type Screen = (app: App, params: ScreenParams) => HTMLElement;

export interface OnboardingDraft {
  mode: "create" | "import" | "restore";
  mnemonic: string;
}

const TOUCH_INTERVAL_MS = 15_000;
const TABS = new Set<ScreenName>(["home", "activity", "settings"]);

export class App {
  readonly root: HTMLElement;
  readonly backend: Backend;
  readonly screens: Record<ScreenName, Screen>;
  status: WalletStatus | undefined;
  wallet: { snapshot: WalletSnapshot; tokens: Tokens } | undefined;
  walletError: string | undefined;
  draft: OnboardingDraft | undefined;
  pendingApproval: ApprovalView | undefined;
  #stack: { name: ScreenName; params: ScreenParams }[] = [];
  #lastTouch = 0;
  #toast: HTMLElement | undefined;
  #refreshing: Promise<void> | undefined;

  constructor(root: HTMLElement, backend: Backend, screens: Record<ScreenName, Screen>) {
    this.root = root;
    this.backend = backend;
    this.screens = screens;
  }

  get current(): ScreenName {
    return this.#stack.at(-1)?.name ?? "loading";
  }

  async start(initial?: { name: ScreenName; params?: ScreenParams }): Promise<void> {
    this.go("loading");
    const activity = () => {
      if (this.status?.unlocked !== true || Date.now() - this.#lastTouch < TOUCH_INTERVAL_MS) return;
      this.#lastTouch = Date.now();
      void this.backend.touch().catch(() => undefined);
    };
    document.addEventListener("pointerdown", activity, { passive: true });
    document.addEventListener("keydown", activity, { passive: true });
    try {
      this.status = await this.backend.status();
    } catch (error) {
      this.replace("lock", { error: this.errorMessage(error) });
      return;
    }
    if (initial !== undefined) {
      this.reset(initial.name, initial.params ?? {});
      return;
    }
    this.home();
  }

  /** Route to the right entry screen for the current lock state. */
  home(): void {
    if (this.status === undefined || !this.status.initialized) this.reset("welcome");
    else if (!this.status.unlocked) this.reset("lock");
    else {
      this.reset("home");
      void this.refresh();
    }
  }

  go(name: ScreenName, params: ScreenParams = {}): void {
    if (TABS.has(name)) this.#stack = [];
    this.#stack.push({ name, params });
    this.render();
  }

  replace(name: ScreenName, params: ScreenParams = {}): void {
    this.#stack.pop();
    this.#stack.push({ name, params });
    this.render();
  }

  reset(name: ScreenName, params: ScreenParams = {}): void {
    this.#stack = [{ name, params }];
    this.render();
  }

  back(): void {
    if (this.#stack.length > 1) this.#stack.pop();
    else this.#stack = [{ name: this.status?.unlocked === true ? "home" : "lock", params: {} }];
    this.render();
  }

  render(): void {
    const top = this.#stack.at(-1) ?? { name: "loading" as const, params: {} };
    const screen = this.screens[top.name];
    const element = screen(this, top.params);
    this.root.dataset["screen"] = top.name;
    replaceChildren(this.root, element);
    if (this.#toast !== undefined) this.root.append(this.#toast);
    element.querySelector<HTMLElement>("[autofocus]")?.focus();
  }

  /** Re-render only if the given screen is still on top (after async loads). */
  rerenderIf(name: ScreenName): void {
    if (this.current === name) this.render();
  }

  async refresh(): Promise<void> {
    this.#refreshing ??= (async () => {
      try {
        this.wallet = await this.backend.snapshot();
        this.walletError = undefined;
      } catch (error) {
        if (error instanceof BackendError && error.code === "LOCKED") {
          await this.lockedOut();
          return;
        }
        this.walletError = this.errorMessage(error);
      } finally {
        this.#refreshing = undefined;
      }
      if (this.current === "home" || this.current === "send" || this.current === "receive" || this.current === "manage") this.render();
    })();
    return this.#refreshing;
  }

  async lockedOut(): Promise<void> {
    this.wallet = undefined;
    try {
      this.status = await this.backend.status();
    } catch {
      // keep previous status
    }
    this.reset("lock");
  }

  async lock(): Promise<void> {
    await this.backend.lock().catch(() => undefined);
    this.wallet = undefined;
    if (this.status !== undefined) this.status = { ...this.status, unlocked: false };
    this.reset("lock");
  }

  errorMessage(error: unknown): string {
    if (error instanceof BackendError && error.code === "LOCKED") return "Wallet is locked";
    return error instanceof Error && error.message !== "" ? error.message : "Something went wrong";
  }

  toast(text: string): void {
    this.#toast?.remove();
    const toast = h("div", { class: "toast", role: "status" }, text);
    this.#toast = toast;
    this.root.append(toast);
    setTimeout(() => {
      if (this.#toast === toast) {
        toast.remove();
        this.#toast = undefined;
      }
    }, 1_600);
  }

  async copy(text: string, label = "Copied"): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
      this.toast(label);
    } catch {
      this.toast("Copy failed");
    }
  }
}
