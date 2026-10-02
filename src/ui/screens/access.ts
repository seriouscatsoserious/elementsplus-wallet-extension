import { NETWORK_IDENTITY } from "../../network/identity.js";
/** Lock gate and onboarding (create / import / restore → phrase → confirm → password). */
import type { App, ScreenParams } from "../lib/app.js";
import { h } from "../lib/dom.js";
import { icon } from "../lib/icons.js";
import { backHeader, brandMark, busy, button, errorLine, showError } from "../lib/parts.js";

export const MIN_PASSWORD_LENGTH = 12;

export function lockScreen(app: App, params: ScreenParams): HTMLElement {
  const password = h("input", { class: "field", type: "password", placeholder: "Password", autocomplete: "current-password", autofocus: true, "aria-label": "Password" });
  const error = errorLine();
  const unlock = h("button", { class: "btn primary", type: "submit" }, "Unlock");
  const submit = async () => {
    showError(error, null);
    if (password.value.length === 0) {
      showError(error, "Enter your password");
      return;
    }
    try {
      await busy(unlock, "Unlocking", () => app.backend.unlock(password.value));
      password.value = "";
      app.status = await app.backend.status();
      const onUnlock = params["onUnlock"];
      if (typeof onUnlock === "function") (onUnlock as () => void)();
      else app.home();
    } catch (failure) {
      showError(error, app.errorMessage(failure));
      password.select();
    }
  };
  const form = h("form", { class: "stack", onsubmit: (event: Event) => { event.preventDefault(); void submit(); } },
    h("label", null, h("span", { class: "vh" }, "Password"), password),
    error,
    unlock,
    params["hideRestore"] === true ? null : h("button", {
      class: "link center",
      type: "button",
      onclick: () => {
        app.draft = { mode: "restore", mnemonic: "" };
        app.go("import");
      },
    }, "Forgot password? Restore from recovery phrase"),
  );
  if (typeof params["error"] === "string") showError(error, params["error"]);
  return h("div", { class: "screen pad between" },
    h("div", { class: "hero" },
      brandMark("lg"),
      h("div", { class: "center" },
        h("h1", { class: "title" }, typeof params["title"] === "string" ? params["title"] : "Welcome back"),
        h("p", { class: "muted sub" }, typeof params["subtitle"] === "string" ? params["subtitle"] : "Elements+ Wallet"),
      ),
    ),
    form,
  );
}

export function welcomeScreen(app: App): HTMLElement {
  const error = errorLine();
  const create = button("Create a new wallet", () => void (async () => {
    try {
      const mnemonic = await busy(create, "Generating", () => app.backend.generateMnemonic());
      app.draft = { mode: "create", mnemonic };
      app.go("show-phrase");
    } catch (failure) {
      showError(error, app.errorMessage(failure));
    }
  })());
  return h("div", { class: "screen pad between" },
    h("div", { class: "hero" },
      brandMark("lg"),
      h("div", { class: "center" },
        h("h1", { class: "title" }, "Elements+ Wallet"),
        h("p", { class: "muted sub" }, `A self-custodial wallet for ${app.status?.network.name ?? NETWORK_IDENTITY.displayName}`),
      ),
    ),
    h("div", { class: "stack" },
      error,
      create,
      button("I already have a wallet", () => {
        app.draft = { mode: "import", mnemonic: "" };
        app.go("import");
      }, "ghost"),
    ),
  );
}

function words(mnemonic: string): string[] {
  return mnemonic.split(" ");
}

export function showPhraseScreen(app: App): HTMLElement {
  const draft = app.draft;
  if (draft === undefined) return welcomeScreen(app);
  let revealed = false;
  const grid = h("ol", { class: "words blurred", "aria-label": "Recovery phrase" },
    words(draft.mnemonic).map((word, index) => h("li", null, h("span", { class: "n" }, String(index + 1)), h("span", { class: "w mono" }, word))));
  const cover = h("button", { class: "cover", type: "button", onclick: () => {
    revealed = true;
    grid.classList.remove("blurred");
    cover.remove();
    next.disabled = false;
  } }, icon("eye"), "Click to reveal your phrase");
  const next = button("I've written it down", () => app.go("confirm-phrase"));
  next.disabled = !revealed;
  return h("div", { class: "screen" },
    backHeader(app, "Recovery phrase", () => {
      app.draft = undefined;
      app.back();
    }),
    h("div", { class: "body" },
      h("p", { class: "muted small" }, "Write these 12 words down in order and keep them offline. Anyone with this phrase can take your funds."),
      h("div", { class: "words-wrap" }, grid, cover),
    ),
    h("div", { class: "foot" }, next),
  );
}

function pickPositions(count: number, total: number): number[] {
  const chosen = new Set<number>();
  const random = new Uint32Array(1);
  while (chosen.size < count) {
    crypto.getRandomValues(random);
    chosen.add(random[0]! % total);
  }
  return [...chosen].sort((a, b) => a - b);
}

export function confirmPhraseScreen(app: App): HTMLElement {
  const draft = app.draft;
  if (draft === undefined) return welcomeScreen(app);
  const list = words(draft.mnemonic);
  const positions = pickPositions(3, list.length);
  const error = errorLine();
  const inputs = positions.map((position) => h("input", {
    class: "field mono",
    autocomplete: "off",
    autocapitalize: "off",
    spellcheck: "false",
    "aria-label": `Word #${position + 1}`,
    placeholder: `Word #${position + 1}`,
  }));
  inputs[0]?.setAttribute("autofocus", "");
  const next = button("Continue", () => {
    const ok = positions.every((position, index) => inputs[index]!.value.trim().toLowerCase() === list[position]);
    if (!ok) {
      showError(error, "Those words don't match your phrase. Check the order and try again.");
      return;
    }
    app.go("password");
  });
  return h("div", { class: "screen" },
    backHeader(app, "Confirm phrase"),
    h("form", { class: "body", onsubmit: (event: Event) => { event.preventDefault(); next.click(); } },
      h("p", { class: "muted small" }, "Enter the following words from your recovery phrase."),
      positions.map((position, index) => h("label", null, h("span", { class: "label" }, `Word #${position + 1}`), inputs[index]!)),
      error,
      h("button", { type: "submit", hidden: true }),
    ),
    h("div", { class: "foot" }, next),
  );
}

export function importScreen(app: App): HTMLElement {
  const draft = app.draft ?? { mode: "import" as const, mnemonic: "" };
  app.draft = draft;
  const phrase = h("textarea", {
    class: "field area mono",
    rows: 4,
    autocomplete: "off",
    autocapitalize: "off",
    spellcheck: "false",
    placeholder: "Enter your 12 or 24-word recovery phrase",
    "aria-label": "Recovery phrase",
    autofocus: true,
  });
  const error = errorLine();
  const next = button("Continue", () => void (async () => {
    const mnemonic = phrase.value.normalize("NFKD").trim().toLowerCase().replace(/\s+/gu, " ");
    if (![12, 15, 18, 21, 24].includes(mnemonic.split(" ").length)) {
      showError(error, "A recovery phrase has 12 or 24 words");
      return;
    }
    const valid = await busy(next, "Checking", () => app.backend.validateMnemonic(mnemonic)).catch(() => false);
    if (!valid) {
      showError(error, "That recovery phrase is not valid. Check each word.");
      return;
    }
    draft.mnemonic = mnemonic;
    phrase.value = "";
    app.go("password");
  })());
  return h("div", { class: "screen" },
    backHeader(app, draft.mode === "restore" ? "Restore wallet" : "Import wallet", () => {
      app.draft = undefined;
      app.back();
    }),
    h("div", { class: "body" },
      draft.mode === "restore"
        ? h("p", { class: "notice warn" }, icon("alert"), h("span", null, "This replaces the wallet on this device. Make sure you have the right recovery phrase."))
        : h("p", { class: "muted small" }, "Restore an existing wallet with its recovery phrase. It stays encrypted on this device."),
      phrase,
      error,
    ),
    h("div", { class: "foot" }, next),
  );
}

export function passwordScreen(app: App): HTMLElement {
  const draft = app.draft;
  if (draft === undefined || draft.mnemonic === "") return welcomeScreen(app);
  const first = h("input", { class: "field", type: "password", placeholder: "New password", autocomplete: "new-password", autofocus: true, "aria-label": "New password" });
  const second = h("input", { class: "field", type: "password", placeholder: "Confirm password", autocomplete: "new-password", "aria-label": "Confirm password" });
  const error = errorLine();
  const finish = button(draft.mode === "create" ? "Create wallet" : "Restore wallet", () => void (async () => {
    showError(error, null);
    if (new TextEncoder().encode(first.value).length < MIN_PASSWORD_LENGTH) {
      showError(error, `Use at least ${MIN_PASSWORD_LENGTH} characters`);
      return;
    }
    if (first.value !== second.value) {
      showError(error, "Passwords don't match");
      return;
    }
    try {
      await busy(finish, "Encrypting", () => app.backend.createVault(first.value, draft.mnemonic, draft.mode === "restore"));
      first.value = "";
      second.value = "";
      app.draft = undefined;
      app.status = await app.backend.status();
      app.home();
    } catch (failure) {
      showError(error, app.errorMessage(failure));
    }
  })());
  return h("div", { class: "screen" },
    backHeader(app, "Set a password"),
    h("form", { class: "body", onsubmit: (event: Event) => { event.preventDefault(); finish.click(); } },
      h("p", { class: "muted small" }, "This password unlocks the wallet on this device only. It can't recover your funds — your phrase can."),
      first,
      second,
      error,
      h("button", { type: "submit", hidden: true }),
    ),
    h("div", { class: "foot" }, finish),
  );
}
