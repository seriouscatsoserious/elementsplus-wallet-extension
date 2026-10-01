/** Settings: network & endpoints, connected sites, auto-lock, recovery phrase, advanced pins. */
import type { ConnectedSite } from "../../background/settings.js";
import type { App, ScreenParams } from "../lib/app.js";
import { h, type Child } from "../lib/dom.js";
import { shortId } from "../lib/format.js";
import { icon, type IconName } from "../lib/icons.js";
import { backHeader, busy, button, errorLine, kv, nav, showError, titleHeader } from "../lib/parts.js";

const AUTO_LOCK = [1, 5, 15, 30, 60] as const;

function row(glyph: IconName, title: string, value: Child, onClick: () => void): HTMLElement {
  return h("button", { class: "srow", type: "button", onclick: onClick },
    h("span", { class: "ic" }, icon(glyph)),
    h("span", { class: "nm" }, h("strong", null, title), h("small", { class: "muted" }, value)),
    icon("forward", "sm muted"),
  );
}

let sitesCache: readonly ConnectedSite[] | undefined;

export function settingsScreen(app: App): HTMLElement {
  const status = app.status;
  const settings = status?.settings;
  if (sitesCache === undefined) {
    void app.backend.sites().then((sites) => {
      sitesCache = sites;
      app.rerenderIf("settings");
    }).catch(() => undefined);
  }
  const lockSelect = h("select", { class: "select", "aria-label": "Auto-lock timer" },
    AUTO_LOCK.map((minutes) => h("option", { value: minutes }, minutes === 60 ? "1 hour" : `${minutes} min`)));
  lockSelect.value = String(settings?.autoLockMinutes ?? 15);
  lockSelect.addEventListener("change", () => void (async () => {
    try {
      const updated = await app.backend.updateSettings({ autoLockMinutes: Number(lockSelect.value) });
      if (app.status !== undefined) app.status = { ...app.status, settings: updated.settings };
      app.toast("Auto-lock updated");
    } catch (failure) {
      app.toast(app.errorMessage(failure));
    }
  })());
  let explorerHost = "";
  try {
    explorerHost = settings === undefined ? "" : new URL(settings.explorerUrl).host;
  } catch {
    explorerHost = settings?.explorerUrl ?? "";
  }
  return h("div", { class: "screen" },
    titleHeader("Settings"),
    h("div", { class: "list" },
      h("div", { class: "grp" }, "Network"),
      row("globe", "Network & endpoints", `${status?.network.name ?? "ECX Alpha"} · ${explorerHost}`, () => app.go("settings-network")),
      row("link", "Connected sites", sitesCache === undefined ? "…" : sitesCache.length === 0 ? "None" : `${sitesCache.length} site${sitesCache.length === 1 ? "" : "s"}`, () => app.go("settings-sites")),
      h("div", { class: "grp" }, "Security"),
      h("label", { class: "srow" },
        h("span", { class: "ic" }, icon("lock")),
        h("span", { class: "nm" }, h("strong", null, "Auto-lock"), h("small", { class: "muted" }, "Lock after this much inactivity")),
        lockSelect),
      row("key", "Recovery phrase", "Reveal with your password", () => app.go("settings-phrase")),
      row("sliders", "Advanced", "Network pins and build", () => app.go("settings-advanced")),
      h("div", { class: "pad-x" }, button([icon("lock"), "Lock wallet"], () => void app.lock(), "ghost")),
    ),
    nav(app, "settings"),
  );
}

export function networkSettingsScreen(app: App, params: ScreenParams): HTMLElement {
  const settings = app.status?.settings;
  const field = (name: string, label: string, value: string, placeholder: string, hint: string) => {
    const input = h("input", { class: "field mono sm", name, value, placeholder, spellcheck: "false", autocomplete: "off", "aria-label": label, autofocus: params["focus"] === name });
    return { input, element: h("label", null, h("span", { class: "label" }, label), input, h("small", { class: "muted hint" }, hint)) };
  };
  const explorer = field("explorerUrl", "Explorer (Esplora)", settings?.explorerUrl ?? "", "https://…", "Balances and history come from here. The wallet checks it serves the pinned network.");
  const registry = field("registryUrl", "Token list URL", settings?.registryUrl ?? "", "https://dex.example/api/assets", "Token names are shown only after on-chain verification.");
  const dex = field("dexUrl", "DEX URL", settings?.dexUrl ?? "", "https://dex.example", "Opened by the Swap button.");
  const error = errorLine();
  const save = button("Save", () => void (async () => {
    showError(error, null);
    try {
      const result = await busy(save, "Saving", () => app.backend.updateSettings({
        explorerUrl: explorer.input.value.trim(),
        registryUrl: registry.input.value.trim(),
        dexUrl: dex.input.value.trim(),
      }));
      if (app.status !== undefined) app.status = { ...app.status, settings: result.settings, unlocked: result.unlocked };
      if (!result.unlocked) {
        app.toast("Explorer changed — unlock again");
        await app.lockedOut();
        return;
      }
      app.toast("Saved");
      app.back();
      void app.refresh();
    } catch (failure) {
      showError(error, app.errorMessage(failure));
    }
  })());
  const reset = () => {
    explorer.input.value = app.status?.network.defaultExplorerUrl ?? "";
    registry.input.value = "";
    dex.input.value = "";
  };
  return h("div", { class: "screen" },
    backHeader(app, "Network & endpoints"),
    h("form", { class: "body scroll", onsubmit: (event: Event) => { event.preventDefault(); save.click(); } },
      h("dl", { class: "card m0" }, kv("Network", app.status?.network.name ?? "ECX Alpha")),
      explorer.element,
      registry.element,
      dex.element,
      h("button", { class: "link", type: "button", onclick: reset }, "Reset to defaults"),
      error,
    ),
    h("div", { class: "foot" }, save),
  );
}

export function sitesScreen(app: App): HTMLElement {
  const list = h("div", { class: "list" });
  const render = (sites: readonly ConnectedSite[]) => {
    sitesCache = sites;
    list.replaceChildren(...(sites.length === 0
      ? [h("div", { class: "empty" }, icon("link"), h("p", null, "No connected sites"), h("small", { class: "muted" }, "Sites you connect to will appear here."))]
      : sites.map((site) => h("div", { class: "tok" },
        h("span", { class: "tk unknown" }, site.origin.replace(/^https?:\/\//u, "").slice(0, 1).toUpperCase()),
        h("span", { class: "nm" }, h("strong", { class: "mono ellipsis" }, site.origin.replace(/^https:\/\//u, "")), h("small", { class: "muted" }, `Connected ${new Date(site.connectedAt).toLocaleDateString()}`)),
        h("button", { class: "pill-btn", type: "button", onclick: () => void (async () => {
          await app.backend.revokeSite(site.origin);
          render(await app.backend.sites());
          app.toast("Disconnected");
        })() }, "Disconnect"),
      ))));
  };
  render(sitesCache ?? []);
  void app.backend.sites().then(render).catch(() => undefined);
  return h("div", { class: "screen" }, backHeader(app, "Connected sites"), list);
}

export function phraseScreen(app: App): HTMLElement {
  const body = h("div", { class: "body" });
  const password = h("input", { class: "field", type: "password", placeholder: "Password", autocomplete: "current-password", autofocus: true, "aria-label": "Password" });
  const error = errorLine();
  const reveal = h("button", { class: "btn primary", type: "submit" }, "Reveal phrase");
  const submit = async () => {
    showError(error, null);
    try {
      const mnemonic = await busy(reveal, "Checking", () => app.backend.revealPhrase(password.value));
      password.value = "";
      body.replaceChildren(
        h("p", { class: "notice warn" }, icon("alert"), h("span", null, "Never share this phrase. Anyone who has it controls your funds.")),
        h("ol", { class: "words", "aria-label": "Recovery phrase" }, mnemonic.split(" ").map((word, index) => h("li", null, h("span", { class: "n" }, String(index + 1)), h("span", { class: "w mono" }, word)))),
      );
      reveal.remove();
    } catch (failure) {
      showError(error, app.errorMessage(failure));
    }
  };
  body.append(
    h("p", { class: "muted small" }, "Enter your password to show the recovery phrase for this wallet."),
    h("form", { class: "stack", onsubmit: (event: Event) => { event.preventDefault(); void submit(); } }, password, error, reveal),
  );
  return h("div", { class: "screen" }, backHeader(app, "Recovery phrase"), body);
}

export function advancedScreen(app: App): HTMLElement {
  const network = app.status?.network;
  return h("div", { class: "screen" },
    backHeader(app, "Advanced"),
    h("div", { class: "body scroll" },
      h("p", { class: "muted small m0" }, "This wallet only signs for the network pinned below. An explorer serving a different chain is refused."),
      h("dl", { class: "card m0" },
        kv("Network", network?.name ?? ""),
        kv("Genesis", h("span", { class: "mono wrap" }, network?.genesisHash ?? "")),
        kv("Policy asset", h("span", { class: "mono wrap" }, network?.policyAsset ?? "")),
        kv("Outputs", "Explicit only"),
        kv("Build", network?.mode === "elementsplus-regtest" ? "Local regtest" : "Production"),
      ),
      h("p", { class: "muted tiny m0" }, `Explorer: ${shortId(app.status?.settings.explorerUrl ?? "", 40, 0)}`),
    ),
  );
}
