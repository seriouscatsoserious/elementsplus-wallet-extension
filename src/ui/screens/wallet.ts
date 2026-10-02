import { NETWORK_IDENTITY } from "../../network/identity.js";
/** Home (balances), Manage tokens, Receive. */
import type { AssetBalance } from "../../adapters/elementsplus-wasm.js";
import { encodeQr, qrPath } from "../../shared/qr.js";
import type { App } from "../lib/app.js";
import { h, svg } from "../lib/dom.js";
import { amount, avatar, displayName, shortAddress, shortId, symbol, tokenFor, unverifiedTag } from "../lib/format.js";
import { icon } from "../lib/icons.js";
import { backHeader, button, nav, titleHeader } from "../lib/parts.js";

const HIDDEN_KEY = "elementsplus.ui.hiddenAssets";

function readHidden(): Set<string> {
  try {
    const raw = localStorage.getItem(HIDDEN_KEY);
    const parsed = raw === null ? [] : JSON.parse(raw) as unknown;
    return new Set(Array.isArray(parsed) ? parsed.filter((entry): entry is string => typeof entry === "string") : []);
  } catch {
    return new Set();
  }
}

function writeHidden(hidden: Set<string>): void {
  try {
    localStorage.setItem(HIDDEN_KEY, JSON.stringify([...hidden]));
  } catch {
    // Display preference only.
  }
}

function header(app: App): HTMLElement {
  const network = app.status?.network;
  const regtest = network?.id === "elementsplus-regtest";
  return h("header", { class: "top" },
    h("button", { class: "acct", type: "button", onclick: () => app.go("receive") }, h("span", { class: "av" }, "A"), "Account 1"),
    h("span", { class: `net${regtest ? " test" : ""}`, title: network === undefined ? "" : `Genesis ${shortId(network.genesisHash, 8, 8)}` },
      h("span", { class: `dot${app.walletError !== undefined ? " bad" : ""}` }), network?.name ?? NETWORK_IDENTITY.displayName),
    h("button", { class: "ib", type: "button", "aria-label": "Lock wallet", title: "Lock", onclick: () => void app.lock() }, icon("lock")),
  );
}

function tokenRow(app: App, balance: AssetBalance): HTMLElement {
  const token = tokenFor(app.wallet?.tokens ?? {}, balance.assetId);
  const pending = BigInt(balance.amount) - BigInt(balance.confirmed);
  return h("button", { class: "tok", type: "button", onclick: () => app.go("send", { assetId: balance.assetId }) },
    avatar(token),
    h("span", { class: "nm" },
      h("strong", null, token.native ? symbol(token) : displayName(token), unverifiedTag(token)),
      h("small", { class: token.verified ? "" : "mono" }, token.native ? "Native asset" : token.verified ? token.ticker : shortId(token.assetId, 6, 4)),
    ),
    h("span", { class: "amt" },
      h("strong", null, amount(balance.amount, token)),
      h("small", { class: pending !== 0n ? "pend" : "" }, pending !== 0n ? `${amount(pending, token, { signed: true })} pending` : token.verified ? symbol(token) : "Base units"),
    ),
  );
}

export function homeScreen(app: App): HTMLElement {
  const wallet = app.wallet;
  const native = app.status?.network.policyAsset ?? "";
  const tokens = wallet?.tokens ?? {};
  const nativeToken = tokenFor(tokens, native);
  const nativeBalance = wallet?.snapshot.balances.find((entry) => entry.assetId === native)?.amount ?? "0";
  const address = wallet?.snapshot.receiveAddress ?? app.status?.primaryAddress ?? null;
  const hidden = readHidden();
  const balances = (wallet?.snapshot.balances ?? []).filter((entry) => entry.assetId === native || !hidden.has(entry.assetId));
  let list: HTMLElement;
  if (wallet === undefined && app.walletError === undefined) {
    list = h("div", { class: "list" }, [0, 1, 2].map(() => h("div", { class: "tok skeleton" }, h("span", { class: "tk" }), h("span", { class: "nm" }, h("i"), h("i")))));
  } else if (wallet === undefined) {
    list = h("div", { class: "list" }, h("div", { class: "empty" },
      h("p", null, "Couldn't reach the network"),
      h("small", { class: "muted" }, app.walletError ?? ""),
      button("Try again", () => {
        app.walletError = undefined;
        app.render();
        void app.refresh();
      }, "ghost"),
    ));
  } else {
    list = h("div", { class: "list" }, balances.map((balance) => tokenRow(app, balance)));
  }
  const dexUrl = app.status?.settings.dexUrl ?? "";
  return h("div", { class: "screen" },
    header(app),
    h("section", { class: "bal" },
      h("div", { class: `big${wallet === undefined ? " dim" : ""}` }, wallet === undefined ? "–" : amount(nativeBalance, nativeToken), " ", h("span", null, "ECX")),
      address === null ? null : h("button", { class: "addr mono", type: "button", title: "Copy address", onclick: () => void app.copy(address, "Address copied") },
        shortAddress(address), icon("copy", "sm")),
    ),
    h("div", { class: "acts" },
      h("button", { class: "act", type: "button", onclick: () => app.go("receive") }, h("span", { class: "ac" }, icon("receive")), "Receive"),
      h("button", { class: "act", type: "button", onclick: () => app.go("send") }, h("span", { class: "ac" }, icon("send")), "Send"),
      h("button", {
        class: "act",
        type: "button",
        title: dexUrl === "" ? "Set a DEX URL in Settings" : dexUrl,
        onclick: () => dexUrl === "" ? app.go("settings-network", { focus: "dexUrl" }) : app.backend.openTab(dexUrl),
      }, h("span", { class: "ac" }, icon("swap")), "Swap"),
    ),
    h("div", { class: "lh" }, h("strong", null, "Tokens"), h("button", { class: "link", type: "button", onclick: () => app.go("manage") }, "Manage")),
    list,
    nav(app, "home"),
  );
}

export function manageScreen(app: App): HTMLElement {
  const hidden = readHidden();
  const native = app.status?.network.policyAsset ?? "";
  const tokens = app.wallet?.tokens ?? {};
  const rows = (app.wallet?.snapshot.balances ?? []).filter((entry) => entry.assetId !== native).map((balance) => {
    const token = tokenFor(tokens, balance.assetId);
    const toggle = h("input", { type: "checkbox", class: "switch", "aria-label": `Show ${displayName(token)}` });
    toggle.checked = !hidden.has(balance.assetId);
    toggle.addEventListener("change", () => {
      if (toggle.checked) hidden.delete(balance.assetId);
      else hidden.add(balance.assetId);
      writeHidden(hidden);
    });
    return h("label", { class: "tok" },
      avatar(token),
      h("span", { class: "nm" },
        h("strong", null, displayName(token), unverifiedTag(token)),
        h("small", { class: "mono" }, shortId(balance.assetId, 10, 6))),
      toggle,
    );
  });
  return h("div", { class: "screen" },
    backHeader(app, "Manage tokens"),
    h("div", { class: "list" },
      rows.length === 0 ? h("div", { class: "empty" }, h("p", null, "No other tokens yet")) : rows,
      h("p", { class: "muted small pad-x" },
        "Names come from the token list in Settings and are shown only after your wallet verifies the issuance on-chain. Anything else is marked UNVERIFIED — anyone can create a token with any name."),
    ),
  );
}

export function qrSvg(text: string, pixels = 184): SVGElement {
  const code = encodeQr(text, "M");
  const border = 1;
  const size = code.size + border * 2;
  return svg("svg", { viewBox: `0 0 ${size} ${size}`, width: pixels, height: pixels, "shape-rendering": "crispEdges", role: "img", "aria-label": "Address QR code" },
    svg("rect", { width: size, height: size, fill: "#FFFFFF" }),
    svg("path", { d: qrPath(code, border), fill: "#0E0F13" }));
}

export function receiveScreen(app: App): HTMLElement {
  const address = app.wallet?.snapshot.receiveAddress ?? app.status?.primaryAddress ?? null;
  const network = app.status?.network.name ?? NETWORK_IDENTITY.displayName;
  return h("div", { class: "screen" },
    backHeader(app, "Receive"),
    h("div", { class: "body center-items" },
      h("div", { class: "qr" }, address === null ? h("div", { class: "qr-empty" }) : qrSvg(address)),
      h("div", { class: "center" }, h("strong", null, "Account 1"), h("div", { class: "muted small mt4" }, `ECX and every ${network} token`)),
      h("div", { class: "addrbox mono", "data-testid": "receive-address" }, address ?? "Loading…"),
      h("p", { class: "muted small center m0" }, `Only send assets on ${network} (Elements+). Coins sent from another chain will be lost.`),
    ),
    h("div", { class: "foot" }, button([icon("copy"), "Copy address"], () => {
      if (address !== null) void app.copy(address, "Address copied");
    })),
  );
}

export { titleHeader };
