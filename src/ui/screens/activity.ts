/** Activity list from the explorer (display-only, unverified data). */
import type { ActivityEntry } from "../../network/activity.js";
import type { App } from "../lib/app.js";
import type { Tokens } from "../lib/backend.js";
import { h } from "../lib/dom.js";
import { amountWithSymbol, dayLabel, displayName, explorerTxUrl, shortAddress, symbol, tokenFor } from "../lib/format.js";
import { icon, type IconName } from "../lib/icons.js";
import { button, nav, titleHeader } from "../lib/parts.js";

interface ActivityState {
  entries: readonly ActivityEntry[] | undefined;
  tokens: Tokens;
  error: string | undefined;
  loading: boolean;
}

const state: ActivityState = { entries: undefined, tokens: {}, error: undefined, loading: false };

async function load(app: App): Promise<void> {
  if (state.loading) return;
  state.loading = true;
  try {
    const history = await app.backend.history();
    state.entries = history.entries;
    state.tokens = history.tokens;
    state.error = undefined;
  } catch (error) {
    state.error = app.errorMessage(error);
  } finally {
    state.loading = false;
  }
  app.rerenderIf("activity");
}

const TITLES: Record<ActivityEntry["kind"], [string, IconName]> = {
  received: ["Received", "receive"],
  sent: ["Sent", "send"],
  swap: ["Swapped", "swap"],
  issuance: ["Issued token", "plus"],
  self: ["Moved between your addresses", "swap"],
};

function row(app: App, entry: ActivityEntry, tokens: Tokens): HTMLElement {
  const [title, glyph] = TITLES[entry.kind];
  const merged = { ...app.wallet?.tokens, ...tokens };
  const primary = entry.kind === "swap" || entry.kind === "received" || entry.kind === "issuance"
    ? entry.deltas.find((delta) => !delta.amount.startsWith("-")) ?? entry.deltas[0]
    : entry.deltas.find((delta) => delta.amount.startsWith("-")) ?? entry.deltas[0];
  const secondary = entry.deltas.find((delta) => delta !== primary);
  let sub: string;
  if (entry.kind === "swap" && entry.deltas.length >= 2) {
    const paid = entry.deltas.find((delta) => delta.amount.startsWith("-"));
    const got = entry.deltas.find((delta) => !delta.amount.startsWith("-"));
    sub = paid !== undefined && got !== undefined ? `${symbol(tokenFor(merged, paid.assetId))} → ${symbol(tokenFor(merged, got.assetId))}` : "Swap";
  } else if (entry.kind === "issuance" && entry.issuedAssetId !== null) {
    const token = tokenFor(merged, entry.issuedAssetId);
    sub = token.verified ? `${token.name} · ${token.ticker}` : displayName(token);
  } else if (entry.counterparty !== null) {
    sub = `${entry.kind === "received" ? "From" : "To"} ${shortAddress(entry.counterparty)}`;
  } else {
    sub = entry.kind === "self" ? "Self-transfer" : "";
  }
  const positive = primary !== undefined && !primary.amount.startsWith("-");
  const statusText = entry.confirmed ? "Confirmed" : "In mempool";
  const explorer = app.status?.settings.explorerUrl;
  return h("button", {
    class: "tx",
    type: "button",
    title: "Open in explorer",
    onclick: () => { if (explorer !== undefined) app.backend.openTab(explorerTxUrl(explorer, entry.txid)); },
  },
    h("span", { class: `ic${entry.confirmed ? "" : " pend"}` }, icon(entry.confirmed ? glyph : "activity")),
    h("span", { class: "nm" }, h("strong", null, title), h("small", { class: entry.counterparty !== null && entry.kind !== "swap" ? "mono" : "" }, sub)),
    h("span", { class: "amt" },
      primary === undefined
        ? h("strong", { class: "muted" }, entry.complete ? "—" : "Hidden amount")
        : h("strong", { class: positive ? "pos" : "" }, amountWithSymbol(primary.amount, tokenFor(merged, primary.assetId), { signed: true })),
      h("small", { class: entry.confirmed ? "" : "pend" },
        secondary !== undefined && entry.confirmed ? amountWithSymbol(secondary.amount, tokenFor(merged, secondary.assetId), { signed: true }) : statusText),
    ),
  );
}

export function activityScreen(app: App): HTMLElement {
  if (state.entries === undefined && state.error === undefined) void load(app);
  const groups = new Map<string, ActivityEntry[]>();
  for (const entry of state.entries ?? []) {
    const label = entry.confirmed && entry.blockTime !== null ? dayLabel(entry.blockTime) : "Pending";
    const list = groups.get(label) ?? [];
    list.push(entry);
    groups.set(label, list);
  }
  let content: HTMLElement[];
  if (state.entries === undefined && state.error === undefined) {
    content = [h("div", { class: "grp" }, "Loading"), ...[0, 1, 2, 3].map(() => h("div", { class: "tx skeleton" }, h("span", { class: "ic" }), h("span", { class: "nm" }, h("i"), h("i"))))];
  } else if (state.error !== undefined) {
    content = [h("div", { class: "empty" }, h("p", null, "Couldn't load activity"), h("small", { class: "muted" }, state.error),
      button("Try again", () => { state.error = undefined; app.render(); }, "ghost"))];
  } else if ((state.entries ?? []).length === 0) {
    content = [h("div", { class: "empty" }, icon("activity"), h("p", null, "No activity yet"), h("small", { class: "muted" }, "Transactions to and from this wallet will show up here."))];
  } else {
    content = [...groups.entries()].flatMap(([label, entries]) => [
      h("div", { class: "grp" }, label),
      ...entries.map((entry) => row(app, entry, state.tokens)),
    ]);
    content.push(h("p", { class: "muted tiny pad-x" }, "History is read from your explorer and is not independently verified."));
  }
  return h("div", { class: "screen" },
    titleHeader("Activity", h("button", {
      class: "ib",
      type: "button",
      "aria-label": "Refresh",
      title: "Refresh",
      onclick: () => {
        state.entries = undefined;
        state.error = undefined;
        app.render();
      },
    }, icon("refresh"))),
    h("div", { class: "list" }, content),
    nav(app, "activity"),
  );
}

/** Test/preview hook. */
export function setActivityState(entries: readonly ActivityEntry[], tokens: Tokens): void {
  state.entries = entries;
  state.tokens = tokens;
  state.error = undefined;
}
