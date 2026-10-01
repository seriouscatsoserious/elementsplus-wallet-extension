/** Generic rendering of a wallet-computed TxReview (spec §1.1). */
import type { TxReview } from "../../adapters/wallet-core.js";
import type { ApprovalView, OperationSummary } from "../../background/controller.js";
import { formatAtomic } from "../../shared/amount.js";
import type { Tokens } from "./backend.js";
import { h, type Child } from "./dom.js";
import { amountWithSymbol, avatar, shortId, symbol, tokenFor } from "./format.js";
import { icon } from "./icons.js";
import { kv } from "./parts.js";

export function reviewTitle(review: TxReview, operation: OperationSummary): string {
  if (operation.kind === "swap_offer") return "Create swap offer";
  switch (review.kind) {
    case "transfer": return "Approve send";
    case "issuance": return "Create token";
    case "swap_offer": return "Create swap offer";
    case "swap_take": return "Approve swap";
    case "offer_split": return "Prepare offer";
    case "cancel": return "Cancel offer";
  }
}

interface Leg {
  readonly assetId: string;
  readonly amount: bigint;
  readonly label: string;
}

/** Balance-change legs: from the review, or (split-then-offer) from the approved offer terms. */
export function legs(review: TxReview, operation: OperationSummary): Leg[] {
  if (operation.kind === "swap_offer" && operation.needsSplit) {
    return [
      { assetId: operation.giveAsset, amount: -BigInt(operation.giveAmount), label: "You offer" },
      { assetId: operation.wantAsset, amount: BigInt(operation.wantAmount), label: "You receive when filled" },
    ];
  }
  const pending = review.kind === "swap_offer";
  return review.balanceChanges
    .map((delta) => ({ assetId: delta.assetId, amount: BigInt(delta.amount) }))
    .filter((leg) => leg.amount !== 0n)
    .sort((a, b) => (a.amount < 0n ? -1 : 1) - (b.amount < 0n ? -1 : 1))
    .map((leg) => ({
      ...leg,
      label: leg.amount < 0n ? (pending ? "You offer" : review.kind === "transfer" ? "You send" : "You pay")
        : pending ? "You receive when filled" : review.kind === "issuance" ? "New tokens" : "You receive",
    }));
}

export function legsCard(review: TxReview, operation: OperationSummary, tokens: Tokens): HTMLElement {
  const rows = legs(review, operation);
  if (rows.length === 0) {
    return h("div", { class: "card" }, h("div", { class: "leg" }, h("span", { class: "muted" }, "No change to your balances except the network fee")));
  }
  return h("div", { class: "card" }, rows.map((leg, index) => {
    const token = tokenFor(tokens, leg.assetId);
    return h("div", { class: `leg${index > 0 ? " sep" : ""}` },
      avatar(token),
      h("span", { class: "grow" }, h("span", { class: "muted" }, leg.label), token.verified ? null : h("span", { class: "block" }, h("span", { class: "tag flush" }, "UNVERIFIED"))),
      h("strong", { class: `big-amt ${leg.amount < 0n ? "neg" : "pos"}` },
        token.verified ? amountWithSymbol(leg.amount, token, { signed: true }) : `${formatAtomic(leg.amount, 0, { signed: true })} units`),
    );
  }));
}

function rate(rows: Leg[], tokens: Tokens): string | null {
  const paid = rows.find((leg) => leg.amount < 0n);
  const got = rows.find((leg) => leg.amount > 0n);
  if (paid === undefined || got === undefined || rows.length !== 2) return null;
  const paidToken = tokenFor(tokens, paid.assetId);
  const gotToken = tokenFor(tokens, got.assetId);
  // price of 1 received unit in paid units = |paid| / got, scaled by precisions (8 decimals shown).
  const scale = 10n ** 8n;
  const numerator = -paid.amount * 10n ** BigInt(gotToken.precision) * scale;
  const denominator = got.amount * 10n ** BigInt(paidToken.precision);
  if (denominator === 0n) return null;
  const value = formatAtomic(numerator / denominator, 8, { grouping: true });
  return `1 ${symbol(gotToken)} = ${value} ${symbol(paidToken)}`;
}

const SETTLEMENT: Record<TxReview["kind"], string> = {
  transfer: "One transaction",
  issuance: "New asset · one transaction",
  swap_offer: "Signed offer · settles when taken",
  swap_take: "Atomic · one transaction",
  offer_split: "Self-transfer",
  cancel: "Spends the offered coin back to you",
};

export function factsCard(view: Pick<ApprovalView, "review" | "operation" | "tokens">, networkName: string, extra: Child[] = []): HTMLElement {
  const { review, operation, tokens } = view;
  const native = Object.values(tokens).find((token) => token.native);
  const feeToken = native ?? tokenFor(tokens, "");
  const rows: HTMLElement[] = [];
  for (const output of review.externalOutputs) {
    rows.push(kv(review.kind === "swap_take" ? "Pays maker" : "To",
      h("span", null, h("span", { class: "mono addr-full" }, output.address),
        review.externalOutputs.length > 1 || review.kind !== "transfer" ? h("small", { class: "muted block" }, amountWithSymbol(output.amount, tokenFor(tokens, output.assetId))) : null)));
  }
  const rateText = rate(legs(review, operation), tokens);
  if (rateText !== null && (review.kind === "swap_take" || review.kind === "swap_offer" || operation.kind === "swap_offer")) rows.push(kv("Rate", rateText));
  if (review.issuance !== null && operation.kind === "issuance") {
    rows.push(kv("Token", `${operation.name} · ${operation.ticker}`));
    rows.push(kv("Decimals", String(operation.precision)));
    if (review.issuance.tokenId !== null) rows.push(kv("Reissuance tokens", review.issuance.tokenAmount));
  }
  const unknown = new Set([...legs(review, operation).map((leg) => leg.assetId), ...review.externalOutputs.map((output) => output.assetId)]
    .filter((assetId) => !tokenFor(tokens, assetId).verified));
  for (const assetId of unknown) rows.push(kv("Unknown asset", h("span", { class: "mono wrap small" }, assetId)));
  rows.push(kv("Network fee", review.fee === "0" ? "None" : native === undefined ? `${review.fee} sat` : amountWithSymbol(review.fee, feeToken)));
  rows.push(kv("Network", networkName));
  rows.push(kv("Settlement", operation.kind === "swap_offer" && operation.needsSplit
    ? "Prepares an exact coin, then signs the offer"
    : SETTLEMENT[review.kind]));
  return h("dl", { class: "card m0" }, rows, extra);
}

export function detailsSection(view: Pick<ApprovalView, "review" | "reviewHash" | "expiresAt" | "operation">): HTMLElement {
  const { review } = view;
  const body = h("dl", { class: "card m0 details-body" },
    kv("Review hash", h("span", { class: "mono wrap" }, view.reviewHash)),
    kv("Kind", review.kind.replace("_", " ")),
    kv("Signature type", review.sighash),
    kv(`Signs ${review.inputsSigned.length} input${review.inputsSigned.length === 1 ? "" : "s"}`,
      h("span", { class: "mono wrap" }, review.inputsSigned.map((input) => h("span", { class: "block" }, shortId(input, 10, 6))))),
    review.foreignInputs.length === 0 ? null : kv("Other parties' inputs",
      h("span", { class: "mono wrap" }, review.foreignInputs.map((input) => h("span", { class: "block" }, shortId(input, 10, 6))))),
    review.issuance === null ? null : kv("Contract hash", h("span", { class: "mono wrap" }, review.issuance.contractHash)),
    review.issuance === null ? null : kv("Asset id", h("span", { class: "mono wrap" }, review.issuance.assetId)),
    kv("Expires", new Date(view.expiresAt).toLocaleTimeString()),
  );
  body.hidden = true;
  const toggle = h("button", { class: "disclosure", type: "button", "aria-expanded": "false", onclick: () => {
    body.hidden = !body.hidden;
    toggle.setAttribute("aria-expanded", String(!body.hidden));
    toggle.classList.toggle("open", !body.hidden);
  } }, "Transaction details", icon("chevronDown"));
  return h("div", { class: "details" }, toggle, body);
}

export function checkedNote(offer = false): HTMLElement {
  return h("p", { class: "note" }, icon("shield", "sm"), offer
    ? "Checked by your wallet: the signed offer can only be filled on exactly these terms."
    : "Checked by your wallet: these are the only balance changes in this transaction.");
}
