/** Send → Confirm → Sent. */
import type { ApprovalResult } from "../../background/controller.js";
import { resolveEcxAlphaAddress } from "../../network/ecx-alpha.js";
import {
  AmountError,
  atomicToDecimalInput,
  DEFAULT_FEE_PRESET,
  estimateFeeAtomic,
  FEE_PRESETS,
  parseDecimalAmount,
  type FeePreset,
} from "../../shared/amount.js";
import type { App, ScreenParams } from "../lib/app.js";
import { h } from "../lib/dom.js";
import { amount, amountWithSymbol, avatar, displayName, explorerTxUrl, symbol, tokenFor } from "../lib/format.js";
import { icon } from "../lib/icons.js";
import { backHeader, busy, button, errorLine, kv, showError } from "../lib/parts.js";
import { detailsSection } from "../lib/review.js";

interface SendDraft {
  recipient: string;
  assetId: string;
  amount: string;
  preset: FeePreset;
}

let draft: SendDraft | undefined;

export function resetSendDraft(): void {
  draft = undefined;
}

export function sendScreen(app: App, params: ScreenParams): HTMLElement {
  const native = app.status?.network.policyAsset ?? "";
  const tokens = app.wallet?.tokens ?? {};
  const balances = app.wallet?.snapshot.balances ?? [];
  if (draft === undefined || (typeof params["assetId"] === "string" && params["fresh"] !== false)) {
    draft = { recipient: draft?.recipient ?? "", assetId: typeof params["assetId"] === "string" ? params["assetId"] : native, amount: "", preset: DEFAULT_FEE_PRESET };
    params["fresh"] = false;
  }
  const current = draft;
  const token = tokenFor(tokens, current.assetId);
  const balance = balances.find((entry) => entry.assetId === current.assetId);
  const nativeBalance = balances.find((entry) => entry.assetId === native);
  const feeEstimate = () => estimateFeeAtomic(nativeBalance?.utxoCount ?? 1, FEE_PRESETS[current.preset].satPerVbyte);
  const nativeToken = tokenFor(tokens, native);

  const to = h("input", {
    class: "field mono",
    placeholder: `${app.status?.network.name ?? "ECX Alpha"} address`,
    autocomplete: "off",
    spellcheck: "false",
    "aria-label": "Recipient address",
    value: current.recipient,
    autofocus: current.recipient === "",
  });
  to.addEventListener("input", () => { current.recipient = to.value.trim(); });

  const amountInput = h("input", { class: "amount-input", inputmode: "decimal", placeholder: "0", "aria-label": "Amount", value: current.amount, autocomplete: "off" });
  const sizeAmount = () => {
    const length = Math.max(1, amountInput.value.length);
    amountInput.classList.toggle("long", length > 9);
    amountInput.setAttribute("size", String(Math.min(14, length + 1)));
  };
  amountInput.addEventListener("input", () => {
    current.amount = amountInput.value;
    sizeAmount();
  });
  sizeAmount();

  const feeLabel = h("span", null);
  const updateFee = () => {
    feeLabel.textContent = `≈ ${amountWithSymbol(feeEstimate(), nativeToken, { minFraction: 0 })} · ${FEE_PRESETS[current.preset].label}`;
  };
  updateFee();
  const feeMenu = h("div", { class: "menu", role: "menu", hidden: true },
    (Object.keys(FEE_PRESETS) as FeePreset[]).map((preset) => h("button", {
      type: "button",
      role: "menuitemradio",
      class: preset === current.preset ? "on" : "",
      "aria-checked": String(preset === current.preset),
      onclick: () => {
        current.preset = preset;
        feeMenu.hidden = true;
        for (const item of feeMenu.querySelectorAll("button")) item.classList.toggle("on", item.dataset["preset"] === preset);
        updateFee();
      },
      "data-preset": preset,
    }, h("span", null, FEE_PRESETS[preset].label), h("small", { class: "muted" }, `${FEE_PRESETS[preset].satPerVbyte} sat/vB`))),
  );

  const error = errorLine();
  const useMax = h("button", { class: "max", type: "button", onclick: () => {
    if (balance === undefined) return;
    let max = BigInt(balance.amount);
    if (current.assetId === native) max -= feeEstimate();
    if (max < 0n) max = 0n;
    amountInput.value = atomicToDecimalInput(max, token.precision);
    current.amount = amountInput.value;
    sizeAmount();
  } }, "Use max");

  const assetMenu = h("div", { class: "menu wide", role: "menu", hidden: true },
    balances.map((entry) => {
      const option = tokenFor(tokens, entry.assetId);
      return h("button", { type: "button", role: "menuitem", onclick: () => {
        current.assetId = entry.assetId;
        current.amount = "";
        app.render();
      } }, avatar(option, "sm"), h("span", { class: "grow" }, option.native ? symbol(option) : displayName(option)), h("small", { class: "muted" }, amount(entry.amount, option)));
    }),
  );

  const next = button("Continue", () => void (async () => {
    showError(error, null);
    let recipient: string;
    try {
      const resolved = resolveEcxAlphaAddress(to.value.trim());
      if (resolved.confidential) throw new Error("confidential");
      recipient = resolved.canonical;
    } catch {
      showError(error, `Enter a valid ${app.status?.network.name ?? "ECX Alpha"} address`);
      to.focus();
      return;
    }
    let atomic: bigint;
    try {
      atomic = parseDecimalAmount(amountInput.value, token.precision);
      if (atomic === 0n) throw new AmountError("Enter an amount greater than zero");
    } catch (failure) {
      showError(error, failure instanceof Error ? failure.message : "Invalid amount");
      amountInput.focus();
      return;
    }
    if (balance !== undefined && atomic > BigInt(balance.amount)) {
      showError(error, "Amount exceeds your balance");
      return;
    }
    try {
      const view = await busy(next, "Preparing", () => app.backend.prepareTransfer({
        assetId: current.assetId,
        recipient,
        amount: atomic.toString(),
        feeRate: FEE_PRESETS[current.preset].satPerVbyte,
      }));
      app.pendingApproval = view;
      app.go("confirm");
    } catch (failure) {
      showError(error, app.errorMessage(failure));
    }
  })());

  return h("div", { class: "screen" },
    backHeader(app, "Send", () => {
      draft = undefined;
      app.back();
    }),
    h("form", { class: "body", onsubmit: (event: Event) => { event.preventDefault(); next.click(); } },
      h("label", null, h("span", { class: "label" }, "To"), to),
      h("div", { class: "rel" },
        h("span", { class: "label" }, "Asset"),
        h("button", { class: "pick", type: "button", "aria-haspopup": "menu", onclick: () => { assetMenu.hidden = !assetMenu.hidden; } },
          avatar(token, "sm"),
          h("span", { class: "grow col" },
            h("strong", null, token.native ? symbol(token) : displayName(token), token.verified ? null : h("span", { class: "tag" }, "UNVERIFIED")),
            h("small", { class: "muted" }, `Balance ${balance === undefined ? "0" : amount(balance.amount, token)}`)),
          icon("chevronDown")),
        assetMenu,
      ),
      h("div", { class: "amount-card" },
        h("label", { class: "amount-row" }, h("span", { class: "vh" }, "Amount"), amountInput, h("span", { class: "muted unit" }, symbol(token))),
        useMax,
      ),
      h("div", { class: "row between rel" },
        h("span", { class: "muted" }, "Network fee"),
        h("button", { class: "plain", type: "button", "aria-haspopup": "menu", onclick: () => { feeMenu.hidden = !feeMenu.hidden; } }, feeLabel, icon("chevronDown", "sm")),
        feeMenu,
      ),
      error,
      h("button", { type: "submit", hidden: true }),
    ),
    h("div", { class: "foot" }, next),
  );
}

export function confirmScreen(app: App): HTMLElement {
  const view = app.pendingApproval;
  if (view === undefined) {
    return h("div", { class: "screen" }, backHeader(app, "Confirm send"), h("div", { class: "body" }, h("p", { class: "muted" }, "Nothing to confirm.")));
  }
  const tokens = { ...app.wallet?.tokens, ...view.tokens };
  const output = view.review.externalOutputs[0];
  const sent = output === undefined ? undefined : tokenFor(tokens, output.assetId);
  const nativeToken = Object.values(tokens).find((token) => token.native) ?? tokenFor(tokens, app.status?.network.policyAsset ?? "");
  const total = output !== undefined && sent?.native === true
    ? amountWithSymbol(BigInt(output.amount) + BigInt(view.review.fee), nativeToken)
    : output !== undefined && sent !== undefined
      ? `${amountWithSymbol(output.amount, sent)} + ${amountWithSymbol(view.review.fee, nativeToken)}`
      : "";
  const error = errorLine();
  const leave = () => {
    void app.backend.reject(view.approvalId).catch(() => undefined);
    app.pendingApproval = undefined;
    app.back();
  };
  const confirm = button("Confirm", () => void (async () => {
    showError(error, null);
    try {
      const result = await busy(confirm, "Sending", () => app.backend.approve(view));
      app.pendingApproval = undefined;
      resetSendDraft();
      app.replace("sent", { result, amount: output === undefined || sent === undefined ? "" : amountWithSymbol(output.amount, sent) });
      void app.refresh();
    } catch (failure) {
      showError(error, `${app.errorMessage(failure)}. Go back and try again.`);
      confirm.disabled = true;
    }
  })());
  return h("div", { class: "screen" },
    backHeader(app, "Confirm send", leave),
    h("div", { class: "body scroll" },
      h("div", { class: "hero-amt" },
        sent === undefined ? null : avatar(sent, "lg"),
        h("strong", null, output === undefined || sent === undefined ? "" : amountWithSymbol(-BigInt(output.amount), sent)),
        sent !== undefined && !sent.verified ? h("span", { class: "tag" }, "UNVERIFIED ASSET") : null,
      ),
      h("dl", { class: "card m0" },
        kv("To", h("span", { class: "mono addr-full" }, output?.address ?? "")),
        kv("Network", app.status?.network.name ?? "ECX Alpha"),
        kv("Network fee", amountWithSymbol(view.review.fee, nativeToken)),
        kv(h("strong", { class: "fg" }, "Total"), h("strong", null, total)),
      ),
      detailsSection(view),
      error,
    ),
    h("div", { class: "foot" }, button("Reject", leave, "ghost"), confirm),
  );
}

export function sentScreen(app: App, params: ScreenParams): HTMLElement {
  const result = params["result"] as ApprovalResult | undefined;
  const txid = result?.txid ?? "";
  const explorer = app.status?.settings.explorerUrl;
  return h("div", { class: "screen pad between" },
    h("div", { class: "hero" },
      h("span", { class: "done-mark" }, icon("check")),
      h("div", { class: "center" },
        h("h1", { class: "title" }, "Sent"),
        h("p", { class: "muted sub" }, typeof params["amount"] === "string" ? `${params["amount"]} is on its way` : "Transaction broadcast"),
      ),
      h("button", { class: "addr mono", type: "button", onclick: () => void app.copy(txid, "Transaction id copied") }, `${txid.slice(0, 10)}…${txid.slice(-8)}`, icon("copy", "sm")),
    ),
    h("div", { class: "stack" },
      explorer === undefined || txid === "" ? null : button([icon("external"), "View in explorer"], () => app.backend.openTab(explorerTxUrl(explorer, txid)), "ghost"),
      button("Done", () => app.go("home")),
    ),
  );
}
