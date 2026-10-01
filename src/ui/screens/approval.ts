/** dApp approval window: unlock, Connect, and a generic TxReview approval. */
import type { ApprovalResult } from "../../background/controller.js";
import type { Backend, PendingRequestView, Tokens, WalletStatus } from "../lib/backend.js";
import { h, replaceChildren } from "../lib/dom.js";
import { amountWithSymbol, shortId, tokenFor } from "../lib/format.js";
import { icon } from "../lib/icons.js";
import { brandMark, busy, button, errorLine, showError } from "../lib/parts.js";
import { checkedNote, detailsSection, factsCard, legsCard, reviewTitle } from "../lib/review.js";

function host(origin: string | undefined): string {
  if (origin === undefined) return "";
  try {
    const url = new URL(origin);
    return url.protocol === "https:" ? url.host : origin;
  } catch {
    return origin;
  }
}

export class ApprovalFlow {
  readonly #root: HTMLElement;
  readonly #backend: Backend;
  readonly #requestId: string;
  readonly #close: () => void;
  #decided = false;
  /** The approval on screen: the decision binds to exactly this review hash and token. */
  #current: PendingRequestView["approval"];

  constructor(root: HTMLElement, backend: Backend, requestId: string, close: () => void = () => window.close()) {
    this.#root = root;
    this.#backend = backend;
    this.#requestId = requestId;
    this.#close = close;
  }

  async start(): Promise<void> {
    this.#show(this.#loading());
    let view: PendingRequestView;
    let status: WalletStatus;
    try {
      [view, status] = await Promise.all([this.#backend.describeRequest(this.#requestId), this.#backend.status()]);
    } catch (error) {
      this.#show(this.#message("Something went wrong", error instanceof Error ? error.message : "The wallet did not respond."));
      return;
    }
    if (view.status === "gone") {
      this.#show(this.#message("Request expired", "This request is no longer pending. You can close this window."));
      return;
    }
    if (view.status === "failed") {
      this.#show(this.#message("Couldn't prepare this request", view.message ?? "The wallet could not build this transaction."));
      return;
    }
    if (view.locked === true || !status.unlocked) {
      this.#show(this.#unlock(view, status));
      return;
    }
    if (view.kind === "unlock") {
      await this.#decide(true);
      return;
    }
    if (view.kind === "connect") {
      this.#show(this.#connect(view, status));
      return;
    }
    if (view.approval !== undefined) {
      this.#current = view.approval;
      this.#show(this.#transaction(view, status));
    }
  }

  #show(element: HTMLElement): void {
    replaceChildren(this.#root, element);
    element.querySelector<HTMLElement>("[autofocus]")?.focus();
  }

  #loading(): HTMLElement {
    return h("div", { class: "screen pad center-all" }, h("span", { class: "spin lg", "aria-label": "Loading" }));
  }

  #message(title: string, text: string): HTMLElement {
    return h("div", { class: "screen pad between" },
      h("div", { class: "hero" }, brandMark("lg"), h("div", { class: "center" }, h("h1", { class: "title" }, title), h("p", { class: "muted sub" }, text))),
      button("Close", () => this.#close(), "ghost"),
    );
  }

  #originHeader(title: string, origin: string | undefined): HTMLElement {
    return h("div", { class: "origin-head" }, brandMark("sm"), h("div", null, h("h1", null, title), h("div", { class: "mono muted small" }, host(origin))));
  }

  #unlock(view: PendingRequestView, status: WalletStatus): HTMLElement {
    const password = h("input", { class: "field", type: "password", placeholder: "Password", autocomplete: "current-password", autofocus: true, "aria-label": "Password" });
    const error = errorLine();
    const unlock = h("button", { class: "btn primary", type: "submit" }, "Unlock");
    const submit = async () => {
      showError(error, null);
      try {
        await busy(unlock, "Unlocking", () => this.#backend.unlock(password.value));
        password.value = "";
        await this.start();
      } catch (failure) {
        showError(error, failure instanceof Error ? failure.message : "Unlock failed");
      }
    };
    return h("div", { class: "screen pad between" },
      h("div", { class: "hero" },
        brandMark("lg"),
        h("div", { class: "center" },
          h("h1", { class: "title" }, status.initialized ? "Unlock to continue" : "No wallet yet"),
          h("p", { class: "muted sub mono" }, host(view.origin)),
        ),
      ),
      status.initialized
        ? h("form", { class: "stack", onsubmit: (event: Event) => { event.preventDefault(); void submit(); } },
          password, error, unlock, button("Cancel", () => void this.#decide(false), "ghost"))
        : h("div", { class: "stack" }, h("p", { class: "muted small center" }, "Open the wallet from the toolbar to create one first."), button("Cancel", () => void this.#decide(false), "ghost")),
    );
  }

  #connect(view: PendingRequestView, status: WalletStatus): HTMLElement {
    const balance = h("span", { class: "strong" }, "");
    void this.#backend.snapshot().then(({ snapshot, tokens }) => {
      const native = snapshot.balances.find((entry) => entry.assetId === status.network.policyAsset);
      balance.textContent = amountWithSymbol(native?.amount ?? "0", tokenFor(tokens, status.network.policyAsset));
    }).catch(() => undefined);
    const error = errorLine();
    const connect = button("Connect", () => void (async () => {
      try {
        await busy(connect, "Connecting", () => this.#decide(true));
      } catch (failure) {
        showError(error, failure instanceof Error ? failure.message : "Could not connect");
      }
    })());
    return h("div", { class: "screen" },
      h("div", { class: "body top-pad" },
        h("div", { class: "hero tight" },
          h("span", { class: "brand md outline" }, "E+"),
          h("div", { class: "center" }, h("h1", { class: "title sm" }, "Connect to this site?"), h("div", { class: "mono muted small mt6" }, host(view.origin)))),
        h("label", { class: "account-card" },
          h("input", { type: "radio", name: "acct", checked: true }),
          h("span", { class: "av" }, "A"),
          h("span", { class: "grow col" }, h("strong", null, "Account 1"), h("small", { class: "mono muted" }, status.primaryAddress === null ? "" : shortId(status.primaryAddress, 12, 5))),
          balance),
        h("div", null,
          h("div", { class: "grp flush" }, "This site will be able to"),
          h("div", { class: "perm" }, icon("check", "ok"), h("span", null, "See your address and token balances")),
          h("div", { class: "perm" }, icon("check", "ok"), h("span", null, "Ask you to approve transactions")),
          h("p", { class: "muted small m0" }, "It can never move funds without your approval.")),
        error,
      ),
      h("div", { class: "foot" }, button("Cancel", () => void this.#decide(false), "ghost"), connect),
    );
  }

  #transaction(view: PendingRequestView, status: WalletStatus): HTMLElement {
    const approval = view.approval!;
    const tokens: Tokens = approval.tokens;
    const error = errorLine();
    const unverified = approval.review.balanceChanges.some((delta) => !tokenFor(tokens, delta.assetId).verified);
    const approve = button("Approve", () => void (async () => {
      showError(error, null);
      try {
        const result = await busy(approve, "Signing", () => this.#decide(true));
        this.#show(this.#done(result));
      } catch (failure) {
        showError(error, failure instanceof Error ? failure.message : "Approval failed");
        approve.disabled = true;
      }
    })());
    return h("div", { class: "screen" },
      h("div", { class: "body scroll top-pad-sm" },
        this.#originHeader(reviewTitle(approval.review, approval.operation), view.origin),
        legsCard(approval.review, approval.operation, tokens),
        unverified ? h("p", { class: "notice warn" }, icon("alert"), h("span", null, "Includes an unverified asset. Its name and decimals are unknown; amounts are shown in base units.")) : null,
        factsCard(approval, status.network.name),
        checkedNote(approval.operation.kind === "swap_offer"),
        detailsSection(approval),
        error,
      ),
      h("div", { class: "foot" }, button("Reject", () => void this.#decide(false), "ghost"), approve),
    );
  }

  #done(result: ApprovalResult | undefined): HTMLElement {
    const detail = result?.offer !== undefined ? "Offer signed and returned to the site." : result?.txid !== undefined ? `Transaction ${result.txid.slice(0, 10)}… broadcast.` : "Done.";
    setTimeout(() => this.#close(), 1_500);
    return h("div", { class: "screen pad center-all" },
      h("div", { class: "hero" }, h("span", { class: "done-mark" }, icon("check")), h("div", { class: "center" }, h("h1", { class: "title" }, "Approved"), h("p", { class: "muted sub" }, detail))));
  }

  async #decide(approved: boolean): Promise<ApprovalResult | undefined> {
    if (this.#decided) return undefined;
    const approval = this.#current;
    const response = await this.#backend.resolveRequest(this.#requestId, approved, approved ? approval : undefined);
    this.#decided = true;
    if (!approved || response.result === undefined) setTimeout(() => this.#close(), approved ? 600 : 0);
    return response.result;
  }

}
