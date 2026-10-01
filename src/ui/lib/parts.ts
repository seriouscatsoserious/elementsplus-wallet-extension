import type { App, ScreenName } from "./app.js";
import { h, type Child } from "./dom.js";
import { icon, type IconName } from "./icons.js";

export function backHeader(app: App, title: string, onBack: () => void = () => app.back(), right: Child = h("span")): HTMLElement {
  return h("header", { class: "head" },
    h("button", { class: "ib", type: "button", "aria-label": "Back", onclick: onBack }, icon("back")),
    h("h1", null, title),
    right,
  );
}

export function titleHeader(title: string, right: Child = null): HTMLElement {
  return h("header", { class: "head left" }, h("h1", null, title), right);
}

export function nav(app: App, active: "home" | "activity" | "settings"): HTMLElement {
  const item = (name: ScreenName & ("home" | "activity" | "settings"), label: string, glyph: IconName) =>
    h("button", {
      class: active === name ? "on" : "",
      type: "button",
      "aria-current": active === name ? "page" : undefined,
      onclick: () => {
        if (active !== name) app.go(name);
      },
    }, icon(glyph), label);
  return h("nav", { class: "nav", "aria-label": "Wallet" },
    item("home", "Wallet", "wallet"),
    item("activity", "Activity", "activity"),
    item("settings", "Settings", "gear"),
  );
}

export function button(label: Child, onClick: (event: Event) => void, variant: "primary" | "ghost" | "danger" = "primary", attributes: Record<string, string | boolean> = {}): HTMLButtonElement {
  return h("button", { class: `btn ${variant}`, type: "button", onclick: onClick, ...attributes }, label);
}

export function errorLine(): HTMLElement {
  return h("p", { class: "err", role: "alert", hidden: true });
}

export function showError(element: HTMLElement, message: string | null): void {
  element.textContent = message ?? "";
  element.hidden = message === null || message === "";
}

/** Disable a button while an async action runs; show a spinner label. */
export async function busy<T>(target: HTMLButtonElement, label: string, work: () => Promise<T>): Promise<T> {
  const previous = [...target.childNodes];
  target.disabled = true;
  target.replaceChildren(h("span", { class: "spin", "aria-hidden": "true" }), label);
  try {
    return await work();
  } finally {
    target.disabled = false;
    target.replaceChildren(...previous);
  }
}

export function brandMark(size: "lg" | "md" | "sm" = "md"): HTMLElement {
  return h("span", { class: `brand ${size}`, "aria-hidden": "true" }, "E+");
}

export function kv(label: Child, value: Child, valueClass = ""): HTMLElement {
  return h("div", { class: "kv" }, h("dt", null, label), h("dd", { class: valueClass }, value));
}
