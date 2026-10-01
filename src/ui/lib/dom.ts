/** Tiny DOM builder. No innerHTML anywhere: every string becomes a text node. */
export type Child = Node | string | number | null | undefined | false | readonly Child[];

export interface Attributes {
  readonly [name: string]: string | number | boolean | null | undefined | ((event: Event) => void);
}

export function h<K extends keyof HTMLElementTagNameMap>(tag: K, attributes: Attributes | null = null, ...children: Child[]): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  if (attributes !== null) {
    for (const [name, value] of Object.entries(attributes)) {
      if (value === undefined || value === null || value === false) continue;
      if (typeof value === "function") {
        element.addEventListener(name.replace(/^on/u, "").toLowerCase(), value as EventListener);
      } else if (name === "class") {
        element.className = String(value);
      } else if (value === true) {
        element.setAttribute(name, "");
      } else if (name === "value" && "value" in element) {
        (element as HTMLInputElement).value = String(value);
      } else {
        element.setAttribute(name, String(value));
      }
    }
  }
  append(element, children);
  return element;
}

export function append(parent: Node, children: readonly Child[]): void {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    if (Array.isArray(child)) append(parent, child);
    else parent.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

export function replaceChildren(parent: Element, ...children: Child[]): void {
  parent.replaceChildren();
  append(parent, children);
}

const SVG = "http://www.w3.org/2000/svg";

export function svg(tag: string, attributes: Record<string, string | number>, ...children: Element[]): SVGElement {
  const element = document.createElementNS(SVG, tag);
  for (const [name, value] of Object.entries(attributes)) element.setAttribute(name, String(value));
  for (const child of children) element.appendChild(child);
  return element as SVGElement;
}
