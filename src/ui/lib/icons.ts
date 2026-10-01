import { svg } from "./dom.js";

/** Stroke icons (24×24) drawn to match the mockup. */
const PATHS = {
  chevronDown: ["m6 9 6 6 6-6"],
  back: ["m15 18-6-6 6-6"],
  forward: ["m9 18 6-6-6-6"],
  receive: ["M17 7 7 17M16 17H7V8"],
  send: ["M7 17 17 7M8 7h9v9"],
  swap: ["M7 4 3 8l4 4M3 8h14M17 20l4-4-4-4M21 16H7"],
  plus: ["M12 5v14M5 12h14"],
  copy: ["M5 15V5a2 2 0 0 1 2-2h10"],
  check: ["m5 12 5 5 9-10"],
  shield: ["M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6Z"],
  clock: ["M12 7v5l3 2"],
  settings: ["M12 2v3M12 19v3M4.9 4.9 7 7M17 17l2.1 2.1M2 12h3M19 12h3M4.9 19.1 7 17M17 7l2.1-2.1"],
  wallet: ["M16 13h2M3 10h18"],
  x: ["M18 6 6 18M6 6l12 12"],
  external: ["M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"],
  globe: ["M3 12h18M12 3c2.5 2.7 3.8 5.7 3.8 9s-1.3 6.3-3.8 9c-2.5-2.7-3.8-5.7-3.8-9S9.5 5.7 12 3Z"],
  key: ["M15 9a4 4 0 1 1-3.9 4.9L4 21H2v-3l7.1-7.1A4 4 0 0 1 15 9Z", "M16 8h.01"],
  alert: ["M12 9v4M12 17h.01", "M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"],
  sliders: ["M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6"],
  link: ["M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7", "M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"],
  refresh: ["M21 12a9 9 0 1 1-2.6-6.4L21 8", "M21 3v5h-5"],
  eye: ["M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"],
} as const;

export type IconName = keyof typeof PATHS | "lock" | "activity" | "gear";

export function icon(name: IconName, extraClass = ""): SVGElement {
  const element = svg("svg", { class: `i ${extraClass}`.trim(), viewBox: "0 0 24 24", "aria-hidden": "true" });
  const add = (tag: string, attributes: Record<string, string | number>) => element.appendChild(svg(tag, attributes));
  switch (name) {
    case "lock":
      add("rect", { x: 5, y: 11, width: 14, height: 10, rx: 2 });
      add("path", { d: "M8 11V7a4 4 0 0 1 8 0v4" });
      return element;
    case "activity":
      add("circle", { cx: 12, cy: 12, r: 9 });
      add("path", { d: "M12 7v5l3 2" });
      return element;
    case "gear":
      add("circle", { cx: 12, cy: 12, r: 3 });
      add("path", { d: PATHS.settings[0] });
      return element;
    case "wallet":
      add("rect", { x: 3, y: 6, width: 18, height: 14, rx: 3 });
      break;
    case "copy":
      add("rect", { x: 9, y: 9, width: 11, height: 11, rx: 2 });
      break;
    case "clock":
    case "globe":
      add("circle", { cx: 12, cy: 12, r: 9 });
      break;
    case "eye":
      add("circle", { cx: 12, cy: 12, r: 3 });
      break;
    default:
      break;
  }
  for (const d of PATHS[name]) add("path", { d });
  return element;
}
