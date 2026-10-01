import { App } from "./lib/app.js";
import { ExtensionBackend } from "./lib/backend.js";
import { SCREENS } from "./screens/index.js";

const root = document.getElementById("app");
if (root === null) throw new Error("wallet root is missing");
// Opened as a tab (options page) rather than the toolbar popup.
if (window.innerWidth > 420) document.documentElement.classList.add("tab");
void new App(root, new ExtensionBackend(), SCREENS).start();
