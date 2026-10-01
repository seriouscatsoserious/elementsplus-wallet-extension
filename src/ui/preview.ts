/**
 * Standalone preview (no extension runtime): renders any screen with sample
 * data. `preview.html?screen=home`, `?screen=confirm`, `?approve=swap`, …
 */
import { App, type ScreenName } from "./lib/app.js";
import { MockBackend, SAMPLE, SAMPLE_APPROVALS } from "./lib/mock-backend.js";
import { ApprovalFlow } from "./screens/approval.js";
import { SCREENS } from "./screens/index.js";

const root = document.getElementById("app");
if (root === null) throw new Error("preview root is missing");
const query = new URLSearchParams(location.search);
const approve = query.get("approve");

if (approve !== null) {
  const backend = new MockBackend({
    unlocked: approve !== "locked",
    request: approve === "connect" || approve === "locked"
      ? { status: "pending", requestId: "preview", origin: "https://your-dex.example", method: "ep_connect", kind: "connect", locked: approve === "locked" }
      : { status: "pending", requestId: "preview", origin: "https://your-dex.example", method: "ep_sendTransfer", kind: "transaction", locked: false, approval: SAMPLE_APPROVALS[approve] ?? SAMPLE_APPROVALS["swap"]! },
  });
  void new ApprovalFlow(root, backend, "preview", () => undefined).start();
} else {
  const screen = (query.get("screen") ?? "home") as ScreenName;
  const locked = screen === "lock";
  const fresh = ["welcome", "show-phrase", "confirm-phrase", "import", "password"].includes(screen);
  const backend = new MockBackend({ unlocked: !locked && !fresh, initialized: !fresh });
  const app = new App(root, backend, SCREENS);
  void (async () => {
    if (fresh && screen !== "welcome") {
      app.draft = { mode: screen === "import" ? "import" : "create", mnemonic: await backend.generateMnemonic() };
    }
    if (!locked && !fresh) await app.refresh();
    if (screen === "confirm") app.pendingApproval = SAMPLE_APPROVALS["send"];
    const params: Record<string, unknown> = {};
    if (screen === "send") params["assetId"] = query.get("asset") === "orbit" ? SAMPLE.orbit : undefined;
    if (screen === "sent") Object.assign(params, { result: { txid: "ab".repeat(32) }, amount: "25.00 ECX" });
    if (params["assetId"] === undefined) delete params["assetId"];
    await app.start({ name: SCREENS[screen] === undefined ? "home" : screen, params });
    if (!locked && !fresh) await app.refresh();
  })();
}
