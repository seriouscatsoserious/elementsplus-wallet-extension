import { ExtensionBackend } from "./lib/backend.js";
import { ApprovalFlow } from "./screens/approval.js";

const root = document.getElementById("app");
if (root === null) throw new Error("approval root is missing");
const requestId = new URLSearchParams(location.search).get("id") ?? "";
void new ApprovalFlow(root, new ExtensionBackend(), requestId).start();
