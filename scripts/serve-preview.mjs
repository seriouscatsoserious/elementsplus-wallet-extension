import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "chromium");
const host = "127.0.0.1";
const portOption = process.argv.indexOf("--port");
const portText = portOption === -1 ? "43198" : process.argv[portOption + 1];
const port = Number(portText);
if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) {
  throw new Error("Preview port must be an integer from 1024 through 65535");
}
const contentTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
]);

const server = createServer(async (request, response) => {
  try {
    const requestUrl = new URL(request.url ?? "/", `http://${host}:${port}`);
    const pathname = requestUrl.pathname === "/" ? "/src/ui/preview.html" : decodeURIComponent(requestUrl.pathname);
    const target = path.resolve(root, `.${pathname}`);
    if (target !== root && !target.startsWith(`${root}${path.sep}`)) {
      response.writeHead(403).end("Forbidden\n");
      return;
    }
    if (!(await stat(target)).isFile()) throw new Error("Not a file");
    const body = await readFile(target);
    response.writeHead(200, {
      "Cache-Control": "no-store",
      "Content-Type": contentTypes.get(path.extname(target)) ?? "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
    });
    response.end(body);
  } catch {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" }).end("Not found\n");
  }
});

server.listen(port, host, () => {
  process.stdout.write(`Static wallet preview: http://${host}:${port}/\n`);
  process.stdout.write(`Individual screens: #dashboard #assets #send #receive #issue #manage #setup #network\n`);
});

server.on("error", (error) => {
  process.stderr.write(`Unable to start preview on ${host}:${port}: ${error.message}\n`);
  process.stderr.write("Choose another port with: npm run preview -- --port 43199\n");
  process.exitCode = 1;
});
