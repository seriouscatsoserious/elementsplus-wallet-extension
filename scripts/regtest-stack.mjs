import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const state = path.join(root, ".regtest");
const nodeSource = path.join(root, ".local", "elementsplus-node");
const nodeBuild = path.join(nodeSource, "build-regtest");
const node = path.join(nodeBuild, "bin", "elements-functional-test-node");
const cliProgram = path.join(nodeBuild, "bin", "elements-functional-test-cli");
const datadir = path.join(state, "node");
const rpcPort = "18884";
const explorerPort = "43199";
const relayBinary = path.join(root, "vendor", "elementsplus-preconf", "target", "release", "preconf-relay");
const signerDirectory = path.join(root, "services", "preconfer-signer");
const signerBinary = path.join(signerDirectory, "target", "release", "elementsplus-preconfer-signer");
const keyBinary = path.join(signerDirectory, "target", "release", "preconf-key");
const profileBinary = path.join(signerDirectory, "target", "release", "preconf-profile");
const bondBinary = path.join(signerDirectory, "target", "release", "preconf-bond");
const pinnedNodeCommit = "006d2a30b1df340f5d77ca9af21e1c3df18b551b";
// This directory contains disposable wallet keys and bearer credentials. Keep
// newly generated state private even when the caller has a permissive umask.
process.umask(0o077);

function run(program, args, options = {}) {
  const result = spawnSync(program, args, {
    cwd: options.cwd ?? root,
    encoding: "utf8",
    stdio: options.quiet ? "pipe" : "inherit",
    env: { ...process.env, ...(options.env ?? {}) },
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.error !== undefined) throw result.error;
  if (result.status !== 0) {
    const details = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim();
    throw new Error(`${program} failed (${String(result.status)})${details ? `: ${details}` : ""}`);
  }
  return (result.stdout ?? "").trim();
}

function tryRun(program, args, options = {}) {
  const result = spawnSync(program, args, {
    cwd: options.cwd ?? root,
    encoding: "utf8",
    stdio: "pipe",
    env: { ...process.env, ...(options.env ?? {}) },
    maxBuffer: 32 * 1024 * 1024,
  });
  return { ok: result.status === 0, output: `${result.stdout ?? ""}${result.stderr ?? ""}`.trim() };
}

function cli(method, ...args) {
  return run(cliProgram, [
    "-chain=elementsregtest",
    `-datadir=${datadir}`,
    `-rpcport=${rpcPort}`,
    method,
    ...args,
  ], { quiet: true });
}

function walletCli(method, ...args) {
  return run(cliProgram, [
    "-chain=elementsregtest",
    `-datadir=${datadir}`,
    `-rpcport=${rpcPort}`,
    "-rpcwallet=miner",
    method,
    ...args,
  ], { quiet: true });
}

function jsonRpc(method, ...args) {
  return JSON.parse(cli(method, ...args));
}

function walletJson(method, ...args) {
  return JSON.parse(walletCli(method, ...args));
}

function alive(pidPath) {
  if (!existsSync(pidPath)) return false;
  const pid = Number(readFileSync(pidPath, "utf8"));
  if (!Number.isSafeInteger(pid) || pid <= 1) return false;
  try { process.kill(pid, 0); return true; } catch { return false; }
}

function stopPid(name) {
  const pidPath = path.join(state, `${name}.pid`);
  if (!alive(pidPath)) {
    rmSync(pidPath, { force: true });
    return;
  }
  const pid = Number(readFileSync(pidPath, "utf8"));
  process.kill(pid, "SIGTERM");
  rmSync(pidPath, { force: true });
}

function startDetached(name, program, args, environment = {}) {
  const pidPath = path.join(state, `${name}.pid`);
  if (alive(pidPath)) return;
  const logPath = path.join(state, `${name}.log`);
  const descriptor = openSync(logPath, "a", 0o600);
  const child = spawn(program, args, {
    cwd: root,
    detached: true,
    env: { ...process.env, ...environment },
    stdio: ["ignore", descriptor, descriptor],
  });
  child.unref();
  closeSync(descriptor);
  if (child.pid === undefined) throw new Error(`failed to start ${name}`);
  writeFileSync(pidPath, `${child.pid}\n`, { mode: 0o600 });
}

function waitForNode() {
  for (let attempt = 0; attempt < 300; attempt += 1) {
    const result = tryRun(cliProgram, [
      "-chain=elementsregtest",
      `-datadir=${datadir}`,
      `-rpcport=${rpcPort}`,
      "getblockchaininfo",
    ]);
    if (result.ok) return;
    spawnSync("sleep", ["0.1"]);
  }
  throw new Error(`regtest node did not become ready; inspect ${path.join(datadir, "elementsregtest", "debug.log")}`);
}

function bootstrap() {
  mkdirSync(path.dirname(nodeSource), { recursive: true });
  if (!existsSync(path.join(nodeSource, ".git"))) {
    run("git", ["clone", "--no-checkout", "https://github.com/ekulkisnek/liquid-drivechain-signet-adaptation.git", nodeSource]);
    // Only this new checkout is changed. Preserve edits in existing checkouts.
    run("git", ["checkout", "--detach", pinnedNodeCommit], { cwd: nodeSource });
  }
  const commit = run("git", ["rev-parse", "HEAD"], { cwd: nodeSource, quiet: true });
  if (commit !== pinnedNodeCommit) {
    throw new Error(`Elements+ node checkout is ${commit}; expected ${pinnedNodeCommit}`);
  }
  if (run("git", ["status", "--porcelain", "--untracked-files=no"], { cwd: nodeSource, quiet: true }) !== "") {
    throw new Error("Elements+ node has tracked local changes; preserve them and use a clean pinned checkout");
  }
  if (!existsSync(path.join(nodeBuild, "build.ninja"))) {
    run("cmake", [
      "-S", nodeSource,
      "-B", nodeBuild,
      "-G", "Ninja",
      "-DCMAKE_BUILD_TYPE=Release",
      "-DBUILD_GUI=OFF",
      "-DBUILD_TESTS=ON",
      "-DBUILD_BENCH=OFF",
      "-DWITH_BDB=OFF",
      "-DWITH_ZMQ=OFF",
      "-DWITH_USDT=OFF",
      "-DWITH_MULTIPROCESS=OFF",
    ]);
  }
  if (!existsSync(node) || !existsSync(cliProgram)) {
    const jobs = process.env["ELEMENTSPLUS_BUILD_JOBS"] ?? "2";
    if (!/^[1-9][0-9]?$/u.test(jobs)) throw new Error("ELEMENTSPLUS_BUILD_JOBS must be an integer from 1 to 99");
    run("cmake", ["--build", nodeBuild, "--target", "elements-functional-test-node", "elements-functional-test-cli", "--parallel", jobs]);
  }
  run("cargo", ["build", "--locked", "--release", "--manifest-path", path.join(signerDirectory, "Cargo.toml")]);
  run("cargo", [
    "build", "--locked", "--release", "--features", "relay", "--bin", "preconf-relay",
    "--manifest-path", path.join(root, "vendor", "elementsplus-preconf", "Cargo.toml"),
  ]);
}

function start() {
  bootstrap();
  mkdirSync(datadir, { recursive: true });
  const ready = tryRun(cliProgram, [
    "-chain=elementsregtest", `-datadir=${datadir}`, `-rpcport=${rpcPort}`, "getblockchaininfo",
  ]).ok;
  if (!ready) {
    run(node, [
      "-chain=elementsregtest",
      `-datadir=${datadir}`,
      "-daemon",
      "-server=1",
      "-listen=0",
      "-discover=0",
      "-dnsseed=0",
      "-txindex=1",
      "-fallbackfee=0.0001",
      "-validatepegin=0",
      "-con_blocksubsidy=5000000000",
      "-evbparams=simplicity:-1:::",
      `-rpcport=${rpcPort}`,
      "-port=18886",
    ], { quiet: true });
    waitForNode();
  }
  const wallets = jsonRpc("listwalletdir").wallets.map((entry) => entry.name);
  const loaded = jsonRpc("listwallets");
  if (!wallets.includes("miner")) {
    cli("createwallet", "miner", "false", "false", "", "false", "true");
  } else if (!loaded.includes("miner")) {
    cli("loadwallet", "miner");
  }
  let height = Number(cli("getblockcount"));
  if (height < 101) {
    const address = walletCli("getnewaddress");
    walletCli("generatetoaddress", String(101 - height), address);
    height = Number(cli("getblockcount"));
  }
  const genesisHash = cli("getblockhash", "0");
  const nativeAssetId = jsonRpc("getsidechaininfo").pegged_asset;
  const network = { genesisHash, nativeAssetId, explorerUrl: `http://127.0.0.1:${explorerPort}`, height };
  mkdirSync(state, { recursive: true });
  writeFileSync(path.join(state, "network.json"), `${JSON.stringify(network, null, 2)}\n`, { mode: 0o600 });
  run(process.execPath, [path.join(root, "scripts", "build-regtest.mjs")]);
  startDetached("explorer", process.execPath, [path.join(root, "scripts", "regtest-explorer.mjs")], {
    ELEMENTSPLUS_REGTEST_CLI: cliProgram,
    ELEMENTSPLUS_REGTEST_DATADIR: datadir,
    ELEMENTSPLUS_REGTEST_RPC_PORT: rpcPort,
    ELEMENTSPLUS_EXPLORER_PORT: explorerPort,
  });
  process.stdout.write(`\nRegtest is up at height ${height}.\nExtension: ${path.join(state, "dist", "chromium")}\n`);
}

function mine() {
  const address = walletCli("getnewaddress");
  const hashes = walletJson("generatetoaddress", "1", address);
  process.stdout.write(`Mined block ${hashes[0]} at height ${cli("getblockcount")}\n`);
}

function findOutput(txid, script) {
  const transaction = jsonRpc("getrawtransaction", txid, "true");
  const output = transaction.vout.find((candidate) => candidate.scriptPubKey?.hex === script);
  if (output === undefined) throw new Error(`transaction ${txid} does not contain expected output ${script}`);
  return `${txid}:${output.n}`;
}

function validSecret(pathname) {
  if (!existsSync(pathname)) writeFileSync(pathname, `${randomBytes(32).toString("hex")}\n`, { mode: 0o600 });
  chmodSync(pathname, 0o600);
  const result = tryRun(keyBinary, [pathname]);
  if (result.ok) return result.output;
  rmSync(pathname, { force: true });
  return validSecret(pathname);
}

function session(address, extensionId) {
  if (!/^[a-p]{32}$/u.test(extensionId)) {
    throw new Error("extension ID must be the 32-letter Chromium ID shown on chrome://extensions");
  }
  const validated = jsonRpc("validateaddress", address);
  if (validated.isvalid !== true || typeof validated.scriptPubKey !== "string") {
    throw new Error("wallet address is not valid on this Elements+ regtest node");
  }
  const fundingTxid = walletCli("sendtoaddress", address, "0.01000000");
  mine();
  const protectedOutput = findOutput(fundingTxid, validated.scriptPubKey);
  const sessionDirectory = path.join(state, "session");
  for (const name of ["signer", "relay-one", "relay-two"]) stopPid(name);
  rmSync(sessionDirectory, { recursive: true, force: true });
  mkdirSync(sessionDirectory, { recursive: true });
  const secretPath = path.join(sessionDirectory, "preconfer.secret");
  const authPath = path.join(sessionDirectory, "wallet.secret");
  const preconfer = validSecret(secretPath);
  writeFileSync(authPath, `${randomBytes(32).toString("hex")}\n`, { mode: 0o600 });
  chmodSync(authPath, 0o600);
  const currentHeight = Number(cli("getblockcount"));
  const operatorConfig = {
    genesis: cli("getblockhash", "0"),
    fee_asset: jsonRpc("getsidechaininfo").pegged_asset,
    preconfer,
    protected_output: protectedOutput,
    epoch: String(Date.now()),
    collateral: 100000,
    active_until: currentHeight + 1000,
    refund_height: currentHeight + 1010,
  };
  const operatorPath = path.join(sessionDirectory, "operator-config.json");
  writeFileSync(operatorPath, `${JSON.stringify(operatorConfig, null, 2)}\n`, { mode: 0o600 });
  const template = JSON.parse(run(bondBinary, [operatorPath], { quiet: true }));
  const decoded = jsonRpc("decodescript", template.script_pubkey);
  const bondAddress = decoded?.segwit?.address ?? decoded?.address;
  if (typeof bondAddress !== "string") throw new Error("node could not encode the Simplicity bond address");
  const bondTxid = walletCli("sendtoaddress", bondAddress, "0.00100000");
  mine();
  const bond = findOutput(bondTxid, template.script_pubkey);
  const profile = { version: 1, sessions: [{ bond, config: operatorConfig }] };
  const profilePath = path.join(sessionDirectory, "profile.json");
  writeFileSync(profilePath, `${JSON.stringify(profile, null, 2)}\n`, { mode: 0o600 });
  const profileId = run(profileBinary, [profilePath], { quiet: true });
  const token = readFileSync(authPath, "utf8").trim();
  const signerConfig = {
    listen: "127.0.0.1:8788",
    allowed_origins: [`chrome-extension://${extensionId}`],
    profile_path: profilePath,
    secret_key_path: secretPath,
    auth_token_path: authPath,
    decision_journal: path.join(sessionDirectory, "signer.journal"),
    node_cli: {
      program: cliProgram,
      args: ["-chain=elementsregtest", `-datadir=${datadir}`, `-rpcport=${rpcPort}`],
    },
    relay_urls: ["ws://127.0.0.1:9430", "ws://127.0.0.1:9431"],
  };
  const signerConfigPath = path.join(sessionDirectory, "signer.json");
  writeFileSync(signerConfigPath, `${JSON.stringify(signerConfig, null, 2)}\n`, { mode: 0o600 });
  const origin = `chrome-extension://${extensionId}`;
  startDetached("relay-one", relayBinary, [
    profilePath, path.join(sessionDirectory, "relay-one.jsonl"), "127.0.0.1:9430", "--origin", origin,
  ]);
  startDetached("relay-two", relayBinary, [
    profilePath, path.join(sessionDirectory, "relay-two.jsonl"), "127.0.0.1:9431", "--origin", origin,
  ]);
  startDetached("signer", signerBinary, [signerConfigPath]);
  const browserConfig = {
    version: 1,
    endpoint: "ws://127.0.0.1:8788",
    relayUrls: ["ws://127.0.0.1:9430", "ws://127.0.0.1:9431"],
    profile: profileId,
    bond,
    authToken: token,
    operatorConfig,
  };
  const command = `await chrome.storage.local.set(${JSON.stringify({ "elementsplus.preconfirmation.v1": browserConfig }, null, 2)});\nlocation.reload();`;
  const commandPath = path.join(sessionDirectory, "extension-config.js");
  writeFileSync(commandPath, `${command}\n`, { mode: 0o600 });
  process.stdout.write(`\nFunded wallet output: ${protectedOutput}\nFunded operator bond: ${bond}\nProfile: ${profileId}\n\nPaste this in the extension service-worker console:\n\n${command}\n\nSaved at ${commandPath}\n`);
}

function status() {
  const nodeStatus = tryRun(cliProgram, [
    "-chain=elementsregtest", `-datadir=${datadir}`, `-rpcport=${rpcPort}`, "getblockcount",
  ]);
  process.stdout.write(`node=${nodeStatus.ok ? `height ${nodeStatus.output}` : "down"}\n`);
  for (const name of ["explorer", "signer", "relay-one", "relay-two"]) {
    try {
      process.stdout.write(`${name}=${alive(path.join(state, `${name}.pid`)) ? "up" : "down"}\n`);
    } catch (error) {
      if (error?.code !== "EACCES") throw error;
      process.stdout.write(`${name}=unknown (state belongs to a different OS user)\n`);
      process.exitCode = 1;
    }
  }
}

function stop() {
  for (const name of ["signer", "relay-one", "relay-two", "explorer"]) stopPid(name);
  const result = tryRun(cliProgram, [
    "-chain=elementsregtest", `-datadir=${datadir}`, `-rpcport=${rpcPort}`, "stop",
  ]);
  process.stdout.write(result.ok ? "Regtest stack stopped.\n" : "Regtest services stopped; node was already down.\n");
}

const [action = "status", ...args] = process.argv.slice(2);
if (action !== "status" && process.getuid?.() === 0) {
  throw new Error("Run the disposable regtest stack as an unprivileged user, not root; see docs/REGTEST-WALLET.md");
}
switch (action) {
  case "bootstrap": bootstrap(); break;
  case "start": start(); break;
  case "stop": stop(); break;
  case "status": status(); break;
  case "mine": mine(); break;
  case "session": {
    if (args.length !== 2) throw new Error("usage: npm run regtest:session -- WALLET_ADDRESS CHROMIUM_EXTENSION_ID");
    session(args[0], args[1]);
    break;
  }
  default: throw new Error(`unknown regtest action: ${action}`);
}
