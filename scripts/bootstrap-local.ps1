$ErrorActionPreference = "Stop"

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  throw "Node.js 24 or newer is required."
}

$nodeMajor = [int]((node -p 'process.versions.node.split(".")[0]') | Select-Object -First 1)
if ($nodeMajor -lt 24) {
  throw "Node.js 24 or newer is required; found $(node --version)."
}

foreach ($requiredCommand in @("cargo", "rustup", "wasm-bindgen")) {
  if (-not (Get-Command $requiredCommand -ErrorAction SilentlyContinue)) {
    throw "$requiredCommand is required; see docs/LOCAL-TESTING.md."
  }
}

$wasmBindgenVersion = (wasm-bindgen --version | Select-Object -First 1)
if ($wasmBindgenVersion -ne "wasm-bindgen 0.2.108") {
  throw "wasm-bindgen-cli 0.2.108 is required; found $wasmBindgenVersion."
}

$installedTargets = @(rustup target list --installed)
if ($installedTargets -notcontains "wasm32-unknown-unknown") {
  throw "The wasm32-unknown-unknown Rust target is required; see docs/LOCAL-TESTING.md."
}

npm ci --ignore-scripts
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
npm run check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "Build complete. Load this directory as an unpacked Chromium extension:"
Write-Host ((Resolve-Path "dist/chromium").Path)
