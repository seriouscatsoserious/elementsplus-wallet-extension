$ErrorActionPreference = "Stop"

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  throw "Node.js 24 or newer is required."
}

$nodeMajor = [int]((node -p 'process.versions.node.split(".")[0]') | Select-Object -First 1)
if ($nodeMajor -lt 24) {
  throw "Node.js 24 or newer is required; found $(node --version)."
}

npm ci --ignore-scripts
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
npm run check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "Build complete. Load this directory as an unpacked Chromium extension:"
Write-Host ((Resolve-Path "dist/chromium").Path)
