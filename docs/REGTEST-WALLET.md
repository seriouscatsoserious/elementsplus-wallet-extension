# Local funded preconfirmation test

This harness runs the exact pinned Elements+ functional-test node, an isolated
RPC-to-Esplora bridge, two receipt relays, the preconfer signer, and a visibly
labelled Chromium wallet build. Everything binds to loopback. It uses disposable
regtest coins and must never receive a real recovery phrase or valuable funds.

The production extension remains pinned to ECX Alpha. Regtest support exists
only in `.regtest/dist/chromium`, whose manifest, network identity and WASM are
generated separately and labelled `LOCAL REGTEST`.

## Server

Use an unprivileged account on Linux (the verified harness platform), either on
your own machine or the Helsinki/Hetzner server. Do not run the harness as root.
It does not need the existing ECX full node or any valuable coins. Native Windows
service orchestration has not been qualified; use the Linux server for the node
and run just the Chromium extension on Windows/macOS.

In addition to the wallet prerequisites in LOCAL-TESTING.md, the functional-test
node needs CMake 3.22+, Ninja, a C/C++ compiler, pkg-config, Python 3, Boost,
libevent and SQLite development libraries. On Debian/Ubuntu, an administrator
can install those prerequisites with:

```sh
sudo apt-get install build-essential clang cmake ninja-build pkg-config python3 libboost-dev libevent-dev libsqlite3-dev
```

For this server, `ssh helsinki` logs in as root. Start a clean development shell
and use a fresh test checkout instead of reusing old root-owned `.regtest` data:

```sh
ssh helsinki
sudo -iu codexhost
git clone --branch handoff/funded-regtest-20261001 https://github.com/seriouscatsoserious/elementsplus-wallet-extension.git /home/codexhost/elementsplus-wallet-test
cd /home/codexhost/elementsplus-wallet-test
./scripts/bootstrap-local.sh
npm run regtest:start
```

If you already created that clean checkout, enter it instead of cloning over it.
On your own Linux machine, run these commands from your ordinary user's clone:

```sh
npm run regtest:start
```

The first run clones the node at commit
`006d2a30b1df340f5d77ca9af21e1c3df18b551b`, builds its non-installed
functional-test node and CLI, mines disposable maturity blocks, builds the
signer/relays, starts the loopback explorer bridge, and creates the test-only
extension at `.regtest/dist/chromium`.

Node builds default to two compiler jobs; use `ELEMENTSPLUS_BUILD_JOBS=4 npm run
regtest:start` if the machine has sufficient memory. A new clone explicitly
checks out the pin; the harness refuses to overwrite an existing different or
modified node-source checkout. None of this installs over a running full node.

Check or stop it with:

```sh
npm run regtest:status
npm run regtest:stop
```

## Browser-machine tunnel and extension

Keep this SSH command running on the machine with Chromium. Replace `helsinki`
only if that is not the SSH host/alias used for this server:

```sh
ssh -N -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:43199:127.0.0.1:43199 \
  -L 127.0.0.1:8788:127.0.0.1:8788 \
  -L 127.0.0.1:9430:127.0.0.1:9430 \
  -L 127.0.0.1:9431:127.0.0.1:9431 \
  helsinki
```

Copy the generated unpacked extension to the browser machine:

```sh
scp -r helsinki:/home/codexhost/elementsplus-wallet-test/.regtest/dist/chromium ./elementsplus-regtest-extension
```

Open `chrome://extensions`, enable Developer mode, choose **Load unpacked**,
and select `elementsplus-regtest-extension`. Confirm that its name contains
`LOCAL REGTEST`. Record the 32-letter extension ID shown by Chromium.

Create a brand-new disposable wallet in the extension, unlock it, and copy its
`ert1...` receive address. Never import an existing phrase.

## Fund the wallet

In the unprivileged server shell opened above, replacing the address:

```sh
cd /home/codexhost/elementsplus-wallet-test
npm run regtest:session -- WALLET_ert1_ADDRESS
```

That command sends 0.01 regtest ECX to the address and mines one block. Open the
wallet, unlock it and it should show 0.01 ECX. Send a small amount back to the
same receive address from **Send**, review it on the confirm screen and approve.
The transaction appears under **Activity → Pending**; mine it:

```sh
npm run regtest:mine
```

Refresh the wallet; the transaction should now be block-confirmed.

Preconfirmations are no longer part of the wallet (V2 spec §0); the
`services/` and `vendor/elementsplus-preconf` sources are parked and are not
built or started by this harness.

If node and browser are on the same Linux machine, omit SSH/SCP, load your local
`.regtest/dist/chromium`, and run the session/mine commands in that same clone.

## Scope

A successful run exercises real wallet signing, the node RPC boundary, exact funded bond
validation, durable signer decision, receipt fanout to two WebSocket relays,
browser BIP340 verification, broadcast and block settlement. Both relays share
one host in this harness, so it does not prove independent operation, economic
security, public BIP301/BMM behavior, reorg safety or production readiness.
