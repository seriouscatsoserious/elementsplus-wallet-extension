// Build the pinned Elements+ node's actual Simplicity C interpreter and run the
// fixtures from `cargo run --example vectors` through it.
// Adapted from JK's elementsplus-preconf scripts/check-fork.mjs (adds the input
// index; fixtures carry their own expected result).
// Usage: node scripts/check-fork.mjs /path/to/elementsplus-node
import { spawnSync } from 'node:child_process';
import { mkdirSync, realpathSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
if (process.argv.length !== 3) throw new Error('Pass the node checkout');
const node = realpathSync(process.argv[2]);
const expected = '4041a8ba5d9c0870dbe22c188bce28410c10348a';
function run(command, args, options = {}) {
  const r = spawnSync(command, args, { cwd: root, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, ...options });
  if (r.error || r.status !== 0) throw new Error(`${command} failed: ${r.error ?? r.stderr ?? r.status}`);
  return r.stdout;
}
assert.equal(
  run('git', ['-C', node, 'rev-parse', 'HEAD:src/simplicity']).trim(),
  run('git', ['-C', node, 'rev-parse', expected + ':src/simplicity']).trim(),
  'fork interpreter differs from the pinned baseline',
);
run('git', ['-C', node, 'diff', '--exit-code', 'HEAD', '--', 'src/simplicity']);
const target = join(root, 'target', 'fork-vm');
mkdirSync(target, { recursive: true });
const sources = ['bitstream','cmr','dag','deserialize','eval','frame','jets','jets-secp256k1',
  'rsort','sha256','type','typeInference','elements/env','elements/exec','elements/ops',
  'elements/elementsJets','elements/primitive','elements/cmr','elements/txEnv'];
const executable = join(target, 'verify');
run('cc', ['-std=c11','-O2','-DPRODUCTION', '-I',join(node,'src/simplicity/include'),
  join(root,'tests/fork_vm.c'), ...sources.map(s => join(node, 'src/simplicity', `${s}.c`)),
  '-o', executable]);
const fixtures = JSON.parse(run('cargo', ['run', '--quiet', '--example', 'vectors']));

const u32 = n => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const blob = h => {
  assert.match(h, /^(?:[0-9a-f]{2})*$/);
  const b = Buffer.from(h, 'hex'); return Buffer.concat([u32(b.length), b]);
};
function encode(f) {
  const chunks = [f.program, f.witness, f.cmr, f.control, f.genesis, f.txid].map(blob);
  chunks.push(u32(f.version), u32(f.lock_time), u32(f.index), u32(f.inputs.length));
  for (const i of f.inputs) chunks.push(blob(i.txid), u32(i.vout), u32(i.sequence), blob(i.asset), blob(i.value), blob(i.script));
  chunks.push(u32(f.outputs.length));
  for (const o of f.outputs) chunks.push(blob(o.asset), blob(o.value), blob(o.script));
  return Buffer.concat(chunks);
}
let count = 0;
for (const f of fixtures.vectors) {
  const r = JSON.parse(run(executable, [], { input: encode(f) }));
  assert.equal(r.error === 0, f.pass, `${f.name}: ${JSON.stringify(r)}`);
  console.log(`PASS ${f.pass ? 'accept' : 'reject'} ${f.name} (interpreter=${r.error}, budget=${r.budget} WU, program=${f.program.length / 2} B, witness=${f.witness.length / 2} B)`);
  count++;
}
console.log(`lockbox CMR ${fixtures.lockbox_cmr}`);
console.log(`bond CMR    ${fixtures.bond_cmr}`);
console.log(`${count} pinned-fork interpreter checks passed. No full-node test here.`);
