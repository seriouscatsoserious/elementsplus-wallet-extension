import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  byteModeCodewords,
  eccLayout,
  encodeQr,
  formatBits,
  maskApplies,
  qrPath,
  reedSolomonDivisor,
  reedSolomonRemainder,
  type QrCode,
  type QrEcc,
} from "../../src/shared/qr.js";

// Matrices produced by the independent python-qrcode 8.x encoder (byte mode, ECC M,
// fixed mask), each row as a big-endian bit string (leftmost module = MSB).
const REFERENCE_VECTORS: readonly { text: string; version: number; mask: number; rows: readonly string[] }[] = [
  {
    text: "hello",
    version: 1,
    mask: 2,
    rows: ["0x1fc07f", "0x104b41", "0x17575d", "0x17555d", "0x17555d", "0x105241", "0x1fd57f", "0x1400", "0x17c67c", "0x1d27cd", "0xd416e", "0x1a3cc", "0xa7921", "0x1d29", "0x1fca96", "0x10543e", "0x175a92", "0x175be8", "0x175164", "0x104bdc", "0x1fd112"],
  },
  {
    text: "elements1qw508d6qejxtdg4y5r3zarvary0c5xw7kfmp4zh",
    version: 4,
    mask: 3,
    rows: ["0x1fd19ff7f", "0x105285241", "0x174f3b45d", "0x17525105d", "0x174a49d5d", "0x104087541", "0x1fd55557f", "0x1609300", "0x16e64fb4b", "0x1f0857bcb", "0x17f25970b", "0x4aef65b8", "0xde126590", "0x10ad9c5a8", "0x1d763c0b4", "0xf0353ace", "0xbc932b77", "0xab83da7b", "0x1bd2280be", "0x11a8231b0", "0xb73058a4", "0x18b7a4ae1", "0x3c05cf73", "0xf28d2612", "0x12e2f87f8", "0x187ed16", "0x1fd843758", "0x105531b1d", "0x174e493fd", "0x1754cf601", "0x1759469c4", "0x104dbe7e1", "0x1fd5a8a74"],
  },
  {
    text: "ert1q6rz28mcfaxtmd6v789l9rrlrusdprr9p69dllk",
    version: 4,
    mask: 5,
    rows: ["0x1fc189c7f", "0x105b05141", "0x175443e5d", "0x175f5555d", "0x174f79c5d", "0x104366341", "0x1fd55557f", "0x1677600", "0x1052df7ce", "0x1925abab6", "0x1759e8472", "0x7009fb8c", "0x1f518ab43", "0x3b10c947", "0x17d435872", "0x2a79173f", "0x14de971a", "0x1886b76ef", "0x5e4bfe6d", "0xb13e3424", "0xbf724b9a", "0x19acc8214", "0x12e1c2d22", "0x138fb7047", "0x1ef3c41f2", "0x1a7a915", "0x1fcb6875e", "0x10483cf1e", "0x174f31df8", "0x1742cc931", "0x17436ea37", "0x104d804ec", "0x1fdff872a"],
  },
];

function rowsToHex(code: QrCode): string[] {
  return code.modules.map((row) => `0x${BigInt(`0b${row.map((cell) => (cell ? "1" : "0")).join("")}`).toString(16)}`);
}

/** Independent minimal decoder: format info → unmask → zig-zag read → de-interleave → byte mode. */
function decode(code: QrCode): { text: string; ecc: QrEcc; mask: number; blocks: number[][] } {
  const size = code.size;
  const m = code.modules;
  const bit = (x: number, y: number) => (m[y]![x] ? 1 : 0);
  // Read format bits from the copy around the top-left finder.
  let raw = 0;
  const coords: [number, number][] = [];
  for (let i = 0; i <= 5; i += 1) coords.push([8, i]);
  coords.push([8, 7], [8, 8], [7, 8]);
  for (let i = 9; i < 15; i += 1) coords.push([14 - i, 8]);
  coords.forEach(([x, y], i) => { raw |= bit(x, y) << i; });
  let found: { ecc: QrEcc; mask: number } | undefined;
  for (const ecc of ["L", "M", "Q", "H"] as const) {
    for (let mask = 0; mask < 8; mask += 1) if (formatBits(ecc, mask) === raw) found = { ecc, mask };
  }
  assert.ok(found, "format information decodes");
  const version = (size - 17) / 4;
  // Function-module map (finders+separators+format, timing, alignment, version).
  const fn = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const mark = (x0: number, y0: number, w: number, h: number) => {
    for (let y = y0; y < y0 + h; y += 1) for (let x = x0; x < x0 + w; x += 1) if (x >= 0 && y >= 0 && x < size && y < size) fn[y]![x] = true;
  };
  mark(0, 0, 9, 9); mark(size - 8, 0, 8, 9); mark(0, size - 8, 9, 8);
  mark(6, 0, 1, size); mark(0, 6, size, 1);
  if (version >= 2) {
    const n = Math.floor(version / 7) + 2;
    const step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (n * 2 - 2)) * 2;
    const pos = [6];
    for (let p = size - 7; pos.length < n; p -= step) pos.splice(1, 0, p);
    for (const ax of pos) for (const ay of pos) {
      if ((ax === 6 && ay === 6) || (ax === 6 && ay === size - 7) || (ax === size - 7 && ay === 6)) continue;
      mark(ax - 2, ay - 2, 5, 5);
    }
  }
  if (version >= 7) { mark(size - 11, 0, 3, 6); mark(0, size - 11, 6, 3); }
  const bits: number[] = [];
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert += 1) {
      for (let j = 0; j < 2; j += 1) {
        const x = right - j;
        const y = ((right + 1) & 2) === 0 ? size - 1 - vert : vert;
        if (!fn[y]![x]) bits.push(bit(x, y) ^ (maskApplies(found.mask, x, y) ? 1 : 0));
      }
    }
  }
  const { blocks: numBlocks, eccPerBlock, rawCodewords } = eccLayout(version, found.ecc);
  const codewords: number[] = [];
  for (let i = 0; i + 8 <= rawCodewords * 8; i += 8) codewords.push(parseInt(bits.slice(i, i + 8).join(""), 2));
  const shortCount = numBlocks - (rawCodewords % numBlocks);
  const shortLen = Math.floor(rawCodewords / numBlocks);
  const dataLens = Array.from({ length: numBlocks }, (_, i) => shortLen - eccPerBlock + (i < shortCount ? 0 : 1));
  const blocks = dataLens.map(() => [] as number[]);
  let k = 0;
  for (let i = 0; i < Math.max(...dataLens); i += 1) for (let b = 0; b < numBlocks; b += 1) if (i < dataLens[b]!) blocks[b]!.push(codewords[k++]!);
  for (let i = 0; i < eccPerBlock; i += 1) for (let b = 0; b < numBlocks; b += 1) blocks[b]!.push(codewords[k++]!);
  const data = blocks.flatMap((block, b) => block.slice(0, dataLens[b]));
  const stream = data.map((byte) => byte.toString(2).padStart(8, "0")).join("");
  assert.equal(stream.slice(0, 4), "0100", "byte mode indicator");
  const countBits = version <= 9 ? 8 : 16;
  const length = parseInt(stream.slice(4, 4 + countBits), 2);
  const payload = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) payload[i] = parseInt(stream.slice(4 + countBits + i * 8, 12 + countBits + i * 8), 2);
  return { text: new TextDecoder().decode(payload), ecc: found.ecc, mask: found.mask, blocks };
}

/** Evaluate a received block as a polynomial at α^i; all syndromes are zero for a valid RS codeword. */
function syndromesZero(block: readonly number[], eccLength: number): boolean {
  const mul = (x: number, y: number) => {
    let z = 0;
    for (let i = 7; i >= 0; i -= 1) { z = (z << 1) ^ ((z >>> 7) * 0x11d); z ^= ((y >>> i) & 1) * x; }
    return z;
  };
  let alpha = 1;
  for (let i = 0; i < eccLength; i += 1) {
    let acc = 0;
    for (const byte of block) acc = mul(acc, alpha) ^ byte;
    if (acc !== 0) return false;
    alpha = mul(alpha, 2);
  }
  return true;
}

describe("QR encoder", () => {
  it("matches the ISO/IEC 18004 Reed–Solomon example (1-M, \"01234567\")", () => {
    const data = [0x10, 0x20, 0x0c, 0x56, 0x61, 0x80, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11];
    const expected = [0xa5, 0x24, 0xd4, 0xc1, 0xed, 0x36, 0xc7, 0x87, 0x2c, 0x55];
    assert.deepEqual(reedSolomonRemainder(data, reedSolomonDivisor(10)), expected);
  });

  it("produces the standard format-information strings", () => {
    assert.equal(formatBits("M", 0), 0b101010000010010);
    assert.equal(formatBits("L", 0), 0b111011111000100);
    assert.equal(formatBits("H", 7), 0b000100000111011);
  });

  it("pads byte-mode data with the alternating 0xEC/0x11 pattern", () => {
    const codewords = byteModeCodewords(new TextEncoder().encode("A"), 1, "M");
    assert.equal(codewords.length, 16);
    assert.deepEqual(codewords.slice(0, 3), [0x40, 0x14, 0x10]);
    assert.deepEqual(codewords.slice(3, 7), [0xec, 0x11, 0xec, 0x11]);
  });

  for (const vector of REFERENCE_VECTORS) {
    it(`matches an independent encoder bit-for-bit (${vector.text.slice(0, 12)}…, v${vector.version})`, () => {
      const code = encodeQr(vector.text, "M", vector.mask);
      assert.equal(code.version, vector.version);
      assert.deepEqual(rowsToHex(code), vector.rows);
    });
  }

  it("round-trips addresses through an independent decoder with valid RS blocks", () => {
    const inputs = [
      "elements1qw508d6qejxtdg4y5r3zarvary0c5xw7kfmp4zh",
      "ert1q6rz28mcfaxtmd6v789l9rrlrusdprr9p69dllk",
      `elements1${"q".repeat(200)}`,
      "x".repeat(400),
    ];
    for (const text of inputs) {
      for (const ecc of ["L", "M", "Q", "H"] as const) {
        const code = encodeQr(text, ecc);
        const decoded = decode(code);
        assert.equal(decoded.text, text);
        assert.equal(decoded.ecc, ecc);
        const { eccPerBlock } = eccLayout(code.version, ecc);
        for (const block of decoded.blocks) assert.ok(syndromesZero(block, eccPerBlock));
      }
    }
  });

  it("uses version 7+ version information for long payloads", () => {
    const code = encodeQr("y".repeat(200), "M");
    assert.ok(code.version >= 7);
    assert.equal(decode(code).text, "y".repeat(200));
  });

  it("emits SVG path data for dark modules only", () => {
    const code = encodeQr("hello", "M", 2);
    const path = qrPath(code, 2);
    assert.match(path, /^M2 2h7v1h-7z/u);
    assert.ok(!/[^Mhvz0-9 -]/u.test(path));
  });
});
