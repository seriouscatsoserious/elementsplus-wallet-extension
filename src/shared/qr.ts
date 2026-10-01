/*
 * Minimal QR Code encoder (byte mode, all versions 1–40, ECC L/M/Q/H, automatic
 * mask selection). Dependency-free TypeScript.
 *
 * Algorithm structure follows Project Nayuki's "QR Code generator library"
 * (https://www.nayuki.io/page/qr-code-generator-library),
 * Copyright (c) Project Nayuki. MIT License:
 *
 *   Permission is hereby granted, free of charge, to any person obtaining a copy of
 *   this software and associated documentation files (the "Software"), to deal in
 *   the Software without restriction, including without limitation the rights to
 *   use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 *   the Software, and to permit persons to whom the Software is furnished to do so,
 *   subject to the following conditions:
 *   - The above copyright notice and this permission notice shall be included in
 *     all copies or substantial portions of the Software.
 *   - The Software is provided "as is", without warranty of any kind, express or
 *     implied, including but not limited to the warranties of merchantability,
 *     fitness for a particular purpose and noninfringement. In no event shall the
 *     authors or copyright holders be liable for any claim, damages or other
 *     liability, whether in an action of contract, tort or otherwise, arising from,
 *     out of or in connection with the Software or the use or other dealings in the
 *     Software.
 */

export type QrEcc = "L" | "M" | "Q" | "H";

const ECC_ORDINAL: Record<QrEcc, number> = { L: 0, M: 1, Q: 2, H: 3 };
/** Format-information bits per ECC level. */
const ECC_FORMAT_BITS: Record<QrEcc, number> = { L: 1, M: 0, Q: 3, H: 2 };

// Index [ecc][version]; index 0 unused.
const ECC_CODEWORDS_PER_BLOCK: readonly (readonly number[])[] = [
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
];
const NUM_ERROR_CORRECTION_BLOCKS: readonly (readonly number[])[] = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
];

export interface QrCode {
  readonly version: number;
  readonly size: number;
  readonly ecc: QrEcc;
  readonly mask: number;
  /** modules[y][x] — true is dark. */
  readonly modules: readonly (readonly boolean[])[];
}

function getBit(value: number, index: number): boolean {
  return ((value >>> index) & 1) !== 0;
}

export function numRawDataModules(version: number): number {
  let result = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const numAlign = Math.floor(version / 7) + 2;
    result -= (25 * numAlign - 10) * numAlign - 55;
    if (version >= 7) result -= 36;
  }
  return result;
}

export function numDataCodewords(version: number, ecc: QrEcc): number {
  const e = ECC_ORDINAL[ecc];
  return Math.floor(numRawDataModules(version) / 8)
    - ECC_CODEWORDS_PER_BLOCK[e]![version]! * NUM_ERROR_CORRECTION_BLOCKS[e]![version]!;
}

export function eccLayout(version: number, ecc: QrEcc): { readonly blocks: number; readonly eccPerBlock: number; readonly rawCodewords: number } {
  const e = ECC_ORDINAL[ecc];
  return {
    blocks: NUM_ERROR_CORRECTION_BLOCKS[e]![version]!,
    eccPerBlock: ECC_CODEWORDS_PER_BLOCK[e]![version]!,
    rawCodewords: Math.floor(numRawDataModules(version) / 8),
  };
}

// ---- Reed–Solomon over GF(256) with polynomial 0x11D -------------------------

export function gfMultiply(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i -= 1) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

export function reedSolomonDivisor(degree: number): number[] {
  const result = new Array<number>(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i += 1) {
    for (let j = 0; j < result.length; j += 1) {
      result[j] = gfMultiply(result[j]!, root);
      if (j + 1 < result.length) result[j] = result[j]! ^ result[j + 1]!;
    }
    root = gfMultiply(root, 0x02);
  }
  return result;
}

export function reedSolomonRemainder(data: readonly number[], divisor: readonly number[]): number[] {
  const result = new Array<number>(divisor.length).fill(0);
  for (const byte of data) {
    const factor = byte ^ result.shift()!;
    result.push(0);
    divisor.forEach((coefficient, index) => {
      result[index] = result[index]! ^ gfMultiply(coefficient, factor);
    });
  }
  return result;
}

function addEccAndInterleave(data: readonly number[], version: number, ecc: QrEcc): number[] {
  const { blocks: numBlocks, eccPerBlock: blockEccLen, rawCodewords } = eccLayout(version, ecc);
  const numShortBlocks = numBlocks - (rawCodewords % numBlocks);
  const shortBlockLen = Math.floor(rawCodewords / numBlocks);
  const blocks: number[][] = [];
  const divisor = reedSolomonDivisor(blockEccLen);
  for (let i = 0, k = 0; i < numBlocks; i += 1) {
    const dat = data.slice(k, k + shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1));
    k += dat.length;
    const eccBytes = reedSolomonRemainder(dat, divisor);
    if (i < numShortBlocks) dat.push(0);
    blocks.push(dat.concat(eccBytes));
  }
  const result: number[] = [];
  for (let i = 0; i < blocks[0]!.length; i += 1) {
    blocks.forEach((block, j) => {
      if (i !== shortBlockLen - blockEccLen || j >= numShortBlocks) result.push(block[i]!);
    });
  }
  return result;
}

function alignmentPatternPositions(version: number): number[] {
  if (version === 1) return [];
  const numAlign = Math.floor(version / 7) + 2;
  const step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (numAlign * 2 - 2)) * 2;
  const result = [6];
  for (let pos = version * 4 + 10; result.length < numAlign; pos -= step) result.splice(1, 0, pos);
  return result;
}

/** Format bits (15) for an ECC level and mask, including BCH and XOR mask. */
export function formatBits(ecc: QrEcc, mask: number): number {
  const data = (ECC_FORMAT_BITS[ecc] << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i += 1) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | rem) ^ 0x5412;
}

class Builder {
  readonly size: number;
  readonly modules: boolean[][];
  readonly isFunction: boolean[][];

  constructor(readonly version: number, readonly ecc: QrEcc) {
    this.size = version * 4 + 17;
    this.modules = Array.from({ length: this.size }, () => new Array<boolean>(this.size).fill(false));
    this.isFunction = Array.from({ length: this.size }, () => new Array<boolean>(this.size).fill(false));
  }

  set(x: number, y: number, dark: boolean): void {
    this.modules[y]![x] = dark;
    this.isFunction[y]![x] = true;
  }

  drawFunctionPatterns(): void {
    for (let i = 0; i < this.size; i += 1) {
      this.set(6, i, i % 2 === 0);
      this.set(i, 6, i % 2 === 0);
    }
    this.drawFinder(3, 3);
    this.drawFinder(this.size - 4, 3);
    this.drawFinder(3, this.size - 4);
    const positions = alignmentPatternPositions(this.version);
    const n = positions.length;
    for (let i = 0; i < n; i += 1) {
      for (let j = 0; j < n; j += 1) {
        if (!((i === 0 && j === 0) || (i === 0 && j === n - 1) || (i === n - 1 && j === 0))) {
          this.drawAlignment(positions[i]!, positions[j]!);
        }
      }
    }
    this.drawFormatBits(0);
    this.drawVersion();
  }

  drawFormatBits(mask: number): void {
    const bits = formatBits(this.ecc, mask);
    for (let i = 0; i <= 5; i += 1) this.set(8, i, getBit(bits, i));
    this.set(8, 7, getBit(bits, 6));
    this.set(8, 8, getBit(bits, 7));
    this.set(7, 8, getBit(bits, 8));
    for (let i = 9; i < 15; i += 1) this.set(14 - i, 8, getBit(bits, i));
    for (let i = 0; i < 8; i += 1) this.set(this.size - 1 - i, 8, getBit(bits, i));
    for (let i = 8; i < 15; i += 1) this.set(8, this.size - 15 + i, getBit(bits, i));
    this.set(8, this.size - 8, true);
  }

  drawVersion(): void {
    if (this.version < 7) return;
    let rem = this.version;
    for (let i = 0; i < 12; i += 1) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (this.version << 12) | rem;
    for (let i = 0; i < 18; i += 1) {
      const color = getBit(bits, i);
      const a = this.size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      this.set(a, b, color);
      this.set(b, a, color);
    }
  }

  drawFinder(x: number, y: number): void {
    for (let dy = -4; dy <= 4; dy += 1) {
      for (let dx = -4; dx <= 4; dx += 1) {
        const dist = Math.max(Math.abs(dx), Math.abs(dy));
        const xx = x + dx;
        const yy = y + dy;
        if (xx >= 0 && xx < this.size && yy >= 0 && yy < this.size) this.set(xx, yy, dist !== 2 && dist !== 4);
      }
    }
  }

  drawAlignment(x: number, y: number): void {
    for (let dy = -2; dy <= 2; dy += 1) {
      for (let dx = -2; dx <= 2; dx += 1) this.set(x + dx, y + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  }

  drawCodewords(data: readonly number[]): void {
    let i = 0;
    for (let right = this.size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < this.size; vert += 1) {
        for (let j = 0; j < 2; j += 1) {
          const x = right - j;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? this.size - 1 - vert : vert;
          if (!this.isFunction[y]![x] && i < data.length * 8) {
            this.modules[y]![x] = getBit(data[i >>> 3]!, 7 - (i & 7));
            i += 1;
          }
        }
      }
    }
  }

  applyMask(mask: number): void {
    for (let y = 0; y < this.size; y += 1) {
      for (let x = 0; x < this.size; x += 1) {
        if (!this.isFunction[y]![x] && maskApplies(mask, x, y)) this.modules[y]![x] = !this.modules[y]![x];
      }
    }
  }

  penalty(): number {
    const size = this.size;
    const m = this.modules;
    let result = 0;
    const N1 = 3;
    const N2 = 3;
    const N3 = 40;
    const N4 = 10;
    const finderPenalty = (runHistory: number[]): number => {
      const n = runHistory[1]!;
      const core = n > 0 && runHistory[2] === n && runHistory[3] === n * 3 && runHistory[4] === n && runHistory[5] === n;
      return (core && runHistory[0]! >= n * 4 && runHistory[6]! >= n ? 1 : 0)
        + (core && runHistory[6]! >= n * 4 && runHistory[0]! >= n ? 1 : 0);
    };
    const addHistory = (run: number, runHistory: number[]): void => {
      if (runHistory[0] === 0) run += size;
      runHistory.pop();
      runHistory.unshift(run);
    };
    const terminate = (color: boolean, run: number, runHistory: number[]): number => {
      if (color) {
        addHistory(run, runHistory);
        run = 0;
      }
      run += size;
      addHistory(run, runHistory);
      return finderPenalty(runHistory);
    };
    for (let pass = 0; pass < 2; pass += 1) {
      for (let a = 0; a < size; a += 1) {
        let color = false;
        let run = 0;
        const history = [0, 0, 0, 0, 0, 0, 0];
        for (let b = 0; b < size; b += 1) {
          const cell = pass === 0 ? m[a]![b]! : m[b]![a]!;
          if (cell === color) {
            run += 1;
            if (run === 5) result += N1;
            else if (run > 5) result += 1;
          } else {
            addHistory(run, history);
            if (!color) result += finderPenalty(history) * N3;
            color = cell;
            run = 1;
          }
        }
        result += terminate(color, run, history) * N3;
      }
    }
    for (let y = 0; y < size - 1; y += 1) {
      for (let x = 0; x < size - 1; x += 1) {
        const c = m[y]![x];
        if (c === m[y]![x + 1] && c === m[y + 1]![x] && c === m[y + 1]![x + 1]) result += N2;
      }
    }
    let dark = 0;
    for (const row of m) for (const cell of row) if (cell) dark += 1;
    const total = size * size;
    const k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
    result += k * N4;
    return result;
  }
}

export function maskApplies(mask: number, x: number, y: number): boolean {
  switch (mask) {
    case 0: return (x + y) % 2 === 0;
    case 1: return y % 2 === 0;
    case 2: return x % 3 === 0;
    case 3: return (x + y) % 3 === 0;
    case 4: return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
    case 5: return ((x * y) % 2) + ((x * y) % 3) === 0;
    case 6: return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
    case 7: return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
    default: throw new RangeError("mask must be 0..7");
  }
}

/** Build the data codewords (mode, length, payload, terminator, padding) for byte mode. */
export function byteModeCodewords(bytes: Uint8Array, version: number, ecc: QrEcc): number[] {
  const capacityBits = numDataCodewords(version, ecc) * 8;
  const bits: number[] = [];
  const append = (value: number, length: number): void => {
    for (let i = length - 1; i >= 0; i -= 1) bits.push((value >>> i) & 1);
  };
  append(0x4, 4);
  append(bytes.length, version <= 9 ? 8 : 16);
  for (const byte of bytes) append(byte, 8);
  if (bits.length > capacityBits) throw new RangeError("data too long for this version");
  append(0, Math.min(4, capacityBits - bits.length));
  append(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < capacityBits; pad ^= 0xec ^ 0x11) append(pad, 8);
  const result: number[] = [];
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j += 1) byte = (byte << 1) | bits[i + j]!;
    result.push(byte);
  }
  return result;
}

/** Encode text (UTF-8, byte mode) at the smallest version that fits. */
export function encodeQr(text: string, ecc: QrEcc = "M", forcedMask?: number): QrCode {
  const bytes = new TextEncoder().encode(text);
  let version = 1;
  for (; version <= 40; version += 1) {
    const needed = 4 + (version <= 9 ? 8 : 16) + bytes.length * 8;
    if (needed <= numDataCodewords(version, ecc) * 8) break;
  }
  if (version > 40) throw new RangeError("data too long for a QR code");
  const data = byteModeCodewords(bytes, version, ecc);
  const all = addEccAndInterleave(data, version, ecc);
  const builder = new Builder(version, ecc);
  builder.drawFunctionPatterns();
  builder.drawCodewords(all);
  let mask = forcedMask ?? -1;
  if (mask === -1) {
    let best = Infinity;
    for (let candidate = 0; candidate < 8; candidate += 1) {
      builder.applyMask(candidate);
      builder.drawFormatBits(candidate);
      const score = builder.penalty();
      if (score < best) {
        best = score;
        mask = candidate;
      }
      builder.applyMask(candidate);
    }
  }
  builder.applyMask(mask);
  builder.drawFormatBits(mask);
  return Object.freeze({
    version,
    size: builder.size,
    ecc,
    mask,
    modules: Object.freeze(builder.modules.map((row) => Object.freeze([...row]))),
  });
}

/** SVG path data ("M x y h1 v1 h-1 z" per dark module run) for a QR code with a quiet zone. */
export function qrPath(code: QrCode, border = 2): string {
  const parts: string[] = [];
  code.modules.forEach((row, y) => {
    let x = 0;
    while (x < row.length) {
      if (!row[x]) {
        x += 1;
        continue;
      }
      let end = x;
      while (end < row.length && row[end]) end += 1;
      parts.push(`M${x + border} ${y + border}h${end - x}v1h-${end - x}z`);
      x = end;
    }
  });
  return parts.join("");
}
