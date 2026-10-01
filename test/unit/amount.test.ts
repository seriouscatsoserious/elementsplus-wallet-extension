import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  AmountError,
  atomicToDecimalInput,
  FEE_PRESETS,
  formatAtomic,
  MAX_U64,
  parseDecimalAmount,
} from "../../src/shared/amount.js";

describe("amount parsing", () => {
  it("parses decimals into atomic units with the asset precision", () => {
    assert.equal(parseDecimalAmount("25", 8), 2_500_000_000n);
    assert.equal(parseDecimalAmount("0.00000001", 8), 1n);
    assert.equal(parseDecimalAmount("1,284.5", 8), 128_450_000_000n);
    assert.equal(parseDecimalAmount(".5", 2), 50n);
    assert.equal(parseDecimalAmount("7.", 2), 700n);
    assert.equal(parseDecimalAmount("12000", 0), 12_000n);
    assert.equal(parseDecimalAmount("  3 000 ", 0), 3_000n);
  });

  it("rejects malformed, negative, too-precise and oversized input", () => {
    for (const bad of ["", " ", "-1", "1e5", "1.2.3", "abc", ".", "0x10", "1.5", "NaN"]) {
      assert.throws(() => parseDecimalAmount(bad, 0), AmountError, bad);
    }
    assert.throws(() => parseDecimalAmount("0.000000001", 8), /at most 8 decimal/u);
    assert.throws(() => parseDecimalAmount("1.5", 0), /no decimal places/u);
    assert.throws(() => parseDecimalAmount((MAX_U64 + 1n).toString(), 0), /too large/u);
    assert.equal(parseDecimalAmount(MAX_U64.toString(), 0), MAX_U64);
    assert.throws(() => parseDecimalAmount("1", 9), /precision/u);
  });

  it("formats atomic values without floating point", () => {
    assert.equal(formatAtomic(128_450_000_000n, 8), "1,284.5");
    assert.equal(formatAtomic(128_450_000_000n, 8, { minFraction: 2 }), "1,284.50");
    assert.equal(formatAtomic("210", 8), "0.0000021");
    assert.equal(formatAtomic(-2_500_000_000n, 8, { minFraction: 2 }), "−25.00");
    assert.equal(formatAtomic(5_000n, 0, { signed: true }), "+5,000");
    assert.equal(formatAtomic(0n, 8, { signed: true }), "0");
    assert.equal(formatAtomic(MAX_U64, 8, { grouping: false }), "184467440737.09551615");
    assert.equal(atomicToDecimalInput(123_456_789n, 8), "1.23456789");
  });

  it("round-trips every precision", () => {
    for (let precision = 0; precision <= 8; precision += 1) {
      for (const value of [0n, 1n, 10n, 123_456_789n, MAX_U64]) {
        assert.equal(parseDecimalAmount(atomicToDecimalInput(value, precision), precision), value);
      }
    }
  });

  it("exposes integer fee presets", () => {
    assert.deepEqual(
      Object.values(FEE_PRESETS).map((preset) => preset.satPerVbyte),
      [1, 2, 5],
    );
  });
});
