import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { ECX_ALPHA_IDENTITY } from "../../src/network/identity.js";
import {
  parseBroadcastTransactionResult,
  parsePreparedSendApproval,
  parseSendDraft,
  SendFlowValidationError,
} from "../../src/ui/send-flow.js";

const DESTINATION = "elements1qw508d6qejxtdg4y5r3zarvary0c5xw7kfmp4zh";
const NOW = Date.parse("2026-09-19T12:00:00.000Z");

function preparedResponse(overrides: Readonly<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    approvalToken: "A".repeat(43),
    expiresAt: "2026-09-19T12:02:00.000Z",
    summaryHash: "b".repeat(64),
    summary: {
      kind: "transfer",
      networkKey: ECX_ALPHA_IDENTITY.key,
      genesisHash: ECX_ALPHA_IDENTITY.genesisHash,
      assetId: ECX_ALPHA_IDENTITY.nativeAssetId,
      destination: DESTINATION,
      amountAtomic: "2500",
      networkFeeAssetId: ECX_ALPHA_IDENTITY.nativeAssetId,
      networkFeeAtomic: "125",
      feeRate: "1.25",
      transactionPolicy: "explicit-only",
    },
    ...overrides,
  };
}

describe("wallet send UI boundary", () => {
  it("canonicalizes and validates a native-ECX send draft", () => {
    const draft = parseSendDraft({
      destination: `  ${DESTINATION}  `,
      amountAtomic: "2500",
      feeRate: "1.25",
    });
    assert.deepEqual(draft, {
      assetId: ECX_ALPHA_IDENTITY.nativeAssetId,
      destination: DESTINATION,
      amountAtomic: "2500",
      feeRate: "1.25",
    });
    assert(Object.isFrozen(draft));
  });

  it("rejects non-canonical amounts and fee rates before contacting the controller", () => {
    for (const amountAtomic of ["", "0", "01", "1.0", "-1", "18446744073709551616"]) {
      assert.throws(
        () => parseSendDraft({ destination: DESTINATION, amountAtomic, feeRate: "1" }),
        SendFlowValidationError,
      );
    }
    for (const feeRate of ["", "0", "01", "1.0", ".5", "1e2", "-1"]) {
      assert.throws(
        () => parseSendDraft({ destination: DESTINATION, amountAtomic: "1", feeRate }),
        SendFlowValidationError,
      );
    }
  });

  it("accepts only an unexpired, exact summary for the requested transfer", () => {
    const draft = parseSendDraft({ destination: DESTINATION, amountAtomic: "2500", feeRate: "1.25" });
    const approval = parsePreparedSendApproval(preparedResponse(), draft, NOW);
    assert.equal(approval.summary.destination, DESTINATION);
    assert.equal(approval.summary.networkFeeAtomic, "125");
    assert.equal(approval.summaryHash, "b".repeat(64));
    assert(!("pset" in approval));

    assert.throws(
      () => parsePreparedSendApproval(preparedResponse({ expiresAt: "2026-09-19T11:59:59.000Z" }), draft, NOW),
      /expired/u,
    );
    assert.throws(
      () => parsePreparedSendApproval(preparedResponse({ summary: { ...(preparedResponse()["summary"] as object), amountAtomic: "2501" } }), draft, NOW),
      /does not match/u,
    );
    assert.throws(
      () => parsePreparedSendApproval({ ...preparedResponse(), pset: "must-not-cross-the-boundary" }, draft, NOW),
      /malformed/u,
    );
    assert.throws(
      () => parsePreparedSendApproval(preparedResponse({
        summary: { ...(preparedResponse()["summary"] as object), networkFeeAtomic: "0" },
      }), draft, NOW),
      /greater than zero/u,
    );
  });

  it("validates a broadcast transaction ID and rejects extra response data", () => {
    assert.deepEqual(parseBroadcastTransactionResult({ txid: "c".repeat(64), settlement: "preconfirmed" }), { txid: "c".repeat(64), settlement: "preconfirmed" });
    assert.throws(() => parseBroadcastTransactionResult({ txid: "nope", settlement: "broadcast" }), SendFlowValidationError);
    assert.throws(
      () => parseBroadcastTransactionResult({ txid: "c".repeat(64), settlement: "broadcast", rawTransaction: "00" }),
      SendFlowValidationError,
    );
  });
});
