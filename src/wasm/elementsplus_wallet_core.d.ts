export interface InitOutput {
  readonly memory: WebAssembly.Memory;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export default function init(moduleOrPath?: InitInput | Promise<InitInput>): Promise<InitOutput>;

export function initSync(module: { readonly module: BufferSource | WebAssembly.Module }): InitOutput;

// All request/response JSON is snake_case. Amounts are decimal strings of
// atomic units; `fee` / `fee_rate` are integers. See docs/V2-SPEC.md §1.3.
export function generate_mnemonic(): string;
export function validate_mnemonic(mnemonic: string): boolean;
/** `{raw_tx_hex, expected_txid, vin, contract}` → `{asset_id, token_id|null, contract_hash}`. */
export function verify_asset_issuance_json(requestJson: string): string;
/** Id of the network profile compiled into this WASM build (absent if none). */
export function network_profile_id(): string | undefined;
/** Verifies against the compiled network profile → DecodedOffer JSON. */
export function decode_offer_json(offerJson: string, prevoutRawTxHex: string): string;

export class WasmWalletCore {
  /** Pins come only from the compiled profile; throws for a regtest or pending build. */
  constructor(mnemonic: string);
  static forRegtest?(
    mnemonic: string,
    genesisHash: string,
    policyAsset: string,
    displayName: string,
  ): WasmWalletCore;
  derive_address_json(branch: string, index: number): string;
  /** camelCase request/response, unchanged from v1. */
  verify_raw_transaction_json(requestJson: string): string;
  /** Each prepare_* returns PreparedTx JSON `{pset_base64, review, review_hash}`. */
  prepare_transfer_json(requestJson: string): string;
  prepare_issuance_json(requestJson: string): string;
  prepare_offer_split_json(requestJson: string): string;
  prepare_swap_offer_json(requestJson: string): string;
  /** `req.offers: [{ offer, prevout_raw_tx_hex }]`; `offer` may be an object or its JSON string. */
  take_swap_offers_json(requestJson: string): string;
  prepare_cancel_json(requestJson: string): string;
  /** → `{ txid, review_hash, raw_tx_hex?: string, offer?: Offer }` */
  sign_prepared_json(preparedJson: string, approvedReviewHash: string): string;
  /** Like the free `decode_offer_json`, but against this wallet's network (useful on regtest). */
  decode_offer_json(offerJson: string, prevoutRawTxHex: string): string;
  free(): void;
}
