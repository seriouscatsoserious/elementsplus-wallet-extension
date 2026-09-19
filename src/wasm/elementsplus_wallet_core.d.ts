export interface InitOutput {
  readonly memory: WebAssembly.Memory;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export default function init(moduleOrPath?: InitInput | Promise<InitInput>): Promise<InitOutput>;

export function initSync(module: { readonly module: BufferSource | WebAssembly.Module }): InitOutput;

export function generate_mnemonic(): string;
export function validate_mnemonic(mnemonic: string): boolean;

export class WasmWalletCore {
  constructor(mnemonic: string);
  derive_address_json(branch: string, index: number): string;
  prepare_send_json(requestJson: string): string;
  sign_prepared_json(preparedJson: string, approvedReviewHash: string): string;
  verify_raw_transaction_json(requestJson: string): string;
  free(): void;
}
