export interface ReceiptObservation {
  readonly monitoringReady: boolean;
  readonly conflicted: boolean;
  readonly observedEverywhere: boolean;
}

export class ReceiptMonitor extends EventTarget {
  constructor(options: {
    readonly profile: string;
    readonly bonds: readonly string[];
    readonly relays: readonly string[];
    readonly verifyReceipt: (receipt: Readonly<{ bond: string; txid: string; signature: string }>) => boolean | Promise<boolean>;
    readonly WebSocketImpl?: typeof WebSocket;
    readonly staleMs?: number;
    readonly reconnectMs?: number;
  });
  start(): void;
  stop(): void;
  health(): { readonly monitoringReady: boolean };
  observation(bond: string, txid: string): ReceiptObservation;
}
