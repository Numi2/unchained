// TypeScript types for blockchain data
export interface WalletInfo {
  address: string;
  balance: number;
  unlocked: boolean;
}

export interface NodeStatus {
  running: boolean;
  mining: boolean;
  peers: number;
  current_epoch?: number;
  difficulty?: number;
  coins_mined: number;
}

export interface EpochInfo {
  num: number;
  hash: string;
  difficulty: number;
  coin_count: number;
  cumulative_work: string;
  mem_kib: number;
}

export interface TransferRequest {
  to_address: string;
  coin_id: string;
  passphrase: string;
}

export interface NetworkPeer {
  id: string;
  address: string;
  connected: boolean;
}

export interface Config {
  net: {
    listen_port: number;
    max_peers: number;
    connection_timeout_secs: number;
    bootstrap: string[];
  };
  storage: {
    path: string;
  };
  epoch: {
    seconds: number;
    target_leading_zeros: number;
    target_coins_per_epoch: number;
    retarget_interval: number;
    max_difficulty_adjustment: number;
  };
  mining: {
    enabled: boolean;
    mem_kib: number;
    lanes: number;
    min_mem_kib: number;
    max_mem_kib: number;
    max_memory_adjustment: number;
    heartbeat_interval_secs: number;
    max_consecutive_failures: number;
    max_mining_attempts: number;
  };
  metrics: {
    bind: string;
  };
}