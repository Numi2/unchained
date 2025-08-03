import { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { WalletInfo, NodeStatus, EpochInfo, BlockInfo } from '@/types/blockchain';

export const useBlockchain = () => {
  const [walletInfo, setWalletInfo] = useState<WalletInfo | null>(null);
  const [nodeStatus, setNodeStatus] = useState<NodeStatus>({
    running: false,
    mining: false,
    peers: 0,
    coins_mined: 0,
  });
  const [recentEpochs, setRecentEpochs] = useState<EpochInfo[]>([]);
  const [recentBlocks, setRecentBlocks] = useState<BlockInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>('');

  const clearError = () => setError('');

  const loadConfig = useCallback(async (configPath: string): Promise<string> => {
    try {
      const result = await invoke<string>('load_config', { configPath });
      return result;
    } catch (err) {
      throw new Error(`Failed to load config: ${err}`);
    }
  }, []);

  const getWalletInfo = useCallback(async () => {
    try {
      const info = await invoke<WalletInfo | null>('get_wallet_info');
      setWalletInfo(info);
      return info;
    } catch (err) {
      setError(`Failed to get wallet info: ${err}`);
      return null;
    }
  }, []);

  const unlockWallet = useCallback(async (passphrase: string) => {
    setLoading(true);
    setError('');
    try {
      const info = await invoke<WalletInfo>('unlock_wallet', { passphrase });
      setWalletInfo(info);
      return info;
    } catch (err) {
      setError(`Failed to unlock wallet: ${err}`);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const getNodeStatus = useCallback(async () => {
    try {
      const status = await invoke<NodeStatus>('get_node_status');
      setNodeStatus(status);
      return status;
    } catch (err) {
      setError(`Failed to get node status: ${err}`);
      return {
        running: false,
        mining: false,
        peers: 0,
        coins_mined: 0,
      } as NodeStatus;
    }
  }, []);

  const getRecentEpochs = useCallback(async (limit: number = 10) => {
    try {
      const epochs = await invoke<EpochInfo[]>('get_recent_epochs', { limit });
      setRecentEpochs(epochs);
      return epochs;
    } catch (err) {
      setError(`Failed to get recent epochs: ${err}`);
      return [];
    }
  }, []);

  const getRecentBlocks = useCallback(async (limit: number = 10) => {
    try {
      const blocks = await invoke<BlockInfo[]>('get_recent_blocks', { limit });
      setRecentBlocks(blocks);
      return blocks;
    } catch (err) {
      setError(`Failed to get recent blocks: ${err}`);
      return [];
    }
  }, []);

  const startNode = useCallback(async (configPath: string) => {
    setLoading(true);
    setError('');
    try {
      const result = await invoke<string>('start_node', { configPath });
      await getNodeStatus();
      return result;
    } catch (err) {
      setError(`Failed to start node: ${err}`);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [getNodeStatus]);

  const stopNode = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const result = await invoke<string>('stop_node');
      await getNodeStatus();
      setWalletInfo(null);
      return result;
    } catch (err) {
      setError(`Failed to stop node: ${err}`);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [getNodeStatus]);

  const toggleMining = useCallback(async (enabled: boolean) => {
    setLoading(true);
    setError('');
    try {
      const result = await invoke<string>('toggle_mining', { enabled });
      await getNodeStatus();
      // Refresh wallet info after mining is toggled to get updated balance
      if (walletInfo) {
        await getWalletInfo();
      }
      return result;
    } catch (err) {
      setError(`Failed to toggle mining: ${err}`);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [getNodeStatus, walletInfo, getWalletInfo]);

  const createTransfer = useCallback(async (toAddress: string, coinId: string, passphrase: string) => {
    setLoading(true);
    setError('');
    try {
      const result = await invoke<string>('create_transfer', {
        request: {
          to_address: toAddress,
          coin_id: coinId,
          passphrase,
        },
      });
      return result;
    } catch (err) {
      setError(`Failed to create transfer: ${err}`);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const getOwnedCoins = useCallback(async () => {
    try {
      const coins = await invoke<string[]>('get_owned_coins');
      return coins;
    } catch (err) {
      setError(`Failed to get owned coins: ${err}`);
      return [];
    }
  }, []);

  // Auto-refresh data when node is running
  useEffect(() => {
    if (nodeStatus.running) {
      const interval = setInterval(() => {
        getNodeStatus();
        getRecentEpochs();
        getRecentBlocks();
        // Only refresh wallet info every 30 seconds to reduce CLI spam
        if (walletInfo && Date.now() % 30000 < 5000) {
          getWalletInfo();
        }
      }, 10000); // Refresh every 10 seconds instead of 5

      return () => clearInterval(interval);
    }
  }, [nodeStatus.running, walletInfo, getNodeStatus, getRecentEpochs, getRecentBlocks, getWalletInfo]);

  return {
    walletInfo,
    nodeStatus,
    recentEpochs,
    recentBlocks,
    loading,
    error,
    clearError,
    loadConfig,
    getWalletInfo,
    unlockWallet,
    getNodeStatus,
    getRecentEpochs,
    getRecentBlocks,
    startNode,
    stopNode,
    toggleMining,
    createTransfer,
    getOwnedCoins,
  };
};