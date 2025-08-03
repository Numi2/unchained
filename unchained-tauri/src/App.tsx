import { useState } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useBlockchain } from '@/hooks/useBlockchain';
import { Dashboard } from '@/components/Dashboard';
import { Wallet } from '@/components/Wallet';
import { Mining } from '@/components/Mining';
import { Transfer } from '@/components/Transfer';
import { Network } from '@/components/Network';
import { Settings } from '@/components/Settings';
import { 
  Home, 
  Wallet as WalletIcon, 
  Cpu, 
  Send, 
  Network as NetworkIcon, 
  Settings as SettingsIcon,
  AlertTriangle,
  X
} from 'lucide-react';

import { Onboarding } from '@/components/Onboarding';

function App() {
  const {
    walletInfo,
    nodeStatus,
    recentEpochs,
    loading,
    error,
    clearError,
    loadConfig,
    unlockWallet,
    startNode,
    stopNode,
    toggleMining,
    createTransfer,
    getOwnedCoins,
  } = useBlockchain();

  const [activeTab, setActiveTab] = useState('dashboard');

  // Tracks whether the onboarding wizard has already been completed in this
  // session (persists across re-renders but resets on full refresh). We could
  // store this in localStorage if desired.
  const [onboardingDone, setOnboardingDone] = useState(false);

  const handleStartNode = async () => {
    try {
      // Try multiple possible config paths
      await startNode('../../config.toml');
    } catch (error) {
      // Error is handled by the hook
    }
  };

  const handleStopNode = async () => {
    try {
      await stopNode();
    } catch (error) {
      // Error is handled by the hook
    }
  };

  const handleToggleMining = async (enabled: boolean) => {
    try {
      await toggleMining(enabled);
    } catch (error) {
      // Error is handled by the hook
    }
  };

  const handleUnlockWallet = async (passphrase: string) => {
    try {
      await unlockWallet(passphrase);
    } catch (error) {
      // Error is handled by the hook
      throw error;
    }
  };

  const handleCreateTransfer = async (toAddress: string, coinId: string, passphrase: string) => {
    try {
      const result = await createTransfer(toAddress, coinId, passphrase);
      return result;
    } catch (error) {
      // Error is handled by the hook
      throw error;
    }
  };

  // ---------------------------------------------------------------------
  // Onboarding wizard – displayed until the flow is marked as completed.
  // ---------------------------------------------------------------------

  if (!onboardingDone) {
    return (
      <Onboarding
        nodeStatus={nodeStatus}
        walletInfo={walletInfo}
        loading={loading}
        error={error}
        clearError={clearError}
        startNode={startNode}
        unlockWallet={unlockWallet}
        toggleMining={toggleMining}
        onComplete={() => setOnboardingDone(true)}
      />
    );
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <div className="h-8 w-8 bg-gradient-to-br from-primary-500 to-blockchain-500 rounded-lg flex items-center justify-center">
                </div>
                <h1 className="text-xl font-bold">Unchained</h1>
              </div>
             
            </div>
            
            <div className="flex items-center space-x-2">
              <Badge variant={nodeStatus.running ? "default" : "secondary"}>
                {nodeStatus.running ? "Node Online" : "Node Offline"}
              </Badge>
              {walletInfo && (
                <Badge variant="outline">
                  Wallet: {walletInfo.balance} numicoin
                </Badge>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* Error Banner */}
      {error && (
        <div className="bg-red-50 border-b border-red-200">
          <div className="container mx-auto px-4 py-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <AlertTriangle className="h-4 w-4 text-red-500" />
                <span className="text-red-700 text-sm">{error}</span>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={clearError}
                className="text-red-500 hover:text-red-700"
              >
                <X className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Main Content */}
      <main className="container mx-auto px-4 py-6">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-6">
            <TabsTrigger value="dashboard" className="flex items-center space-x-2">
              <Home className="h-4 w-4" />
              <span>Dashboard</span>
            </TabsTrigger>
            <TabsTrigger value="wallet" className="flex items-center space-x-2">
              <WalletIcon className="h-4 w-4" />
              <span>Wallet</span>
            </TabsTrigger>
            <TabsTrigger value="mining" className="flex items-center space-x-2">
              <Cpu className="h-4 w-4" />
              <span>Mining</span>
            </TabsTrigger>
            <TabsTrigger value="transfer" className="flex items-center space-x-2">
              <Send className="h-4 w-4" />
              <span>Transfer</span>
            </TabsTrigger>
            <TabsTrigger value="network" className="flex items-center space-x-2">
              <NetworkIcon className="h-4 w-4" />
              <span>Network</span>
            </TabsTrigger>
            <TabsTrigger value="settings" className="flex items-center space-x-2">
              <SettingsIcon className="h-4 w-4" />
              <span>Settings</span>
            </TabsTrigger>
          </TabsList>

          <div className="mt-6">
            <TabsContent value="dashboard">
              <Dashboard
                nodeStatus={nodeStatus}
                recentEpochs={recentEpochs}
                onStartNode={handleStartNode}
                onStopNode={handleStopNode}
                onToggleMining={handleToggleMining}
                loading={loading}
              />
            </TabsContent>

            <TabsContent value="wallet">
              <Wallet
                walletInfo={walletInfo}
                onUnlockWallet={handleUnlockWallet}
                loading={loading}
              />
            </TabsContent>

            <TabsContent value="mining">
              <Mining
                nodeStatus={nodeStatus}
                recentEpochs={recentEpochs}
                onToggleMining={handleToggleMining}
                loading={loading}
              />
            </TabsContent>

            <TabsContent value="transfer">
              <Transfer
                walletInfo={walletInfo}
                onCreateTransfer={handleCreateTransfer}
                onGetOwnedCoins={getOwnedCoins}
                loading={loading}
              />
            </TabsContent>

            <TabsContent value="network">
              <Network
                nodeStatus={nodeStatus}
                loading={loading}
              />
            </TabsContent>

            <TabsContent value="settings">
              <Settings
                onLoadConfig={loadConfig}
                loading={loading}
              />
            </TabsContent>
          </div>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="border-t bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <div className="flex items-center space-x-4">
              <span>Unchained</span>
              <span>•</span>
              <span>Post-Quantum Blockchain</span>
            </div>
            <div className="flex items-center space-x-4">
             
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;