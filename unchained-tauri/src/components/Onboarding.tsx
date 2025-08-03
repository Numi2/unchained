import { useState } from 'react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { AlertTriangle, Check, Loader2 } from 'lucide-react';

import { NodeStatus, WalletInfo } from '@/types/blockchain';

interface OnboardingProps {
  /** Current node status */
  nodeStatus: NodeStatus;
  /** Current wallet information (may be null if locked / not yet created) */
  walletInfo: WalletInfo | null;

  /** Indicates whether a request is currently running */
  loading: boolean;

  /** Optional error message coming from the blockchain hook */
  error: string;
  clearError: () => void;

  /** Starts the Rust node */
  startNode: (configPath: string) => Promise<any>;
  /** Unlocks or creates the wallet */
  unlockWallet: (passphrase: string) => Promise<any>;
  /** Enables / disables mining */
  toggleMining: (enabled: boolean) => Promise<any>;

  /** Called once the onboarding flow has successfully completed */
  onComplete: () => void;
}

/**
 * Very lightweight wizard that guides a novice (“simpleton”) user through the
 * three essential steps required to get going:
 * 1. Enter a pass-phrase
 * 2. Spin up the local node and open / create the wallet
 * 3. Start mining coins
 */
export function Onboarding({
  nodeStatus,
  walletInfo,
  loading,
  error,
  clearError,
  startNode,
  unlockWallet,
  toggleMining,
  onComplete,
}: OnboardingProps) {
  /** Local wizard step */
  const [step, setStep] = useState<'form' | 'readyToMine' | 'completed'>('form');

  /** Pass-phrase that the user enters */
  const [passphrase, setPassphrase] = useState('');

  /** Internal loading state so that we can disable the buttons while we wait */
  const [submitting, setSubmitting] = useState(false);

  /** Handles the primary “Start” button: spins up the node then unlocks wallet */
  const handleStart = async () => {
    if (submitting) return;
    setSubmitting(true);
    clearError();

    try {
      // 1) Boot the node. The config file lives two directories above the
      //    frontend source (../../config.toml when executed from the FE).
      await startNode('../../config.toml');

      // 2) Unlock or create the wallet using the given pass-phrase. Falling
      //    back to a default pass-phrase feels wrong from a security stand-
      //    point, therefore we enforce a non-empty pass-phrase here.
      await unlockWallet(passphrase.trim());

      setStep('readyToMine');
    } finally {
      setSubmitting(false);
    }
  };

  /** Handles the “Start mining” button */
  const handleStartMining = async () => {
    if (submitting) return;
    setSubmitting(true);
    clearError();

    try {
      await toggleMining(true);
      setStep('completed');

      // Inform parent component (App) that the wizard is done so that it will
      // not be shown again.
      onComplete();
    } finally {
      setSubmitting(false);
    }
  };

  // ---------------------------------------------------------------------
  // UI helpers
  // ---------------------------------------------------------------------

  const renderError = () => {
    if (!error) return null;
    return (
      <div className="flex items-center space-x-2 text-red-600 text-sm mt-4">
        <AlertTriangle className="h-4 w-4" />
        <span>{error}</span>
      </div>
    );
  };

  if (step === 'completed' && nodeStatus.running && walletInfo && nodeStatus.mining) {
    // Wizard is done – render nothing so that the main application takes over.
    return null;
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-6">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>
            {step === 'form' && 'Welcome to Unchained'}
            {step === 'readyToMine' && 'All set!'}
          </CardTitle>
          <CardDescription>
            {step === 'form' && 'Enter a passphrase to create / unlock your wallet and start the node.'}
            {step === 'readyToMine' && 'Your node & wallet are ready. Start mining to earn coins.'}
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-6">
          {step === 'form' && (
            <>
              <div className="space-y-2">
                <Label htmlFor="passphrase">Passphrase</Label>
                <Input
                  id="passphrase"
                  type="password"
                  placeholder="Choose a strong passphrase"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                />
              </div>

              <Button
                className="w-full"
                disabled={submitting || passphrase.trim().length === 0 || loading}
                onClick={handleStart}
              >
                {submitting || loading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Starting…
                  </>
                ) : (
                  'Start'
                )}
              </Button>

              {renderError()}
            </>
          )}

          {step === 'readyToMine' && (
            <>
              <div className="flex items-center space-x-2 text-green-600">
                <Check className="h-5 w-5" />
                <span>Node running and wallet unlocked</span>
              </div>

              <Button
                className="w-full"
                disabled={submitting || loading}
                onClick={handleStartMining}
              >
                {submitting || loading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Starting miner…
                  </>
                ) : (
                  'Start mining'
                )}
              </Button>

              {renderError()}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
