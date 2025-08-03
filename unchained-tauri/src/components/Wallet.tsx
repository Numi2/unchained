import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { WalletInfo } from '@/types/blockchain';
import { Wallet as WalletIcon, Lock, Unlock, Copy, CheckCircle2 } from 'lucide-react';

interface WalletProps {
  walletInfo: WalletInfo | null;
  onUnlockWallet: (passphrase: string) => Promise<void>;
  loading: boolean;
}

export function Wallet({ walletInfo, onUnlockWallet, loading }: WalletProps) {
  const [passphrase, setPassphrase] = useState('');
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (passphrase.trim()) {
      try {
        await onUnlockWallet(passphrase);
        setPassphrase('');
      } catch (error) {
        // Error is handled by the parent component
      }
    }
  };

  const copyAddress = async () => {
    if (walletInfo?.address) {
      await navigator.clipboard.writeText(walletInfo.address);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center space-x-2">
        <WalletIcon className="h-6 w-6" />
        <h1 className="text-3xl font-bold">Wallet</h1>
      </div>

      {!walletInfo ? (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <Lock className="h-5 w-5" />
              <span>Unlock Wallet</span>
            </CardTitle>
         
          </CardHeader>
          <CardContent>
            <form onSubmit={handleUnlock} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="passphrase">Passphrase</Label>
                <Input
                  id="passphrase"
                  type={showPassphrase ? "text" : "password"}
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  placeholder="Enter your wallet passphrase"
                  required
                />
              </div>
              
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="show-passphrase"
                  checked={showPassphrase}
                  onChange={(e) => setShowPassphrase(e.target.checked)}
                  className="rounded"
                />
                <Label htmlFor="show-passphrase" className="text-sm">
                  Show passphrase
                </Label>
              </div>

              <Button type="submit" disabled={loading || !passphrase.trim()}>
                {loading ? "Unlocking..." : "Unlock Wallet"}
              </Button>
            </form>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {/* Wallet Status */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Unlock className="h-5 w-5 text-green-500" />
                <span>Wallet Unlocked</span>
              </CardTitle>
              <CardDescription>
                Your wallet is ready for transactions
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center space-x-2">
                <Badge variant="default" className="bg-green-500">
                  <CheckCircle2 className="mr-1 h-3 w-3" />
                  Unlocked
                </Badge>
              </div>
            </CardContent>
          </Card>

          {/* Balance */}
          <Card>
            <CardHeader>
              <CardTitle>Balance</CardTitle>
           
          
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold">
                {walletInfo.balance} 
                <span className="text-sm font-normal text-muted-foreground ml-2">
                  numicoin
                </span>
              </div>
            </CardContent>
          </Card>

          {/* Address */}
          <Card>
            <CardHeader>
              <CardTitle>Wallet Address</CardTitle>
              <CardDescription>
                Your public wallet address for receiving coins
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <div className="flex items-center space-x-2">
                  <code className="bg-muted px-3 py-2 rounded text-sm break-all flex-1">
                    {walletInfo.address}
                  </code>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={copyAddress}
                    className="shrink-0"
                  >
                    {copied ? (
                      <CheckCircle2 className="h-4 w-4 text-green-500" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </Button>
                </div>
                {copied && (
                  <p className="text-sm text-green-600">Address copied to clipboard!</p>
                )}
              </div>
            </CardContent>
          </Card>

         
        </div>
      )}
    </div>
  );
}