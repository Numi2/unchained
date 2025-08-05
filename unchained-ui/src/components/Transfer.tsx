import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { WalletInfo } from '@/types/blockchain';
import { Send, AlertCircle, CheckCircle2 } from 'lucide-react';

interface TransferProps {
  walletInfo: WalletInfo | null;
  onCreateTransfer: (toAddress: string, coinId: string, passphrase: string) => Promise<string>;
  onGetOwnedCoins: () => Promise<string[]>;
  loading: boolean;
}

export function Transfer({ walletInfo, onCreateTransfer, onGetOwnedCoins, loading }: TransferProps) {
  const [toAddress, setToAddress] = useState('');
  const [coinId, setCoinId] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [ownedCoins, setOwnedCoins] = useState<string[]>([]);
  const [transferResult, setTransferResult] = useState<string>('');
  const [showPassphrase, setShowPassphrase] = useState(false);

  const handleGetCoins = async () => {
    try {
      const coins = await onGetOwnedCoins();
      setOwnedCoins(coins);
    } catch (error) {
      // Error handled by parent
    }
  };

  const handleTransfer = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!toAddress.trim() || !coinId.trim() || !passphrase.trim()) {
      return;
    }

    try {
      const result = await onCreateTransfer(toAddress, coinId, passphrase);
      setTransferResult(result);
      // Clear form on success
      setToAddress('');
      setCoinId('');
      setPassphrase('');
    } catch (error) {
      // Error handled by parent
    }
  };

  const isValidAddress = (address: string) => {
    // Basic validation - should be 64 hex characters (32 bytes * 2)
    return /^[a-fA-F0-9]{64}$/.test(address);
  };

  const isValidCoinId = (id: string) => {
    // Basic validation - should be 64 hex characters (32 bytes * 2)
    return /^[a-fA-F0-9]{64}$/.test(id);
  };

  if (!walletInfo) {
    return (
      <div className="space-y-6 p-6">
        <div className="flex items-center space-x-2">
          <Send className="h-6 w-6" />
          <h1 className="text-3xl font-bold">Transfer Coins</h1>
        </div>
        
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <AlertCircle className="h-5 w-5 text-yellow-500" />
              <span>Wallet Required</span>
            </CardTitle>
            <CardDescription>
              Please unlock your wallet first to send coins
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center space-x-2">
        <Send className="h-6 w-6" />
        <h1 className="text-3xl font-bold">Transfer Coins</h1>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Transfer Form */}
        <Card>
          <CardHeader>
            <CardTitle>Send Coins</CardTitle>
            <CardDescription>
              Transfer unchaineds to another address
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleTransfer} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="to-address">Recipient Address</Label>
                <Input
                  id="to-address"
                  value={toAddress}
                  onChange={(e) => setToAddress(e.target.value)}
                  placeholder="Enter recipient wallet address (64 hex characters)"
                  required
                />
                {toAddress && !isValidAddress(toAddress) && (
                  <p className="text-sm text-red-500">
                    Address must be 64 hex characters
                  </p>
                )}
              </div>

              <div className="space-y-2">
                <Label htmlFor="coin-id">Coin ID</Label>
                <Input
                  id="coin-id"
                  value={coinId}
                  onChange={(e) => setCoinId(e.target.value)}
                  placeholder="Enter coin ID to transfer (64 hex characters)"
                  required
                />
                {coinId && !isValidCoinId(coinId) && (
                  <p className="text-sm text-red-500">
                    Coin ID must be 64 hex characters
                  </p>
                )}
              </div>

              <div className="space-y-2">
                <Label htmlFor="transfer-passphrase">Wallet Passphrase</Label>
                <Input
                  id="transfer-passphrase"
                  type={showPassphrase ? "text" : "password"}
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  placeholder="Enter your wallet passphrase"
                  required
                />
                <div className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    id="show-transfer-passphrase"
                    checked={showPassphrase}
                    onChange={(e) => setShowPassphrase(e.target.checked)}
                    className="rounded"
                  />
                  <Label htmlFor="show-transfer-passphrase" className="text-sm">
                    Show passphrase
                  </Label>
                </div>
              </div>

              <Button 
                type="submit" 
                className="w-full"
                disabled={
                  loading || 
                  !toAddress.trim() || 
                  !coinId.trim() || 
                  !passphrase.trim() ||
                  !isValidAddress(toAddress) ||
                  !isValidCoinId(coinId)
                }
              >
                {loading ? "Sending..." : "Send Coins"}
              </Button>
            </form>
          </CardContent>
        </Card>

        {/* Owned Coins */}
        <Card>
          <CardHeader>
            <CardTitle>Your Coins</CardTitle>
            <CardDescription>
              Coins available for transfer
            </CardDescription>
            <Button onClick={handleGetCoins} disabled={loading} size="sm">
              Refresh Coins
            </Button>
          </CardHeader>
          <CardContent>
            {ownedCoins.length === 0 ? (
              <div className="text-center py-8">
                <p className="text-muted-foreground">No coins found</p>
                <p className="text-sm text-muted-foreground mt-1">
                  Start mining to earn coins
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                {ownedCoins.map((coin, index) => (
                  <div 
                    key={index}
                    className="flex items-center justify-between p-3 border rounded cursor-pointer hover:bg-muted"
                    onClick={() => setCoinId(coin)}
                  >
                    <code className="text-sm break-all flex-1 mr-2">
                      {coin.slice(0, 16)}...{coin.slice(-16)}
                    </code>
                    <Badge variant="outline">1 numicoin</Badge>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Transfer Result */}
      {transferResult && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <CheckCircle2 className="h-5 w-5 text-green-500" />
              <span>Transfer Result</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-green-600">{transferResult}</p>
          </CardContent>
        </Card>
      )}

      {/* Instructions */}
      <Card>
        <CardHeader>
          <CardTitle>Transfer Instructions</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 text-sm text-muted-foreground">
            <p>• Each coin has a value of 1 numicoin and can be transferred individually</p>
            <p>• Addresses are 32-byte hex strings (64 characters)</p>
            <p>• Transfers require your wallet passphrase for security</p>
            <p>• All transfers use post-quantum Dilithium3 signatures</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}