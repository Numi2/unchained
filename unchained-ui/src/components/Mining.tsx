import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { NodeStatus, EpochInfo, BlockInfo } from '@/types/blockchain';
import { Cpu, Zap, Timer, MemoryStick, Target, TrendingUp } from 'lucide-react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

interface MiningProps {
  nodeStatus: NodeStatus;
  recentEpochs: EpochInfo[];
  recentBlocks: BlockInfo[];
  onToggleMining: (enabled: boolean) => Promise<void>;
  loading: boolean;
}

export function Mining({ nodeStatus, recentEpochs, recentBlocks, onToggleMining, loading }: MiningProps) {
  const latestEpoch = recentEpochs[0];
  
  // Calculate mining efficiency metrics
  const miningMetrics = {
    avgCoinsPerEpoch: recentEpochs.length > 0 
      ? recentEpochs.reduce((sum, epoch) => sum + epoch.coin_count, 0) / recentEpochs.length 
      : 0,
    avgDifficulty: recentEpochs.length > 0
      ? recentEpochs.reduce((sum, epoch) => sum + epoch.difficulty, 0) / recentEpochs.length
      : 0,
    difficultyTrend: recentEpochs.length >= 2
      ? recentEpochs[0].difficulty - recentEpochs[recentEpochs.length - 1].difficulty
      : 0,
  };

  const handleToggleMining = async () => {
    try {
      await onToggleMining(!nodeStatus.mining);
    } catch (error) {
      // Error handled by parent
    }
  };

  if (!nodeStatus.running) {
    return (
      <div className="space-y-6 p-6">
        <div className="flex items-center space-x-2">
          <Cpu className="h-6 w-6" />
          <h1 className="text-3xl font-bold">Mining</h1>
        </div>
        
        <Card>
          <CardHeader>
            <CardTitle>Node Required</CardTitle>
            <CardDescription>
              Please start the blockchain node first to begin mining
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Cpu className="h-6 w-6" />
          <h1 className="text-3xl font-bold">Mining</h1>
        </div>
        <Button
          onClick={handleToggleMining}
          disabled={loading}
          variant={nodeStatus.mining ? "destructive" : "default"}
        >
          {nodeStatus.mining ? (
            <>
              <Zap className="mr-2 h-4 w-4" />
              Stop Mining
            </>
          ) : (
            <>
              <Cpu className="mr-2 h-4 w-4" />
              Start Mining
            </>
          )}
        </Button>
      </div>

      {/* Mining Status */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Zap className="h-5 w-5" />
            <span>Mining Status</span>
          </CardTitle>
          <CardDescription>
            Current mining operation status
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center space-x-2">
            <Badge variant={nodeStatus.mining ? "default" : "secondary"} className="text-lg py-2">
              {nodeStatus.mining ? (
                <>
                  <Zap className="mr-2 h-4 w-4" />
                  Mining Active
                </>
              ) : (
                <>
                  <Timer className="mr-2 h-4 w-4" />
                  Mining Idle
                </>
              )}
            </Badge>
          </div>
          {nodeStatus.mining && (
            <p className="text-sm text-muted-foreground mt-2">
              Mining with Argon2id proof-of-work algorithm
            </p>
          )}
        </CardContent>
      </Card>

      {/* Recent Blocks */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Blocks</CardTitle>
          <CardDescription>Recently mined blocks</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Epoch</TableHead>
                <TableHead>Height</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {recentBlocks.map((block) => (
                <TableRow key={block.id}>
                  <TableCell className="font-mono">{block.id.substring(0, 16)}...</TableCell>
                  <TableCell>{block.created_at_epoch}</TableCell>
                  <TableCell>{block.created_at_height}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Mining Statistics */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium"> Blocks unchained</CardTitle>
            <Target className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{nodeStatus.coins_mined}</div>
            <p className="text-xs text-muted-foreground">
              unchaineds earned
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Current Difficulty</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {latestEpoch ? latestEpoch.difficulty : 'N/A'}
            </div>
            <p className="text-xs text-muted-foreground">
              Leading zeros required
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Memory Usage</CardTitle>
            <MemoryStick className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {latestEpoch ? `${(latestEpoch.mem_kib / 1024).toFixed(1)}M` : 'N/A'}
            </div>
            <p className="text-xs text-muted-foreground">
              KiB for Argon2id
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Coins This Epoch</CardTitle>
            <Zap className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {latestEpoch ? latestEpoch.coin_count : 'N/A'}
            </div>
            <p className="text-xs text-muted-foreground">
              Network-wide coins
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Mining Configuration */}
      <Card>
        <CardHeader>
          <CardTitle>Mining Configuration</CardTitle>
          <CardDescription>
            Current mining parameters and algorithm details
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <h4 className="font-medium mb-2">Algorithm Details</h4>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Hash Function:</span>
                  <span>Argon2id</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Signature Scheme:</span>
                  <span>Dilithium3 (Post-Quantum)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Key Exchange:</span>
                  <span>X25519 + Kyber (Hybrid)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Transport:</span>
                  <span>QUIC with TLS 1.3</span>
                </div>
              </div>
            </div>

            <div>
              <h4 className="font-medium mb-2">Performance Metrics</h4>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Avg Coins/Epoch:</span>
                  <span>{miningMetrics.avgCoinsPerEpoch.toFixed(1)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Avg Difficulty:</span>
                  <span>{miningMetrics.avgDifficulty.toFixed(1)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Difficulty Trend:</span>
                  <span className={miningMetrics.difficultyTrend > 0 ? "text-red-500" : "text-green-500"}>
                    {miningMetrics.difficultyTrend > 0 ? "↑" : "↓"} {Math.abs(miningMetrics.difficultyTrend)}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Epochs Tracked:</span>
                  <span>{recentEpochs.length}</span>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Mining Info */}
      <Card>
        <CardHeader>
          <CardTitle>About unchained Mining</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3 text-sm text-muted-foreground">
            <p>
              <strong className="text-foreground">Post-Quantum Security:</strong> unchained uses Dilithium3 
              signatures and hybrid key exchange to resist quantum computer attacks.
            </p>
            <p>
              <strong className="text-foreground">Memory-Hard Mining:</strong> Argon2id proof-of-work requires 
              significant memory, making ASIC resistance and fair distribution possible.
            </p>
            <p>
              <strong className="text-foreground">Dynamic Difficulty:</strong> Mining difficulty adjusts 
              automatically based on network hash rate to maintain consistent block times.
            </p>
            <p>
              <strong className="text-foreground">UTXO Model:</strong> Each mined coin is a unique UTXO 
              that can be transferred individually with cryptographic signatures.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}