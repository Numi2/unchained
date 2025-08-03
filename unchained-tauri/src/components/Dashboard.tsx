import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { NodeStatus, EpochInfo } from '@/types/blockchain';
import { Play, Square, Cpu, Network, Coins, Activity } from 'lucide-react';

interface DashboardProps {
  nodeStatus: NodeStatus;
  recentEpochs: EpochInfo[];
  onStartNode: () => void;
  onStopNode: () => void;
  onToggleMining: (enabled: boolean) => void;
  loading: boolean;
}

export function Dashboard({ 
  nodeStatus, 
  recentEpochs, 
  onStartNode, 
  onStopNode, 
  onToggleMining, 
  loading 
}: DashboardProps) {
  const latestEpoch = recentEpochs[0];

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">UnchainedCoin Dashboard</h1>
          <p className="text-muted-foreground">Post-quantum blockchain node management</p>
        </div>
        <div className="flex gap-2">
          {!nodeStatus.running ? (
            <Button onClick={onStartNode} disabled={loading}>
              <Play className="mr-2 h-4 w-4" />
              Start Node
            </Button>
          ) : (
            <Button onClick={onStopNode} variant="destructive" disabled={loading}>
              <Square className="mr-2 h-4 w-4" />
              Stop Node
            </Button>
          )}
        </div>
      </div>

      {/* Status Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Node Status</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="flex items-center space-x-2">
              <Badge variant={nodeStatus.running ? "default" : "secondary"}>
                {nodeStatus.running ? "Running" : "Stopped"}
              </Badge>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Mining Status</CardTitle>
            <Cpu className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <Badge variant={nodeStatus.mining ? "default" : "secondary"}>
                {nodeStatus.mining ? "Mining" : "Idle"}
              </Badge>
              {nodeStatus.running && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => onToggleMining(!nodeStatus.mining)}
                  disabled={loading}
                >
                  {nodeStatus.mining ? "Stop" : "Start"}
                </Button>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Connected Peers</CardTitle>
            <Network className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{nodeStatus.peers}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Coins Mined</CardTitle>
            <Coins className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{nodeStatus.coins_mined}</div>
          </CardContent>
        </Card>
      </div>

      {/* Current Epoch */}
      {latestEpoch && (
        <Card>
          <CardHeader>
            <CardTitle>Current Epoch</CardTitle>
            <CardDescription>Latest blockchain epoch information</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              <div>
                <p className="text-sm font-medium text-muted-foreground">Epoch Number</p>
                <p className="text-2xl font-bold">#{latestEpoch.num}</p>
              </div>
              <div>
                <p className="text-sm font-medium text-muted-foreground">Difficulty</p>
                <p className="text-2xl font-bold">{latestEpoch.difficulty}</p>
              </div>
              <div>
                <p className="text-sm font-medium text-muted-foreground">Coins in Epoch</p>
                <p className="text-2xl font-bold">{latestEpoch.coin_count}</p>
              </div>
              <div>
                <p className="text-sm font-medium text-muted-foreground">Memory (KiB)</p>
                <p className="text-2xl font-bold">{latestEpoch.mem_kib.toLocaleString()}</p>
              </div>
            </div>
            <div className="mt-4">
              <p className="text-sm font-medium text-muted-foreground mb-2">Epoch Hash</p>
              <code className="bg-muted px-2 py-1 rounded text-sm break-all">
                {latestEpoch.hash}
              </code>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Recent Epochs */}
      {recentEpochs.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Recent Epochs</CardTitle>
            <CardDescription>Historical epoch data</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {recentEpochs.slice(0, 5).map((epoch) => (
                <div key={epoch.num} className="flex items-center justify-between p-3 border rounded">
                  <div className="flex items-center space-x-4">
                    <Badge variant="outline">#{epoch.num}</Badge>
                    <span className="text-sm text-muted-foreground">
                      Difficulty: {epoch.difficulty}
                    </span>
                    <span className="text-sm text-muted-foreground">
                      Coins: {epoch.coin_count}
                    </span>
                  </div>
                  <code className="text-xs text-muted-foreground">
                    {epoch.hash.slice(0, 16)}...
                  </code>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}