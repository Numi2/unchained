import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Config } from '@/types/blockchain';
import { Settings as SettingsIcon, FileText, RotateCcw } from 'lucide-react';

interface SettingsProps {
  onLoadConfig: (configPath: string) => Promise<string>;
  loading: boolean;
}

export function Settings({ onLoadConfig, loading }: SettingsProps) {
  const [configPath, setConfigPath] = useState('../config.toml');
  const [configResult, setConfigResult] = useState<string>('');
  const [error, setError] = useState('');

  // Placeholder object so TypeScript can type-check the (currently disabled)
  // detailed configuration display block below without `noUnusedLocals` errors.
  const loadedConfig = {} as Config;

  const handleLoadConfig = async () => {
    setError('');
    try {
      const result = await onLoadConfig(configPath);
      setConfigResult(result);
    } catch (err) {
      setError(`Failed to load config: ${err}`);
    }
  };

  const resetToDefault = () => {
    setConfigPath('../config.toml');
    setConfigResult('');
    setError('');
  };

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center space-x-2">
        <SettingsIcon className="h-6 w-6" />
        <h1 className="text-3xl font-bold">Settings</h1>
      </div>

      {/* Configuration File */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <FileText className="h-5 w-5" />
            <span>Configuration File</span>
          </CardTitle>
          <CardDescription>
            Load and view unchained node configuration
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex space-x-2">
            <div className="flex-1">
              <Label htmlFor="config-path">Config File Path</Label>
              <Input
                id="config-path"
                value={configPath}
                onChange={(e) => setConfigPath(e.target.value)}
                placeholder="Path to config.toml file"
              />
            </div>
            <div className="flex items-end space-x-2">
              <Button onClick={handleLoadConfig} disabled={loading || !configPath.trim()}>
                <FileText className="mr-2 h-4 w-4" />
                Load
              </Button>
              <Button variant="outline" onClick={resetToDefault}>
                <RotateCcw className="mr-2 h-4 w-4" />
                Reset
              </Button>
            </div>
          </div>

          {error && (
            <div className="text-sm text-red-500 bg-red-50 p-3 rounded">
              {error}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Configuration Result */}
      {configResult && (
        <Card>
          <CardHeader>
            <CardTitle>Configuration Status</CardTitle>
            <CardDescription>Configuration loading result</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-sm text-green-600 bg-green-50 p-3 rounded">
              {configResult}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Configuration Display - Disabled for simplicity */}
      {false && (
        <div className="space-y-4">
          {/* Network Configuration */}
          <Card>
            <CardHeader>
              <CardTitle>Network Configuration</CardTitle>
              <CardDescription>P2P network settings</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-3">
                  <div>
                    <Label className="text-sm font-medium text-muted-foreground">Listen Port</Label>
                    <p className="text-lg font-mono">{loadedConfig.net.listen_port}</p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium text-muted-foreground">Max Peers</Label>
                    <p className="text-lg font-mono">{loadedConfig.net.max_peers}</p>
                  </div>
                </div>
                <div className="space-y-3">
                  <div>
                    <Label className="text-sm font-medium text-muted-foreground">Connection Timeout</Label>
                    <p className="text-lg font-mono">{loadedConfig.net.connection_timeout_secs}s</p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium text-muted-foreground">Bootstrap Nodes</Label>
                    <p className="text-lg font-mono">
                      {loadedConfig.net.bootstrap.length > 0 ? loadedConfig.net.bootstrap.length : 'None'}
                    </p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Storage Configuration */}
          <Card>
            <CardHeader>
              <CardTitle>Storage Configuration</CardTitle>
              <CardDescription>Blockchain data storage settings</CardDescription>
            </CardHeader>
            <CardContent>
              <div>
                <Label className="text-sm font-medium text-muted-foreground">Data Path</Label>
                <p className="text-lg font-mono break-all">{loadedConfig.storage.path}</p>
              </div>
            </CardContent>
          </Card>

          {/* Epoch Configuration */}
          <Card>
            <CardHeader>
              <CardTitle>Epoch Configuration</CardTitle>
              <CardDescription>Blockchain timing and difficulty settings</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-3">
                  <div>
                    <Label className="text-sm font-medium text-muted-foreground">Epoch Duration</Label>
                    <p className="text-lg font-mono">{loadedConfig.epoch.seconds}s</p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium text-muted-foreground">Target Leading Zeros</Label>
                    <p className="text-lg font-mono">{loadedConfig.epoch.target_leading_zeros}</p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium text-muted-foreground">Target Coins per Epoch</Label>
                    <p className="text-lg font-mono">{loadedConfig.epoch.target_coins_per_epoch}</p>
                  </div>
                </div>
                <div className="space-y-3">
                  <div>
                    <Label className="text-sm font-medium text-muted-foreground">Retarget Interval</Label>
                    <p className="text-lg font-mono">{loadedConfig.epoch.retarget_interval} epochs</p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium text-muted-foreground">Max Difficulty Adjustment</Label>
                    <p className="text-lg font-mono">{loadedConfig.epoch.max_difficulty_adjustment}x</p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Mining Configuration */}
          <Card>
            <CardHeader>
              <CardTitle>Mining Configuration</CardTitle>
              <CardDescription>Proof-of-work mining settings</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-3">
                  <div>
                    <Label className="text-sm font-medium text-muted-foreground">Mining Enabled</Label>
                    <div className="flex items-center space-x-2">
                      <Badge variant={loadedConfig.mining.enabled ? "default" : "secondary"}>
                        {loadedConfig.mining.enabled ? "Yes" : "No"}
                      </Badge>
                    </div>
                  </div>
                  <div>
                    <Label className="text-sm font-medium text-muted-foreground">Memory (KiB)</Label>
                    <p className="text-lg font-mono">{loadedConfig.mining.mem_kib.toLocaleString()}</p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium text-muted-foreground">Argon2 Lanes</Label>
                    <p className="text-lg font-mono">{loadedConfig.mining.lanes}</p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium text-muted-foreground">Memory Range</Label>
                    <p className="text-lg font-mono">
                      {(loadedConfig.mining.min_mem_kib / 1024).toFixed(1)}M - {(loadedConfig.mining.max_mem_kib / 1024).toFixed(1)}M
                    </p>
                  </div>
                </div>
                <div className="space-y-3">
                  <div>
                    <Label className="text-sm font-medium text-muted-foreground">Max Memory Adjustment</Label>
                    <p className="text-lg font-mono">{loadedConfig.mining.max_memory_adjustment}x</p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium text-muted-foreground">Heartbeat Interval</Label>
                    <p className="text-lg font-mono">{loadedConfig.mining.heartbeat_interval_secs}s</p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium text-muted-foreground">Max Failures</Label>
                    <p className="text-lg font-mono">{loadedConfig.mining.max_consecutive_failures}</p>
                  </div>
                  <div>
                    <Label className="text-sm font-medium text-muted-foreground">Max Mining Attempts</Label>
                    <p className="text-lg font-mono">{loadedConfig.mining.max_mining_attempts.toLocaleString()}</p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Metrics Configuration */}
          <Card>
            <CardHeader>
              <CardTitle>Metrics Configuration</CardTitle>
              <CardDescription>Monitoring and metrics settings</CardDescription>
            </CardHeader>
            <CardContent>
              <div>
                <Label className="text-sm font-medium text-muted-foreground">Metrics Bind Address</Label>
                <p className="text-lg font-mono">{loadedConfig.metrics.bind}</p>
                <p className="text-sm text-muted-foreground mt-1">
                  Prometheus metrics endpoint
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Configuration Help */}
      <Card>
        <CardHeader>
          <CardTitle>Configuration Help</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3 text-sm text-muted-foreground">
            <p>
              <strong className="text-foreground">Config Location:</strong> The configuration file should be 
              in TOML format. Default location is `config.toml` in the project root.
            </p>
            <p>
              <strong className="text-foreground">Mining Settings:</strong> Adjust memory usage based on your 
              hardware. Higher memory values provide better security but require more RAM.
            </p>
            <p>
              <strong className="text-foreground">Network Settings:</strong> Configure bootstrap nodes to 
              connect to other peers in the unchained network.
            </p>
            <p>
              <strong className="text-foreground">Security:</strong> All settings maintain post-quantum 
              cryptographic security regardless of configuration values.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}