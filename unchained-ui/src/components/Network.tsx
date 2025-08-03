import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { NodeStatus, NetworkPeer } from '@/types/blockchain';
import { Network as NetworkIcon, Users, Globe, Wifi, WifiOff, Plus, RefreshCw } from 'lucide-react';

interface NetworkProps {
  nodeStatus: NodeStatus;
  loading: boolean;
}

export function Network({ nodeStatus, loading }: NetworkProps) {
  const [peers, setPeers] = useState<NetworkPeer[]>([]);
  const [newBootstrapNode, setNewBootstrapNode] = useState('');

  // Mock peers data - in a real implementation, this would come from the backend
  useEffect(() => {
    if (nodeStatus.running) {
      // Simulate some peers
      setPeers([
        {
          id: "12D3KooWExample1234567890abcdef",
          address: "/ip4/192.168.1.100/udp/7777/quic-v1",
          connected: true,
        },
        {
          id: "12D3KooWExample2345678901bcdefg",
          address: "/ip4/10.0.0.50/udp/7777/quic-v1",
          connected: true,
        },
        {
          id: "12D3KooWExample3456789012cdefgh",
          address: "/ip4/172.16.0.25/udp/7777/quic-v1",
          connected: false,
        },
      ]);
    } else {
      setPeers([]);
    }
  }, [nodeStatus.running]);

  const handleAddBootstrap = () => {
    if (newBootstrapNode.trim()) {
      // In a real implementation, this would call a backend function
      console.log("Adding bootstrap node:", newBootstrapNode);
      setNewBootstrapNode('');
    }
  };

  const refreshPeers = () => {
    // In a real implementation, this would refresh peer data from the backend
    console.log("Refreshing peer list");
  };

  if (!nodeStatus.running) {
    return (
      <div className="space-y-6 p-6">
        <div className="flex items-center space-x-2">
          <NetworkIcon className="h-6 w-6" />
          <h1 className="text-3xl font-bold">Network</h1>
        </div>
        
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center space-x-2">
              <WifiOff className="h-5 w-5 text-muted-foreground" />
              <span>Node Offline</span>
            </CardTitle>
            <CardDescription>
              Start the blockchain node to view network information
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
          <NetworkIcon className="h-6 w-6" />
          <h1 className="text-3xl font-bold">Network</h1>
        </div>
        <Button onClick={refreshPeers} disabled={loading} variant="outline">
          <RefreshCw className="mr-2 h-4 w-4" />
          Refresh
        </Button>
      </div>

      {/* Network Status */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Connection Status</CardTitle>
            <Wifi className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="flex items-center space-x-2">
              <Badge variant="default" className="bg-green-500">
                <Globe className="mr-1 h-3 w-3" />
                Online
              </Badge>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Connected Peers</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{nodeStatus.peers}</div>
            <p className="text-xs text-muted-foreground">
              Active connections
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Protocol</CardTitle>
            <NetworkIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-lg font-bold">QUIC</div>
            <p className="text-xs text-muted-foreground">
             
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Peer List */}
      <Card>
        <CardHeader>
          <CardTitle>Connected Peers</CardTitle>
          <CardDescription>
            
          </CardDescription>
        </CardHeader>
        <CardContent>
          {peers.length === 0 ? (
            <div className="text-center py-8">
              <Users className="mx-auto h-12 w-12 text-muted-foreground" />
              <p className="mt-2 text-muted-foreground">No peers connected</p>
              <p className="text-sm text-muted-foreground">
                Add bootstrap nodes to discover peers
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {peers.map((peer, index) => (
                <div key={index} className="flex items-center justify-between p-4 border rounded">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-1">
                      <Badge variant={peer.connected ? "default" : "secondary"}>
                        {peer.connected ? "Connected" : "Disconnected"}
                      </Badge>
                      <span className="text-sm text-muted-foreground">
                        {peer.connected ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
                      </span>
                    </div>
                    <p className="text-sm font-mono break-all">
                      <strong>ID:</strong> {peer.id}
                    </p>
                    <p className="text-sm font-mono text-muted-foreground">
                      <strong>Address:</strong> {peer.address}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Add Bootstrap Node */}
      <Card>
        <CardHeader>
          <CardTitle>Add Bootstrap Node</CardTitle>
          <CardDescription>
            Add a new bootstrap node to discover more peers
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex space-x-2">
            <div className="flex-1">
              <Label htmlFor="bootstrap-node" className="sr-only">
                Bootstrap Node Address
              </Label>
              <Input
                id="bootstrap-node"
                placeholder="/ip4/192.168.1.100/udp/7777/quic-v1/p2p/12D3KooW..."
                value={newBootstrapNode}
                onChange={(e) => setNewBootstrapNode(e.target.value)}
              />
            </div>
            <Button onClick={handleAddBootstrap} disabled={!newBootstrapNode.trim()}>
              <Plus className="mr-2 h-4 w-4" />
              Add
            </Button>
          </div>
          <p className="text-xs text-muted-foreground mt-2">
            Format: /ip4/IP_ADDRESS/udp/PORT/quic-v1/p2p/PEER_ID
          </p>
        </CardContent>
      </Card>

      {/* Network Information */}
      <Card>
        <CardHeader>
          <CardTitle>Network Information</CardTitle>
          <CardDescription>
            Technical details about the unchained network
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <h4 className="font-medium mb-2">Transport Layer</h4>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Protocol:</span>
                  <span>QUIC over UDP</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Encryption:</span>
                  <span>TLS 1.3 + Post-Quantum</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Key Exchange:</span>
                  <span>X25519 + Kyber (Hybrid)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Multiplexing:</span>
                  <span>Native QUIC Streams</span>
                </div>
              </div>
            </div>

            <div>
              <h4 className="font-medium mb-2">P2P Features</h4>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Gossip Protocol:</span>
                  <span>libp2p GossipSub</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Peer Discovery:</span>
                  <span>Bootstrap + mDNS</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">NAT Traversal:</span>
                  <span>QUIC Enabled</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">DHT:</span>
                  <span>Kademlia (libp2p)</span>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Security Notice */}
      <Card>
        <CardHeader>
          <CardTitle>Security Notice</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 text-sm text-muted-foreground">
            <p>
              <strong className="text-foreground">Post-Quantum Ready:</strong> All network communications 
              use hybrid cryptography combining classical and post-quantum algorithms.
            </p>
            <p>
              <strong className="text-foreground">Transport Security:</strong> QUIC provides built-in 
              encryption and integrity protection for all data in transit.
            </p>
            <p>
              <strong className="text-foreground">Peer Authentication:</strong> All peers use cryptographic 
              identities based on Ed25519 keys for secure peer-to-peer communication.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}