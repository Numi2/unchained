The core issue is that the gossipsub protocol in libp2p requires at least one peer in the mesh to publish messages. When running a single node, the miner can't broadcast newly created anchors, which stalls the mining process since the miner is waiting for the next anchor to begin mining the next epoch.

