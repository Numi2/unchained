# RocksDB

RocksDB is a high-performance embedded database based on LevelDB, optimized for fast storage and designed for storing data on fast storage devices.

## Role in Unchained

RocksDB serves as the primary persistent storage engine for all blockchain data, providing reliable, fast access to the distributed ledger state.

### Storage Architecture

RocksDB uses **Column Families (CF)** to organize different types of data:

- **`epoch`**: Maps epoch number → `Anchor` data + latest pointer
- **`anchor`**: Maps anchor hash → `Anchor` (reverse lookup)
- **`coin_candidate`**: Indexed by `epoch_hash || coin_id` → `CoinCandidate`
- **`coin`**: Maps confirmed coin_id → `Coin` (selected coins only)
- **`epoch_selected`**: Index key `epoch_num || coin_id` → empty value
- **`epoch_leaves`**: Maps epoch_num → `Vec<[u8;32]>` of sorted leaf hashes
- **`transfer`**: Maps coin_id → `Transfer` (marks coin as spent)
- **`wallet`**: Stores encrypted wallet blob
- **`peers`**: Stores known peer multiaddresses

### Configuration

```rust
// Production-tuned RocksDB configuration
let mut cf_opts = Options::default();
cf_opts.set_write_buffer_size(64 * 1024 * 1024);    // 64MB memtable
cf_opts.set_max_write_buffer_number(2);             // 2 write buffers
cf_opts.set_target_file_size_base(64 * 1024 * 1024); // 64MB SST files

let mut db_opts = Options::default();
db_opts.create_if_missing(true);
db_opts.create_missing_column_families(true);
```

### Performance Optimizations

- **WAL-based Durability**: Uses Write-Ahead Log instead of per-write fsync
- **Batch Writes**: Groups related operations for efficiency
- **Larger Buffers**: 64MB write buffers for high throughput
- **Controlled Compaction**: Avoids over-aggressive small thresholds
- **File Organization**: Structured subdirectories for logs and backups

## Key Features

### ACID Properties
- **Atomicity**: Batch writes ensure all-or-nothing semantics
- **Consistency**: Column family isolation maintains data integrity
- **Isolation**: Snapshot reads provide consistent views
- **Durability**: WAL ensures data persistence across crashes

### Scalability
- **Efficient Prefix Iteration**: Optimized for epoch-based queries
- **Compaction**: Automatic background optimization
- **Memory Management**: Configurable buffer sizes and caching
- **File Limits**: Increased limits for production workloads

## Implementation Details

### Database Operations

```rust
impl Store {
    pub fn put_anchor(&self, anchor: &Anchor) -> Result<()> {
        let cf = self.db.cf_handle("epoch")?;
        let key = anchor.num.to_le_bytes();
        let value = bincode::serialize(anchor)?;
        self.db.put_cf(cf, &key, &value)
    }
    
    pub fn get_coin(&self, coin_id: &[u8; 32]) -> Result<Option<Coin>> {
        let cf = self.db.cf_handle("coin")?;
        if let Some(bytes) = self.db.get_cf(cf, coin_id)? {
            Ok(Some(bincode::deserialize(&bytes)?))
        } else {
            Ok(None)
        }
    }
}
```

### Backup System

```rust
pub fn create_backup(&self) -> Result<String> {
    let backup_dir = format!("{}/backups/{}", 
        self.path, 
        chrono::Utc::now().format("%Y%m%d_%H%M%S")
    );
    
    // Backup critical column families
    for cf_name in ["epoch", "wallet"] {
        // ... backup implementation
    }
}
```

## Configuration Options

### Memory Management
```toml
[storage]
path = "./unchained_data"       # Database directory
```

### Advanced Tuning
- **Write Buffer Size**: Controls memory usage for writes
- **Compaction**: Background optimization of storage layout  
- **Block Cache**: Configurable caching for read performance
- **WAL Directory**: Separate directory for write-ahead logs

## Performance Characteristics

- **Write Throughput**: Optimized for high-frequency blockchain writes
- **Read Latency**: Fast key-value lookups with caching
- **Storage Efficiency**: Automatic compression and compaction
- **Memory Usage**: Configurable memory allocation
- **Crash Recovery**: Fast startup with WAL replay

## Operational Features

### Monitoring
- Database health metrics exposed via Prometheus
- File system usage tracking
- Compaction statistics
- Write amplification monitoring

### Maintenance
- Automatic background compaction
- Configurable retention policies
- Backup and restore capabilities
- Database integrity checking

## Security Considerations

- **File Permissions**: Proper OS-level access controls
- **Encryption at Rest**: Application-level encryption for sensitive data
- **Lock Files**: Prevents concurrent access corruption
- **Atomic Operations**: Ensures data consistency during writes

## Integration with Unchained

RocksDB is tightly integrated with Unchained's consensus mechanism:

- **Epoch Finalization**: Batch writes for selected coins and Merkle leaves
- **Proof Generation**: Fast retrieval of epoch leaves for Merkle proofs
- **Wallet Operations**: Encrypted storage of private key material
- **Sync Operations**: Efficient storage and retrieval during blockchain sync
- **Network State**: Persistent storage of peer information and connection state