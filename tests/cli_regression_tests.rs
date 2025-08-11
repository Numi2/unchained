// Regression test: one-shot CLI commands must not advance epoch
use std::process::Command;
use std::fs;

#[test]
fn oneshot_commands_do_not_advance_epoch() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let db_dir = tmp.path().join("data");
    fs::create_dir_all(&db_dir).unwrap();

    // Minimal config content with epoch.seconds >= 222
    let cfg_contents = r#"[net]
listen_port = 39001
bootstrap = []
max_peers = 8
connection_timeout_secs = 5
sync_timeout_secs = 1

[p2p]
max_validation_failures_per_peer = 10
peer_ban_duration_secs = 60
rate_limit_window_secs = 10
max_messages_per_window = 100

[storage]
path = "__DB_PATH__"

[epoch]
seconds = 222
target_leading_zeros = 1
retarget_interval = 10
target_coins_per_epoch = 1
max_coins_per_epoch = 1

[mining]
enabled = false
mem_kib = 65536
min_mem_kib = 16384
max_mem_kib = 262144
max_memory_adjustment = 1.5

[metrics]
bind = "127.0.0.1:9199"
"#;

    let cfg_path = tmp.path().join("config.toml");
    let cfg_text = cfg_contents.replace("__DB_PATH__", db_dir.to_str().unwrap());
    fs::write(&cfg_path, cfg_text).unwrap();

    // Helper to run the binary with a subcommand
    let mut run_cmd = |args: &[&str]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_unchained"));
        cmd.arg("--config").arg(cfg_path.to_str().unwrap());
        for a in args { cmd.arg(a); }
        cmd.status().expect("failed to run unchained binary")
    };

    // Run a balance query first
    let status = run_cmd(&["balance"]);
    assert!(status.success());

    // Check DB epoch count
    let epoch_count_before = count_epochs(&db_dir);

    // Run history and peer-id
    let status = run_cmd(&["history"]);
    assert!(status.success());
    let status = run_cmd(&["peer-id"]);
    assert!(status.success());

    // Ensure epoch count unchanged
    let epoch_count_after = count_epochs(&db_dir);
    assert_eq!(epoch_count_before, epoch_count_after, "one-shot commands advanced epoch unexpectedly");
}

fn count_epochs(db_dir: &std::path::Path) -> u64 {
    let cfg = unchained::config::Config {
        net: unchained::config::Net { listen_port: 0, bootstrap: vec![], max_peers: 8, connection_timeout_secs: 1, public_ip: None, sync_timeout_secs: 1, require_pq_identity: false },
        p2p: unchained::config::P2p { max_validation_failures_per_peer: 10, peer_ban_duration_secs: 60, rate_limit_window_secs: 10, max_messages_per_window: 100 },
        storage: unchained::config::Storage { path: db_dir.to_string_lossy().to_string() },
        epoch: unchained::config::Epoch { seconds: 222, target_leading_zeros: 1, target_coins_per_epoch: 1, max_coins_per_epoch: 1, retarget_interval: 10, include_transfers_root_in_hash: false, min_ring_size: 5, max_ring_size: 64 },
        mining: unchained::config::Mining { enabled: false, mem_kib: 65536, min_mem_kib: 16384, max_mem_kib: 262144, max_memory_adjustment: 1.5 },
        metrics: unchained::config::Metrics { bind: "127.0.0.1:0".into() },
    };
    let store = unchained::storage::open(&cfg.storage);
    store.epoch_count().expect("epoch_count")
}


