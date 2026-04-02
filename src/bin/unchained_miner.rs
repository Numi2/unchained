#[tokio::main]
async fn main() -> anyhow::Result<()> {
    unchained::app::run_miner_cli().await
}
