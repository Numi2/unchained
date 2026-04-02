#[tokio::main]
async fn main() -> anyhow::Result<()> {
    unchained::app::run_wallet_cli().await
}
