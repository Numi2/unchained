#[tokio::main]
async fn main() -> anyhow::Result<()> {
    unchained::app::run_node_cli().await
}
