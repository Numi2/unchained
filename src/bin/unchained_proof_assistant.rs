#[tokio::main]
async fn main() -> anyhow::Result<()> {
    unchained::app::run_proof_assistant_cli().await
}
