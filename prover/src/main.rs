//! `scarlett-prover prove` reads `{"verifier","token","payload"}` JSON on stdin,
//! runs the Codex job with a TLSNotary proof and prints a JSON summary.
//! `scarlett-prover prove-x` reads `{"verifier","token","request","max_recv"}`,
//! sends one X GraphQL read over MPC-TLS and prints the proven response.
//! `scarlett-prover verifier` runs the validator service (see verifier.rs).
//! `scarlett-prover fake-openai <addr> <ca-out>` is for impersonation tests.

mod fake;
mod policy;
mod prove;
mod verifier;
mod xpolicy;
mod xprove;

use anyhow::{Result, bail};
use tokio::io::AsyncReadExt;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["prove"] => {
            let mut input = Vec::new();
            tokio::io::stdin().take(1 << 20).read_to_end(&mut input).await?;
            let summary = prove::run(serde_json::from_slice(&input)?).await?;
            println!("{}", serde_json::to_string(&summary)?);
            Ok(())
        }
        ["prove-x"] => {
            let mut input = Vec::new();
            tokio::io::stdin().take(1 << 20).read_to_end(&mut input).await?;
            let summary = xprove::run(serde_json::from_slice(&input)?).await?;
            println!("{}", serde_json::to_string(&summary)?);
            Ok(())
        }
        ["verifier"] => verifier::run().await,
        ["fake-openai", listen, ca_out] => fake::run(listen, ca_out).await,
        _ => bail!("usage: scarlett-prover prove | prove-x | verifier | fake-openai <addr> <ca-out>"),
    }
}
