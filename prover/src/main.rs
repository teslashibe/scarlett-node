//! `scarlett-prover prove` reads `{"verifier","token","payload"}` JSON on stdin,
//! runs the Codex job with a TLSNotary proof and prints a JSON summary.
//! `scarlett-prover prove-x` reads `{"verifier","token","request","max_recv"}`,
//! sends one X GraphQL read over MPC-TLS and prints the proven response.
//! `scarlett-prover relay-x` takes the same input and sends the read over a
//! keyed relay session instead (see relay/mod.rs).
//! `scarlett-prover relay-web` reads one web hop (see relay/node.rs), sends
//! it over a relay session to the address the node checked, and prints the
//! hop's summary; on failure it prints `SCARLETT_WEB_ERROR=<class>` on stderr.
//! `scarlett-prover verifier` runs the validator service (see verifier.rs).
//! `scarlett-prover fake-openai <addr> <ca-out>` is for impersonation tests.

mod control;
mod diagnostics;
mod dial;
#[cfg(unix)]
mod fake;
mod policy;
mod prove;
mod relay;
#[cfg(unix)]
mod verifier;
#[cfg(unix)]
mod verifier_store;
mod webpolicy;
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
        ["relay-x"] => {
            let mut input = Vec::new();
            tokio::io::stdin().take(1 << 20).read_to_end(&mut input).await?;
            let summary = relay::node::run(serde_json::from_slice(&input)?).await?;
            println!("{}", serde_json::to_string(&summary)?);
            Ok(())
        }
        ["relay-web"] => {
            let mut input = Vec::new();
            tokio::io::stdin().take(1 << 20).read_to_end(&mut input).await?;
            match relay::node::run_web(&input).await {
                Ok(summary) => {
                    println!("{}", serde_json::to_string(&summary)?);
                    Ok(())
                }
                Err(failure) => {
                    // One classification line, then the cause on one line. The
                    // cause keeps the relay misuse text the node looks for.
                    let cause: String = format!("{:#}", failure.error).chars().map(|c| if c.is_control() { ' ' } else { c }).take(2048).collect();
                    eprintln!("SCARLETT_WEB_ERROR={}\nError: {cause}", failure.class);
                    std::process::exit(1);
                }
            }
        }
        #[cfg(unix)]
        ["verifier"] => verifier::run().await,
        #[cfg(unix)]
        ["fake-openai", listen, ca_out] => fake::run(listen, ca_out).await,
        #[cfg(not(unix))]
        ["verifier"] | ["fake-openai", ..] => bail!("this platform supports the proof client only"),
        _ => bail!("usage: scarlett-prover prove | prove-x | relay-x | relay-web | verifier | fake-openai <addr> <ca-out>"),
    }
}
