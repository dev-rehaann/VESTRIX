//! `vestrix-verify`: a read-only, independent forensic verifier.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use corepc_client::client_sync::{Auth, v17::Client};

use vestrix_verifier_cli::{anchor, chain};

#[derive(Debug, Parser)]
#[command(name = "vestrix-verify", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify every canonical record, hash link, and Ed25519 signature.
    Chain {
        /// Path to the canonical JSONL chain.
        chain: PathBuf,
        /// Raw 32-byte or 64-character lowercase-hex Ed25519 public key file.
        #[arg(long)]
        pubkey: PathBuf,
    },
    /// Verify an OTS anchor against a configured Bitcoin Core node.
    Anchor {
        /// Path to the canonical JSONL chain.
        chain: PathBuf,
        /// Path to a detached OpenTimestamps proof.
        #[arg(long)]
        ots_proof: PathBuf,
        /// Bitcoin Core JSON-RPC endpoint; no endpoint is assumed by default.
        #[arg(long)]
        rpc_url: String,
        /// Bitcoin Core cookie file. Without this, credentials come from
        /// VESTRIX_BITCOIN_RPC_USER and VESTRIX_BITCOIN_RPC_PASSWORD.
        #[arg(long)]
        rpc_cookie: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<String, String> {
    match cli.command {
        Command::Chain { chain, pubkey } => {
            let public_key = read_public_key(&pubkey)?;
            let report =
                chain::verify_path(&chain, &public_key).map_err(|error| error.to_string())?;
            let tip = report.tip.map_or_else(
                || "none (empty chain)".to_owned(),
                |tip| format!("seq {}, {}", tip.seq, tip.record_hash),
            );
            Ok(format!(
                "chain valid: {} record(s); tip {tip}",
                report.records
            ))
        }
        Command::Anchor {
            chain,
            ots_proof,
            rpc_url,
            rpc_cookie,
        } => {
            let client = rpc_client(&rpc_url, rpc_cookie)?;
            let report = anchor::verify_anchor(&chain, &ots_proof, &client)
                .map_err(|error| error.to_string())?;
            Ok(format!(
                "anchor valid: chain tip seq {}; Bitcoin block {} at height {}; {} confirmations",
                report.seq, report.block_hash, report.height, report.confirmations
            ))
        }
    }
}

fn rpc_client(url: &str, cookie: Option<PathBuf>) -> Result<Client, String> {
    let auth = if let Some(path) = cookie {
        Auth::CookieFile(path)
    } else {
        let user = std::env::var("VESTRIX_BITCOIN_RPC_USER").map_err(|_| {
            "RPC configuration error: pass --rpc-cookie or set VESTRIX_BITCOIN_RPC_USER and VESTRIX_BITCOIN_RPC_PASSWORD".to_owned()
        })?;
        let password = std::env::var("VESTRIX_BITCOIN_RPC_PASSWORD").map_err(|_| {
            "RPC configuration error: pass --rpc-cookie or set VESTRIX_BITCOIN_RPC_USER and VESTRIX_BITCOIN_RPC_PASSWORD".to_owned()
        })?;
        Auth::UserPass(user, password)
    };
    Client::new_with_auth(url, auth).map_err(|error| format!("RPC configuration error: {error}"))
}

fn read_public_key(path: &Path) -> Result<[u8; 32], String> {
    let bytes = fs::read(path).map_err(|error| format!("cannot read public key: {error}"))?;
    if bytes.len() == 32 {
        return bytes
            .try_into()
            .map_err(|_| "public key must contain exactly 32 raw bytes".to_owned());
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "public key must be 32 raw bytes or lowercase hexadecimal UTF-8".to_owned())?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    chain::decode_hex_array::<32>(text).map_err(|reason| format!("invalid public key: {reason}"))
}
