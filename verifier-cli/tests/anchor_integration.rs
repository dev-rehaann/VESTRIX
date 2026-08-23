use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use corepc_client::bitcoin::hashes::Hash;
use corepc_client::client_sync::{Auth, v17::Client};
use serde_json::{Value, json};
use vestrix_verifier_cli::anchor;

const MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
const BITCOIN_ATTESTATION: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
const GENESIS_HASH: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
const GENESIS_HEADER: &str = concat!(
    "01000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
    "29ab5f49ffff001d1dac2b7c"
);
const GENESIS_MERKLE_BYTES: &str =
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "vestrix-anchor-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create fixture directory");
        Self(path)
    }

    fn write(&self, name: &str, contents: impl AsRef<[u8]>) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, contents).expect("write fixture");
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn decode_hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII"), 16).expect("hex"))
        .collect()
}

fn varuint(mut value: u64) -> Vec<u8> {
    let mut encoded = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        encoded.push(byte);
        if value == 0 {
            return encoded;
        }
    }
}

fn proof(digest: &[u8; 32], height: u64) -> Vec<u8> {
    let mut proof = MAGIC.to_vec();
    proof.extend_from_slice(&[0x01, 0x08]);
    proof.extend_from_slice(digest);
    proof.push(0x00);
    proof.extend_from_slice(&BITCOIN_ATTESTATION);
    let height = varuint(height);
    proof.push(height.len() as u8);
    proof.extend_from_slice(&height);
    proof
}

fn request_body(stream: &mut TcpStream) -> Value {
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).expect("read request");
        assert!(read > 0, "client closed before HTTP headers");
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(position) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..header_end]).expect("HTTP headers are UTF-8");
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(str::trim)
                .map(str::parse::<usize>)
        })
        .expect("Content-Length")
        .expect("numeric Content-Length");
    while bytes.len() - header_end < content_length {
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).expect("read request body");
        assert!(read > 0, "client closed before HTTP body");
        bytes.extend_from_slice(&chunk[..read]);
    }
    serde_json::from_slice(&bytes[header_end..header_end + content_length]).expect("JSON request")
}

fn mock_rpc(tip_height: u64, active_hash: &'static str) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock RPC");
    let url = format!("http://{}", listener.local_addr().expect("local address"));
    let handle = thread::spawn(move || {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().expect("accept RPC connection");
            let request = request_body(&mut stream);
            let result = match request["method"].as_str().expect("RPC method") {
                "getblockcount" => json!(tip_height),
                "getblockhash" => json!(active_hash),
                "getblockheader" => json!(GENESIS_HEADER),
                method => panic!("unexpected RPC method {method}"),
            };
            let body = json!({"result": result, "error": null, "id": request["id"]}).to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .expect("write response");
        }
    });
    (url, handle)
}

fn run_anchor(digest: &[u8; 32], tip_height: u64, active_hash: &'static str) -> Output {
    let fixture = Fixture::new();
    let digest_hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    let chain = fixture.write(
        "chain.jsonl",
        format!("{{\"record_hash\":\"{digest_hex}\",\"seq\":0}}\n"),
    );
    let proof = fixture.write("tip.ots", proof(digest, 0));
    let cookie = fixture.write(".cookie", "user:password\n");
    let (url, server) = mock_rpc(tip_height, active_hash);
    let output = Command::new(env!("CARGO_BIN_EXE_vestrix-verify"))
        .args(["anchor"])
        .arg(chain)
        .args(["--ots-proof"])
        .arg(proof)
        .args(["--rpc-url", &url])
        .args(["--rpc-cookie"])
        .arg(cookie)
        .output()
        .expect("run anchor command");
    server.join().expect("mock RPC server");
    output
}

#[test]
fn verifies_with_real_corepc_client_response_shapes() {
    let digest: [u8; 32] = decode_hex(GENESIS_MERKLE_BYTES)
        .try_into()
        .expect("32-byte Merkle root");
    let output = run_anchor(&digest, 5, GENESIS_HASH);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("anchor valid"), "{stdout}");
    assert!(stdout.contains("6 confirmations"), "{stdout}");
}

#[test]
fn commitment_mismatch_is_specific_and_nonzero() {
    let output = run_anchor(&[0x11; 32], 5, GENESIS_HASH);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("commitment mismatch"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn insufficient_confirmations_is_specific_and_nonzero() {
    let digest: [u8; 32] = decode_hex(GENESIS_MERKLE_BYTES)
        .try_into()
        .expect("32-byte Merkle root");
    let output = run_anchor(&digest, 4, GENESIS_HASH);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("insufficient confirmations"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inconsistent_active_chain_header_is_specific_and_nonzero() {
    let digest: [u8; 32] = decode_hex(GENESIS_MERKLE_BYTES)
        .try_into()
        .expect("32-byte Merkle root");
    let output = run_anchor(
        &digest,
        5,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("block not on active chain"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn unreachable_rpc_is_specific_and_nonzero() {
    let fixture = Fixture::new();
    let digest = [0x22; 32];
    let chain = fixture.write(
        "chain.jsonl",
        format!("{{\"record_hash\":\"{}\",\"seq\":0}}\n", "22".repeat(32)),
    );
    let proof = fixture.write("tip.ots", proof(&digest, 0));
    let cookie = fixture.write(".cookie", "user:password\n");
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve unused port");
    let url = format!("http://{}", listener.local_addr().expect("local address"));
    drop(listener);

    let output = Command::new(env!("CARGO_BIN_EXE_vestrix-verify"))
        .args(["anchor"])
        .arg(chain)
        .args(["--ots-proof"])
        .arg(proof)
        .args(["--rpc-url", &url])
        .args(["--rpc-cookie"])
        .arg(cookie)
        .output()
        .expect("run anchor command");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("RPC unreachable"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires VESTRIX_REGTEST_RPC_URL/USER/PASSWORD and a regtest node with six blocks"]
fn verifies_against_real_bitcoin_core_regtest() {
    let url = std::env::var("VESTRIX_REGTEST_RPC_URL").expect("regtest RPC URL");
    let user = std::env::var("VESTRIX_REGTEST_RPC_USER").expect("regtest RPC user");
    let password = std::env::var("VESTRIX_REGTEST_RPC_PASSWORD").expect("regtest RPC password");
    let client = Client::new_with_auth(&url, Auth::UserPass(user, password)).expect("RPC client");
    let block_hash = client
        .get_block_hash(1)
        .expect("getblockhash")
        .block_hash()
        .expect("block hash");
    let header = client
        .get_block_header(&block_hash)
        .expect("getblockheader")
        .block_header()
        .expect("block header");
    let digest = header.merkle_root.to_byte_array();

    let fixture = Fixture::new();
    let digest_hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    let chain = fixture.write(
        "regtest-chain.jsonl",
        format!("{{\"record_hash\":\"{digest_hex}\",\"seq\":0}}\n"),
    );
    let proof = fixture.write("regtest-tip.ots", proof(&digest, 1));
    let report = anchor::verify_anchor(&chain, &proof, &client).expect("valid regtest anchor");

    assert_eq!(report.height, 1);
    assert_eq!(report.block_hash, block_hash.to_string());
    assert_eq!(report.confirmations, 6);
}
