use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use vestrix_verifier_cli::canonical;

const PUBLIC_KEY: &str = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
const STORED_LINE: &str = concat!(
    r#"{"class":"normal","confidence":0.875,"event_type":"classification_decision","features_hash":"2222222222222222222222222222222222222222222222222222222222222222","format_version":2,"model_config_hash":"3333333333333333333333333333333333333333333333333333333333333333","model_id":"model-v1","node_id":"node-01","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","raw_csi_hash":"1111111111111111111111111111111111111111111111111111111111111111","record_hash":"a3cf276f603ad38d4c36c6319a47f1aaf618ace6c00a5da65d33cbd3caaa6efb","seq":0,"signature":"e24926670ba994607ddabd50de2506d4e916ace4f35cc470e545015f512262d9122baf4e44a5db6ca5923f18ee2be9286d6f840bc8310fd882dd24fedafdd00d","top_shap":[],"ts_utc":"2026-07-13T12:00:00Z"}"#,
    "\n"
);
const V1_STORED_LINE: &str = concat!(
    r#"{"class":"normal","confidence":0.875,"features_hash":"2222222222222222222222222222222222222222222222222222222222222222","model_config_hash":"3333333333333333333333333333333333333333333333333333333333333333","model_id":"model-v1","node_id":"node-01","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","raw_csi_hash":"1111111111111111111111111111111111111111111111111111111111111111","record_hash":"ef5d7fe2153bd2653b9e8b2d19044498dfe07016a479a2c831d7e63c774777e8","seq":0,"signature":"872e9ac9e8f2c0fb3473ecfc85d852a622460ae3a9718a35376f21eaa16c547b6a35fb9633b8501b982cb7ab535631ad50ab9b7b58ed3d873a896b059318650f","top_shap":[],"ts_utc":"2026-07-13T12:00:00Z"}"#,
    "\n"
);

struct Fixture {
    directory: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "vestrix-verifier-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create test directory");
        Self { directory }
    }

    fn write(&self, name: &str, contents: impl AsRef<[u8]>) -> PathBuf {
        let path = self.directory.join(name);
        fs::write(&path, contents).expect("write fixture");
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn verify(chain: &Path, key: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_vestrix-verify"))
        .args(["chain"])
        .arg(chain)
        .args(["--pubkey"])
        .arg(key)
        .output()
        .expect("run vestrix-verify")
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unsigned_record(seq: u64, confidence: f64, previous: &str) -> Map<String, Value> {
    let mut unsigned = Map::new();
    unsigned.insert("format_version".to_owned(), json!(2));
    unsigned.insert("event_type".to_owned(), json!("classification_decision"));
    unsigned.insert("seq".to_owned(), json!(seq));
    unsigned.insert(
        "ts_utc".to_owned(),
        Value::String(format!("2026-07-13T12:00:{seq:02}Z")),
    );
    unsigned.insert("node_id".to_owned(), json!("node-01"));
    unsigned.insert("raw_csi_hash".to_owned(), json!("1".repeat(64)));
    unsigned.insert("features_hash".to_owned(), json!("2".repeat(64)));
    unsigned.insert("model_id".to_owned(), json!("model-v1"));
    unsigned.insert("model_config_hash".to_owned(), json!("3".repeat(64)));
    unsigned.insert("class".to_owned(), json!("normal"));
    unsigned.insert("confidence".to_owned(), json!(confidence));
    unsigned.insert("top_shap".to_owned(), json!([]));
    unsigned.insert("prev_hash".to_owned(), json!(previous));
    unsigned
}

fn ingestion_record(seq: u64, previous: &str) -> Map<String, Value> {
    let mut unsigned = Map::new();
    unsigned.insert("format_version".to_owned(), json!(2));
    unsigned.insert("event_type".to_owned(), json!("ingestion_accepted"));
    unsigned.insert("seq".to_owned(), json!(seq));
    unsigned.insert(
        "ts_utc".to_owned(),
        Value::String(format!("2026-07-13T12:00:{seq:02}Z")),
    );
    unsigned.insert("node_id".to_owned(), json!("node-01"));
    unsigned.insert("raw_csi_hash".to_owned(), json!("1".repeat(64)));
    unsigned.insert("collector_schema_version".to_owned(), json!("0.1"));
    unsigned.insert("collector_sequence_number".to_owned(), json!(42));
    unsigned.insert("prev_hash".to_owned(), json!(previous));
    unsigned
}

fn signed_chain(sequences: &[u64]) -> Vec<u8> {
    let seed: [u8; 32] = std::array::from_fn(|index| u8::try_from(index).unwrap());
    let signing_key = SigningKey::from_bytes(&seed);
    assert_eq!(
        encode_hex(signing_key.verifying_key().as_bytes()),
        PUBLIC_KEY
    );
    let mut previous = "0".repeat(64);
    let mut chain = Vec::new();

    for &seq in sequences {
        let mut unsigned = unsigned_record(seq, 0.875, &previous);
        let record_bytes = canonical::serialize(&Value::Object(unsigned.clone())).unwrap();
        let hash = encode_hex(&Sha256::digest(&record_bytes));
        let signature = encode_hex(&signing_key.sign(&record_bytes).to_bytes());
        unsigned.insert("record_hash".to_owned(), json!(hash));
        unsigned.insert("signature".to_owned(), json!(signature));
        chain.extend(canonical::serialize(&Value::Object(unsigned)).unwrap());
        chain.push(b'\n');
        previous = hash;
    }
    chain
}

fn mixed_v2_chain() -> Vec<u8> {
    let seed: [u8; 32] = std::array::from_fn(|index| u8::try_from(index).unwrap());
    let signing_key = SigningKey::from_bytes(&seed);
    let mut previous = "0".repeat(64);
    let mut chain = Vec::new();

    for mut unsigned in [
        ingestion_record(0, &previous),
        unsigned_record(1, 0.875, "placeholder"),
    ] {
        unsigned.insert("prev_hash".to_owned(), json!(previous));
        let record_bytes = canonical::serialize(&Value::Object(unsigned.clone())).unwrap();
        let hash = encode_hex(&Sha256::digest(&record_bytes));
        let signature = encode_hex(&signing_key.sign(&record_bytes).to_bytes());
        unsigned.insert("record_hash".to_owned(), json!(hash));
        unsigned.insert("signature".to_owned(), json!(signature));
        chain.extend(canonical::serialize(&Value::Object(unsigned)).unwrap());
        chain.push(b'\n');
        previous = hash;
    }
    chain
}

fn mixed_version_chain() -> Vec<u8> {
    let seed: [u8; 32] = std::array::from_fn(|index| u8::try_from(index).unwrap());
    let signing_key = SigningKey::from_bytes(&seed);
    let mut unsigned = unsigned_record(
        1,
        0.875,
        "ef5d7fe2153bd2653b9e8b2d19044498dfe07016a479a2c831d7e63c774777e8",
    );
    let record_bytes = canonical::serialize(&Value::Object(unsigned.clone())).unwrap();
    let hash = encode_hex(&Sha256::digest(&record_bytes));
    let signature = encode_hex(&signing_key.sign(&record_bytes).to_bytes());
    unsigned.insert("record_hash".to_owned(), json!(hash));
    unsigned.insert("signature".to_owned(), json!(signature));

    let mut chain = V1_STORED_LINE.as_bytes().to_vec();
    chain.extend(canonical::serialize(&Value::Object(unsigned)).unwrap());
    chain.push(b'\n');
    chain
}

#[test]
fn python_float_spec_vectors_match_hashes_and_signatures() {
    let seed: [u8; 32] = std::array::from_fn(|index| u8::try_from(index).unwrap());
    let signing_key = SigningKey::from_bytes(&seed);
    let cases = [
        (
            1.0,
            "1fb4432bfe63a9cf6b54e8ae416ec5d11bd87d6669b527d8c801e54500c4287f",
            concat!(
                "e2a179bc96914aecd5b680659f3158e6067adb64fb20a286a9690de84c56df71",
                "41ee3e3d1681d1c129a3f92685c1023baf04f642fbdfcb3aefdbf9bd9ef63f03"
            ),
        ),
        (
            0.9532,
            "5d6c9cc40f8db9dcf9984ce87cc7889eec0e0694426d0a3d20e97efaa739afc7",
            concat!(
                "b61ad135f9ea5fa3894646c74b4f6b6c410daa10bc7c47feb1a8a288b9bedf6e",
                "fcbd93ce8291c798048899f0a428123ef9acc6c4838bce1372c9978705012c04"
            ),
        ),
        (
            0.1 + 0.2,
            "576598c9ed876b0d040e3d1149883994d0f7e4f1f7800605d9d2552237e72ab6",
            concat!(
                "33344ebde2b8cb80741e9e74e64c26342be691fb1924c0389ba802903d473b09",
                "49c54a91f837534881386f6e21293ccac5ade1764542c584eb1ae6ccc888ff0b"
            ),
        ),
        (
            0.00001,
            "e6019ec3fc79d8c4e22ae378cdd5a8a1753f6bbb36ac847959e34031fae083cf",
            concat!(
                "4545cf6255c52fe1a8ea9849621ac8c3a812570534057681227d212b2274535e",
                "0cbea61e30c8565d695fd9308a155093e546d67b81039a21bf9fc4f5edc53d0a"
            ),
        ),
    ];

    for (confidence, expected_hash, expected_signature) in cases {
        let unsigned = unsigned_record(0, confidence, &"0".repeat(64));
        let record_bytes = canonical::serialize(&Value::Object(unsigned)).unwrap();
        assert_eq!(encode_hex(&Sha256::digest(&record_bytes)), expected_hash);
        assert_eq!(
            encode_hex(&signing_key.sign(&record_bytes).to_bytes()),
            expected_signature
        );
    }
}

#[test]
fn spec_vector_is_byte_for_byte_compatible() {
    let fixture = Fixture::new();
    let chain = fixture.write("chain.jsonl", STORED_LINE);
    let key = fixture.write("public-key.hex", format!("{PUBLIC_KEY}\n"));

    let output = verify(&chain, &key);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("chain valid: 1 record(s)"));
}

#[test]
fn v2_ingestion_and_classification_records_verify_in_one_chain() {
    let fixture = Fixture::new();
    let chain = fixture.write("mixed-v2.jsonl", mixed_v2_chain());
    let key = fixture.write("public-key.hex", PUBLIC_KEY);

    let output = verify(&chain, &key);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("chain valid: 2 record(s)"));
}

#[test]
fn legacy_v1_chain_remains_verifiable() {
    let fixture = Fixture::new();
    let chain = fixture.write("legacy-v1.jsonl", V1_STORED_LINE);
    let key = fixture.write("public-key.hex", PUBLIC_KEY);

    let output = verify(&chain, &key);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn mixed_v1_and_v2_chain_is_rejected() {
    let fixture = Fixture::new();
    let chain = fixture.write("mixed-version.jsonl", mixed_version_chain());
    let key = fixture.write("public-key.hex", PUBLIC_KEY);

    let output = verify(&chain, &key);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("seq 1: chain mixes format versions"));
}

#[test]
fn one_corrupt_historical_byte_reports_its_sequence() {
    let fixture = Fixture::new();
    let mut corrupted = signed_chain(&[0, 1, 2]);
    let needle = b"normal";
    let offset = corrupted
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle)
        .nth(1)
        .map(|(offset, _)| offset)
        .expect("second record class value exists");
    corrupted[offset] = b'N';
    let chain = fixture.write("corrupt.jsonl", corrupted);
    let key = fixture.write("public-key.hex", PUBLIC_KEY);

    let output = verify(&chain, &key);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed at seq 1: record_hash mismatch"),
        "{stderr}"
    );
}

#[test]
fn validly_signed_hash_linked_sequence_gap_is_rejected_distinctly() {
    let fixture = Fixture::new();
    let chain = fixture.write("sequence-gap.jsonl", signed_chain(&[0, 1, 3]));
    let key = fixture.write("public-key.hex", PUBLIC_KEY);

    let output = verify(&chain, &key);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed at seq 2: sequence gap: found seq 3, expected 2"),
        "{stderr}"
    );
    assert!(!stderr.contains("hash link broken"), "{stderr}");
}

#[test]
fn missing_final_lf_reports_next_sequence() {
    let fixture = Fixture::new();
    let chain = fixture.write("unterminated.jsonl", STORED_LINE.trim_end_matches('\n'));
    let key = fixture.write("public-key.hex", PUBLIC_KEY);

    let output = verify(&chain, &key);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("seq 0: record is not LF-terminated"));
}

#[test]
fn altered_signature_is_rejected() {
    let fixture = Fixture::new();
    let mut corrupted = STORED_LINE.as_bytes().to_vec();
    let signature = br#""signature":"#;
    let offset = corrupted
        .windows(signature.len())
        .position(|window| window == signature)
        .expect("signature exists")
        + signature.len();
    corrupted[offset] = if corrupted[offset] == b'9' {
        b'8'
    } else {
        b'9'
    };
    let chain = fixture.write("bad-signature.jsonl", corrupted);
    let key = fixture.write("public-key.hex", PUBLIC_KEY);

    let output = verify(&chain, &key);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("seq 0: Ed25519 signature verification failed")
    );
}

#[test]
fn anchor_nonzero_output_is_not_misrepresented_as_chain_corruption() {
    let fixture = Fixture::new();
    let missing_chain = fixture.directory.join("missing-chain.jsonl");
    let missing_proof = fixture.directory.join("missing-proof.ots");
    let output = Command::new(env!("CARGO_BIN_EXE_vestrix-verify"))
        .args(["anchor"])
        .arg(missing_chain)
        .args(["--ots-proof"])
        .arg(missing_proof)
        .output()
        .expect("run anchor command");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("anchor check incomplete"), "{stderr}");
    assert!(
        stderr.contains("does NOT mean the chain is corrupt or tampered"),
        "{stderr}"
    );
    assert!(
        stderr.contains("`chain` subcommand is the chain-integrity verdict"),
        "{stderr}"
    );
}
