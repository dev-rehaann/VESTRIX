//! OpenTimestamps Bitcoin anchor verification.
//!
//! This module implements the detached-proof envelope and the common Bitcoin
//! path operations (append, prepend, and SHA-256). It proves that the chain tip
//! reaches a Bitcoin block-header attestation, then verifies the commitment
//! against the active-chain header returned by an independently configured
//! Bitcoin Core node.

use std::fmt;
use std::fs;
use std::path::Path;

use corepc_client::bitcoin::hashes::Hash;
use corepc_client::client_sync::v17::Client;
use sha2::{Digest, Sha256};

use crate::chain::{self, ChainTip};

const MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
const BITCOIN_ATTESTATION: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
const MAX_ARGUMENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_ATTESTATION_BYTES: usize = 8192;
const MAX_OP_BYTES: usize = 4096;
const MAX_DEPTH: usize = 256;

#[derive(Debug)]
pub struct AnchorError(pub String);

impl fmt::Display for AnchorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for AnchorError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinAttestation {
    pub height: u64,
    pub commitment: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectedProof {
    pub attestations: Vec<BitcoinAttestation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorReport {
    pub seq: u64,
    pub height: u64,
    pub block_hash: String,
    pub confirmations: u64,
}

/// Verify the chain-tip binding and one Bitcoin attestation against Bitcoin
/// Core's current active chain. Any one valid Bitcoin proof branch is enough.
pub fn verify_anchor(
    chain_path: &Path,
    proof_path: &Path,
    client: &Client,
) -> Result<AnchorReport, AnchorError> {
    let tip = read_tip_without_authentication(chain_path)
        .map_err(|error| AnchorError(format!("chain tip invalid: {error}")))?;
    let tip_bytes = chain::decode_hex_array::<32>(&tip.record_hash)
        .map_err(|error| AnchorError(format!("chain tip invalid: {error}")))?;
    let proof = fs::read(proof_path)
        .map_err(|error| AnchorError(format!("proof malformed: cannot read OTS proof: {error}")))?;
    let inspected = inspect_proof(&proof, &tip_bytes)
        .map_err(|error| AnchorError(format!("proof malformed: {error}")))?;
    let tip_height = client
        .get_block_count()
        .map_err(|error| AnchorError(format!("RPC unreachable: getblockcount failed: {error}")))?
        .0;
    let mut last_failure = None;

    for attestation in inspected.attestations {
        if attestation.height > tip_height {
            last_failure = Some(AnchorError(format!(
                "block not on active chain: attested height {} is above current tip height {tip_height}",
                attestation.height
            )));
            continue;
        }
        // The OTS Bitcoin attestation stores only height, never a block hash.
        // Therefore the node's by-height active-chain hash is authoritative.
        let active_hash = client
            .get_block_hash(attestation.height)
            .map_err(|error| {
                AnchorError(format!(
                    "RPC unreachable: getblockhash({}) failed: {error}",
                    attestation.height
                ))
            })?
            .block_hash()
            .map_err(|error| {
                AnchorError(format!(
                    "RPC unreachable: getblockhash({}) returned a malformed hash: {error}",
                    attestation.height
                ))
            })?;
        let header = client
            .get_block_header(&active_hash)
            .map_err(|error| {
                AnchorError(format!(
                    "RPC unreachable: getblockheader({active_hash}) failed: {error}"
                ))
            })?
            .block_header()
            .map_err(|error| {
                AnchorError(format!(
                    "RPC unreachable: getblockheader({active_hash}) returned a malformed header: {error}"
                ))
            })?;

        if header.block_hash() != active_hash {
            last_failure = Some(AnchorError(format!(
                "block not on active chain: getblockhash({}) returned {active_hash}, but that header hashes to {}",
                attestation.height,
                header.block_hash()
            )));
            continue;
        }
        if header.merkle_root.to_byte_array().as_slice() != attestation.commitment {
            last_failure = Some(AnchorError(format!(
                "commitment mismatch: OTS result does not equal the active block Merkle root at height {}",
                attestation.height
            )));
            continue;
        }

        let confirmations = tip_height - attestation.height + 1;
        if confirmations < 6 {
            last_failure = Some(AnchorError(format!(
                "insufficient confirmations: block at height {} has {confirmations}; require at least 6",
                attestation.height
            )));
            continue;
        }
        return Ok(AnchorReport {
            seq: tip.seq,
            height: attestation.height,
            block_hash: active_hash.to_string(),
            confirmations,
        });
    }

    Err(last_failure.expect("inspect_proof requires at least one Bitcoin attestation"))
}

/// Parse enough of a detached OTS proof to bind a SHA-256 digest and execute
/// common Bitcoin anchoring paths.
pub fn inspect_proof(
    proof: &[u8],
    expected_digest: &[u8; 32],
) -> Result<InspectedProof, AnchorError> {
    if proof.len() > MAX_PROOF_BYTES {
        return Err(AnchorError(
            "OTS proof exceeds the 16 MiB safety limit".to_owned(),
        ));
    }
    let mut parser = Parser::new(proof);
    parser.expect(MAGIC, "invalid OTS detached-proof header")?;
    let version = parser.byte()?;
    if version != 1 {
        return Err(AnchorError(format!("unsupported OTS version {version}")));
    }
    let hash_op = parser.byte()?;
    if hash_op != 0x08 {
        return Err(AnchorError(format!(
            "OTS proof uses unsupported file hash operation 0x{hash_op:02x}; expected SHA-256"
        )));
    }
    let digest = parser.take(32)?;
    if digest != expected_digest {
        return Err(AnchorError(
            "OTS proof digest does not match the current chain tip record_hash".to_owned(),
        ));
    }

    let mut attestations = Vec::new();
    parser.timestamp(expected_digest.to_vec(), 0, &mut attestations)?;
    if !parser.is_finished() {
        return Err(AnchorError("trailing bytes after OTS proof".to_owned()));
    }
    if attestations.is_empty() {
        return Err(AnchorError(
            "OTS proof has no supported Bitcoin block-header attestation".to_owned(),
        ));
    }
    Ok(InspectedProof { attestations })
}

fn read_tip_without_authentication(path: &Path) -> Result<ChainTip, AnchorError> {
    let bytes =
        fs::read(path).map_err(|error| AnchorError(format!("cannot read chain: {error}")))?;
    if bytes.is_empty() {
        return Err(AnchorError("empty chain has no tip to anchor".to_owned()));
    }
    if bytes.last() != Some(&b'\n') {
        return Err(AnchorError("chain is not LF-terminated".to_owned()));
    }
    let line = bytes[..bytes.len() - 1]
        .rsplit(|byte| *byte == b'\n')
        .next()
        .ok_or_else(|| AnchorError("empty chain has no tip to anchor".to_owned()))?;
    let text = std::str::from_utf8(line)
        .map_err(|error| AnchorError(format!("chain tip is not UTF-8: {error}")))?;
    let value = crate::canonical::parse(text)
        .map_err(|error| AnchorError(format!("chain tip is invalid JSON: {error}")))?;
    let canonical = crate::canonical::serialize(&value)
        .map_err(|error| AnchorError(format!("cannot serialize chain tip: {error}")))?;
    if canonical != line {
        return Err(AnchorError("chain tip JSON is not canonical".to_owned()));
    }
    let object = value
        .as_object()
        .ok_or_else(|| AnchorError("chain tip is not an object".to_owned()))?;
    let seq = object
        .get("seq")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| AnchorError("chain tip has no valid seq".to_owned()))?;
    let record_hash = object
        .get("record_hash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AnchorError("chain tip has no record_hash".to_owned()))?
        .to_owned();
    Ok(ChainTip { seq, record_hash })
}

struct Parser<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn is_finished(&self) -> bool {
        self.position == self.input.len()
    }

    fn byte(&mut self) -> Result<u8, AnchorError> {
        let byte = self
            .input
            .get(self.position)
            .copied()
            .ok_or_else(|| AnchorError("unexpected end of OTS proof".to_owned()))?;
        self.position += 1;
        Ok(byte)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], AnchorError> {
        let end = self
            .position
            .checked_add(length)
            .filter(|end| *end <= self.input.len())
            .ok_or_else(|| AnchorError("unexpected end of OTS proof".to_owned()))?;
        let bytes = &self.input[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    fn expect(&mut self, expected: &[u8], reason: &str) -> Result<(), AnchorError> {
        if self.take(expected.len())? != expected {
            return Err(AnchorError(reason.to_owned()));
        }
        Ok(())
    }

    fn varuint(&mut self) -> Result<u64, AnchorError> {
        let mut value = 0_u64;
        let mut shift = 0_u32;
        loop {
            let byte = self.byte()?;
            let chunk = u64::from(byte & 0x7f);
            if chunk > (u64::MAX >> shift) {
                return Err(AnchorError("OTS variable integer overflow".to_owned()));
            }
            value |= chunk << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift = shift
                .checked_add(7)
                .filter(|shift| *shift < 64)
                .ok_or_else(|| AnchorError("OTS variable integer overflow".to_owned()))?;
        }
    }

    fn varbytes(&mut self) -> Result<&'a [u8], AnchorError> {
        let length = usize::try_from(self.varuint()?)
            .map_err(|_| AnchorError("OTS byte string is too large".to_owned()))?;
        if length > MAX_ARGUMENT_BYTES {
            return Err(AnchorError(
                "OTS byte string exceeds the 4 MiB safety limit".to_owned(),
            ));
        }
        self.take(length)
    }

    fn timestamp(
        &mut self,
        message: Vec<u8>,
        depth: usize,
        attestations: &mut Vec<BitcoinAttestation>,
    ) -> Result<(), AnchorError> {
        if depth > MAX_DEPTH {
            return Err(AnchorError("OTS proof is nested too deeply".to_owned()));
        }
        let tag = self.byte()?;
        self.timestamp_from_tag(tag, message, depth, attestations)
    }

    fn timestamp_from_tag(
        &mut self,
        tag: u8,
        message: Vec<u8>,
        depth: usize,
        attestations: &mut Vec<BitcoinAttestation>,
    ) -> Result<(), AnchorError> {
        if depth > MAX_DEPTH {
            return Err(AnchorError("OTS proof is nested too deeply".to_owned()));
        }
        match tag {
            0x00 => self.attestation(&message, attestations),
            0xff => loop {
                self.timestamp(message.clone(), depth + 1, attestations)?;
                let next_tag = self.byte()?;
                if next_tag != 0xff {
                    return self.timestamp_from_tag(next_tag, message, depth + 1, attestations);
                }
            },
            operation => {
                let next = self.operation_from_tag(operation, message)?;
                self.timestamp(next, depth + 1, attestations)
            }
        }
    }

    fn attestation(
        &mut self,
        message: &[u8],
        attestations: &mut Vec<BitcoinAttestation>,
    ) -> Result<(), AnchorError> {
        let tag: [u8; 8] = self
            .take(8)?
            .try_into()
            .expect("take returned exactly eight bytes");
        let payload = self.varbytes()?;
        if payload.len() > MAX_ATTESTATION_BYTES {
            return Err(AnchorError(
                "OTS attestation payload exceeds the 8192-byte limit".to_owned(),
            ));
        }
        if tag == BITCOIN_ATTESTATION {
            if message.len() != 32 {
                return Err(AnchorError(format!(
                    "Bitcoin attestation commitment is {} bytes; expected 32",
                    message.len()
                )));
            }
            let mut payload_parser = Parser::new(payload);
            let height = payload_parser.varuint()?;
            if !payload_parser.is_finished() {
                return Err(AnchorError(
                    "invalid Bitcoin attestation payload".to_owned(),
                ));
            }
            attestations.push(BitcoinAttestation {
                height,
                commitment: message.to_vec(),
            });
        }
        Ok(())
    }

    fn operation_from_tag(&mut self, tag: u8, message: Vec<u8>) -> Result<Vec<u8>, AnchorError> {
        match tag {
            0x08 => Ok(Sha256::digest(message).to_vec()),
            0xf0 => {
                let suffix = self.varbytes()?;
                validate_op_argument(suffix, message.len())?;
                let mut output = message;
                output.extend_from_slice(suffix);
                Ok(output)
            }
            0xf1 => {
                let prefix = self.varbytes()?;
                validate_op_argument(prefix, message.len())?;
                let mut output = Vec::with_capacity(prefix.len() + message.len());
                output.extend_from_slice(prefix);
                output.extend_from_slice(&message);
                Ok(output)
            }
            unsupported => Err(AnchorError(format!(
                "unsupported OTS operation 0x{unsupported:02x}; only append, prepend, and SHA-256 Bitcoin paths are implemented"
            ))),
        }
    }
}

fn validate_op_argument(argument: &[u8], message_length: usize) -> Result<(), AnchorError> {
    if argument.is_empty() || argument.len() > MAX_OP_BYTES {
        return Err(AnchorError(
            "OTS append/prepend argument must contain 1..4096 bytes".to_owned(),
        ));
    }
    if message_length
        .checked_add(argument.len())
        .is_none_or(|length| length > MAX_OP_BYTES)
    {
        return Err(AnchorError(
            "OTS operation result exceeds the 4096-byte safety limit".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof_prefix(digest: &[u8; 32]) -> Vec<u8> {
        let mut proof = MAGIC.to_vec();
        proof.extend_from_slice(&[0x01, 0x08]);
        proof.extend_from_slice(digest);
        proof
    }

    #[test]
    fn follows_common_bitcoin_path() {
        let digest = [0x11; 32];
        let mut proof = proof_prefix(&digest);
        proof.extend_from_slice(&[0xf0, 0x01, 0xaa, 0x08, 0x00]);
        proof.extend_from_slice(&BITCOIN_ATTESTATION);
        proof.extend_from_slice(&[0x02, 0xe8, 0x07]);

        let inspected = inspect_proof(&proof, &digest).expect("proof should parse");
        assert_eq!(inspected.attestations.len(), 1);
        assert_eq!(inspected.attestations[0].height, 1000);
        let mut preimage = digest.to_vec();
        preimage.push(0xaa);
        assert_eq!(
            inspected.attestations[0].commitment,
            Sha256::digest(preimage).to_vec()
        );
    }

    #[test]
    fn handles_fork_and_ignores_unknown_attestation() {
        let digest = [0x22; 32];
        let mut proof = proof_prefix(&digest);
        proof.push(0xff);
        proof.push(0x00);
        proof.extend_from_slice(&[0x99; 8]);
        proof.push(0x00);
        proof.push(0x00);
        proof.extend_from_slice(&BITCOIN_ATTESTATION);
        proof.extend_from_slice(&[0x01, 0x2a]);

        let inspected = inspect_proof(&proof, &digest).expect("forked proof should parse");
        assert_eq!(inspected.attestations.len(), 1);
        assert_eq!(inspected.attestations[0].height, 42);
        assert_eq!(inspected.attestations[0].commitment, digest);
    }

    #[test]
    fn rejects_digest_mismatch() {
        let proof_digest = [0x33; 32];
        let proof = proof_prefix(&proof_digest);
        let error = inspect_proof(&proof, &[0x44; 32]).unwrap_err();
        assert!(error.0.contains("does not match"));
    }

    #[test]
    fn rejects_variable_integer_overflow() {
        let digest = [0x55; 32];
        let mut proof = proof_prefix(&digest);
        proof.push(0x00);
        proof.extend_from_slice(&BITCOIN_ATTESTATION);
        proof.push(0x0b);
        proof.extend_from_slice(&[0xff; 10]);
        proof.push(0x02);
        let error = inspect_proof(&proof, &digest).unwrap_err();
        assert!(error.0.contains("variable integer overflow"));
    }
}
