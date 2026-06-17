// Copyright © 2025–2026 Stefano Noferi & Admina contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use pyo3::prelude::*;
use sha2::{Sha256, Digest};
use chrono::Utc;

/// SHA-256 hash chain for forensic black box integrity.
#[pyclass]
pub struct RustHashChain {
    previous_hash: String,
    sequence: u64,
    total_records: u64,
}

#[pymethods]
impl RustHashChain {
    #[new]
    fn new() -> Self {
        RustHashChain {
            previous_hash: "genesis".to_string(),
            sequence: 0,
            total_records: 0,
        }
    }

    /// Create a new hash-chained record.
    /// Returns dict with hash, previous_hash, sequence, timestamp.
    fn record(&mut self, event_id: &str, data: &str) -> PyResult<Py<PyAny>> {
        self.sequence += 1;
        self.total_records += 1;
        let now = Utc::now();
        let timestamp_iso = now.to_rfc3339();
        let timestamp_ms = now.timestamp_millis();

        // Build hash input: sequence + previous_hash + event_id + data + timestamp
        let hash_input = format!(
            "{}:{}:{}:{}:{}",
            self.sequence, self.previous_hash, event_id, data, timestamp_ms
        );

        let mut hasher = Sha256::new();
        hasher.update(hash_input.as_bytes());
        let hash = hex::encode(hasher.finalize());

        let prev = self.previous_hash.clone();
        self.previous_hash = hash.clone();

        Python::attach(|py| {
            let dict = pyo3::types::PyDict::new(py);
            dict.set_item("hash", &hash)?;
            dict.set_item("previous_hash", &prev)?;
            dict.set_item("sequence", self.sequence)?;
            dict.set_item("event_id", event_id)?;
            dict.set_item("timestamp_iso", &timestamp_iso)?;
            dict.set_item("timestamp_ms", timestamp_ms)?;
            dict.set_item("engine", "rust")?;
            Ok(dict.unbind().into())
        })
    }

    /// Verify a chain of records.
    /// Takes a list of (hash, previous_hash) tuples, returns (valid, broken_at).
    fn verify_chain(&self, chain: Vec<(String, String)>) -> PyResult<Py<PyAny>> {
        Python::attach(|py| {
            let dict = pyo3::types::PyDict::new(py);

            if chain.is_empty() {
                dict.set_item("valid", true)?;
                dict.set_item("length", 0)?;
                return Ok(dict.unbind().into());
            }

            for i in 1..chain.len() {
                if chain[i].1 != chain[i - 1].0 {
                    dict.set_item("valid", false)?;
                    dict.set_item("broken_at", i)?;
                    dict.set_item("expected", &chain[i - 1].0)?;
                    dict.set_item("found", &chain[i].1)?;
                    return Ok(dict.unbind().into());
                }
            }

            dict.set_item("valid", true)?;
            dict.set_item("length", chain.len())?;
            Ok(dict.unbind().into())
        })
    }

    /// Compute SHA-256 hash of arbitrary data.
    #[staticmethod]
    fn sha256(data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn get_stats(&self) -> PyResult<Py<PyAny>> {
        Python::attach(|py| {
            let dict = pyo3::types::PyDict::new(py);
            dict.set_item("total_records", self.total_records)?;
            dict.set_item("current_sequence", self.sequence)?;
            dict.set_item("engine", "rust")?;
            Ok(dict.unbind().into())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_value() {
        let h = RustHashChain::sha256("hello world");
        assert_eq!(h, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }

    #[test]
    fn test_sha256_empty() {
        let h = RustHashChain::sha256("");
        assert_eq!(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_sha256_deterministic() {
        let h1 = RustHashChain::sha256("test data");
        let h2 = RustHashChain::sha256("test data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sha256_different_inputs() {
        let h1 = RustHashChain::sha256("data1");
        let h2 = RustHashChain::sha256("data2");
        assert_ne!(h1, h2);
    }
}
