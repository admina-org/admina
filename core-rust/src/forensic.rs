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
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// The current time as RFC 3339 UTC text and as milliseconds since the epoch.
fn now_utc() -> (String, i64) {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = since_epoch.as_secs() as i64;
    let millis = secs * 1000 + i64::from(since_epoch.subsec_millis());
    (rfc3339_utc(secs, since_epoch.subsec_nanos()), millis)
}

/// RFC 3339 text of a UTC instant, `YYYY-MM-DDTHH:MM:SS[.fff[fff[fff]]]+00:00`:
/// the fraction takes 3, 6 or 9 digits, the fewest that hold every non-zero
/// digit, and is left out for a whole second.
fn rfc3339_utc(secs: i64, nanos: u32) -> String {
    let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
    let in_day = secs.rem_euclid(86_400);
    let (hour, minute, second) = (in_day / 3600, in_day % 3600 / 60, in_day % 60);
    let fraction = if nanos == 0 {
        String::new()
    } else if nanos.is_multiple_of(1_000_000) {
        format!(".{:03}", nanos / 1_000_000)
    } else if nanos.is_multiple_of(1_000) {
        format!(".{:06}", nanos / 1_000)
    } else {
        format!(".{:09}", nanos)
    };
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{fraction}+00:00")
}

/// The proleptic Gregorian date of a day counted from 1970-01-01
/// (H. Hinnant, "chrono-Compatible Low-Level Date Algorithms").
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

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
        let (timestamp_iso, timestamp_ms) = now_utc();

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
    fn test_rfc3339_whole_seconds() {
        assert_eq!(rfc3339_utc(0, 0), "1970-01-01T00:00:00+00:00");
        assert_eq!(rfc3339_utc(951_782_400, 0), "2000-02-29T00:00:00+00:00");
        assert_eq!(rfc3339_utc(1_763_978_400, 0), "2025-11-24T10:00:00+00:00");
        assert_eq!(rfc3339_utc(4_102_444_799, 0), "2099-12-31T23:59:59+00:00");
        assert_eq!(rfc3339_utc(253_402_300_799, 0), "9999-12-31T23:59:59+00:00");
    }

    #[test]
    fn test_rfc3339_fraction_has_3_6_or_9_digits() {
        assert_eq!(rfc3339_utc(0, 500_000_000), "1970-01-01T00:00:00.500+00:00");
        assert_eq!(
            rfc3339_utc(0, 123_456_000),
            "1970-01-01T00:00:00.123456+00:00"
        );
        assert_eq!(
            rfc3339_utc(0, 123_456_789),
            "1970-01-01T00:00:00.123456789+00:00"
        );
        assert_eq!(rfc3339_utc(0, 1_000), "1970-01-01T00:00:00.000001+00:00");
        assert_eq!(rfc3339_utc(0, 1), "1970-01-01T00:00:00.000000001+00:00");
    }

    #[test]
    fn test_record_timestamps_agree() {
        let (iso, ms) = now_utc();
        let secs = ms.div_euclid(1000);
        assert!(iso.starts_with(&rfc3339_utc(secs, 0)[..19]));
        assert!(ms > 1_763_978_400_000);
    }

    #[test]
    fn test_sha256_known_value() {
        let h = RustHashChain::sha256("hello world");
        assert_eq!(
            h,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_sha256_empty() {
        let h = RustHashChain::sha256("");
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
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
