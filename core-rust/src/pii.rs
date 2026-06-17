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
use regex::Regex;
use std::sync::OnceLock;

struct PiiPattern {
    name: &'static str,
    regex: Regex,
    mask: &'static str,
}

static PII_PATTERNS: OnceLock<Vec<PiiPattern>> = OnceLock::new();

fn get_pii_patterns() -> &'static Vec<PiiPattern> {
    PII_PATTERNS.get_or_init(|| {
        vec![
            PiiPattern {
                name: "email",
                regex: Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap(),
                mask: "[EMAIL_REDACTED]",
            },
            PiiPattern {
                name: "credit_card",
                regex: Regex::new(r"\b(?:\d{4}[\s\-]?){3}\d{4}\b").unwrap(),
                mask: "[CC_REDACTED]",
            },
            PiiPattern {
                name: "ssn",
                regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
                mask: "[SSN_REDACTED]",
            },
            PiiPattern {
                name: "phone",
                regex: Regex::new(r"(?:\+?\d{1,3}[\s\-.]?)?\(?\d{2,4}\)?[\s\-.]?\d{3,4}[\s\-.]?\d{3,4}\b").unwrap(),
                mask: "[PHONE_REDACTED]",
            },
            PiiPattern {
                name: "iban",
                regex: Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b").unwrap(),
                mask: "[IBAN_REDACTED]",
            },
            PiiPattern {
                name: "ip_address",
                regex: Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b").unwrap(),
                mask: "[IP_REDACTED]",
            },
        ]
    })
}

/// Result of PII scanning.
#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct PiiResult {
    #[pyo3(get)]
    pub redacted_text: String,
    #[pyo3(get)]
    pub count: usize,
    #[pyo3(get)]
    pub categories: Vec<String>,
    #[pyo3(get)]
    pub details: Vec<(String, usize)>,
}

#[pymethods]
impl PiiResult {
    fn to_dict(&self) -> PyResult<Py<PyAny>> {
        Python::attach(|py| {
            let dict = pyo3::types::PyDict::new(py);
            dict.set_item("redacted_text", &self.redacted_text)?;
            dict.set_item("count", self.count)?;
            dict.set_item("categories", &self.categories)?;
            Ok(dict.unbind().into())
        })
    }
}

/// High-performance PII scanner using compiled Rust regex.
#[pyclass]
pub struct RustPiiScanner {
    total_scans: u64,
    total_redactions: u64,
}

#[pymethods]
impl RustPiiScanner {
    #[new]
    fn new() -> Self {
        let _ = get_pii_patterns();
        RustPiiScanner {
            total_scans: 0,
            total_redactions: 0,
        }
    }

    /// Scan text and redact all PII. Returns PiiResult.
    fn redact(&mut self, text: &str) -> PiiResult {
        self.total_scans += 1;
        let patterns = get_pii_patterns();

        let mut result = text.to_string();
        let mut count: usize = 0;
        let mut categories = Vec::new();
        let mut details: Vec<(String, usize)> = Vec::new();

        for pattern in patterns.iter() {
            let matches: Vec<_> = pattern.regex.find_iter(&result).collect();
            let match_count = matches.len();
            if match_count > 0 {
                result = pattern.regex.replace_all(&result, pattern.mask).to_string();
                count += match_count;
                categories.push(pattern.name.to_string());
                details.push((pattern.name.to_string(), match_count));
            }
        }

        self.total_redactions += count as u64;

        PiiResult {
            redacted_text: result,
            count,
            categories,
            details,
        }
    }

    /// Scan only — detect PII without redacting.
    fn scan(&self, text: &str) -> PiiResult {
        let patterns = get_pii_patterns();
        let mut count: usize = 0;
        let mut categories = Vec::new();
        let mut details: Vec<(String, usize)> = Vec::new();

        for pattern in patterns.iter() {
            let match_count = pattern.regex.find_iter(text).count();
            if match_count > 0 {
                count += match_count;
                categories.push(pattern.name.to_string());
                details.push((pattern.name.to_string(), match_count));
            }
        }

        PiiResult {
            redacted_text: text.to_string(),
            count,
            categories,
            details,
        }
    }

    fn get_stats(&self) -> PyResult<Py<PyAny>> {
        Python::attach(|py| {
            let dict = pyo3::types::PyDict::new(py);
            dict.set_item("total_scans", self.total_scans)?;
            dict.set_item("total_redactions", self.total_redactions)?;
            dict.set_item("pattern_count", get_pii_patterns().len())?;
            dict.set_item("engine", "rust")?;
            Ok(dict.unbind().into())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_redaction() {
        let mut s = RustPiiScanner::new();
        let r = s.redact("Contact john@example.com for details");
        assert!(!r.redacted_text.contains("john@example.com"));
        assert!(r.redacted_text.contains("[EMAIL_REDACTED]"));
        assert!(r.count >= 1);
    }

    #[test]
    fn test_ssn_redaction() {
        let mut s = RustPiiScanner::new();
        let r = s.redact("SSN: 123-45-6789");
        assert!(!r.redacted_text.contains("123-45-6789"));
        assert!(r.count >= 1);
    }

    #[test]
    fn test_credit_card_redaction() {
        let mut s = RustPiiScanner::new();
        let r = s.redact("Card: 4111-2222-3333-4444");
        assert!(!r.redacted_text.contains("4111-2222-3333-4444"));
    }

    #[test]
    fn test_no_pii() {
        let mut s = RustPiiScanner::new();
        let r = s.redact("Normal text with no sensitive data");
        assert_eq!(r.count, 0);
        assert_eq!(r.redacted_text, "Normal text with no sensitive data");
    }

    #[test]
    fn test_scan_without_redacting() {
        let s = RustPiiScanner::new();
        let r = s.scan("Email: test@mail.com, SSN: 123-45-6789");
        assert!(r.count >= 2);
        assert!(r.redacted_text.contains("test@mail.com")); // scan doesn't redact
    }

    #[test]
    fn test_empty_string() {
        let mut s = RustPiiScanner::new();
        let r = s.redact("");
        assert_eq!(r.count, 0);
    }
}
