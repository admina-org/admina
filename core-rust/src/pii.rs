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
use regex::{Captures, Regex};
use std::sync::OnceLock;

struct PiiPattern {
    name: &'static str,
    regex: Regex,
    mask: &'static str,
    /// Whether a match is reported, given the scanned text: the checks the
    /// regex cannot express (a checksum, the characters around the match).
    accept: fn(&str, &Captures) -> bool,
}

fn any_match(_text: &str, _caps: &Captures) -> bool {
    true
}

/// A card number is reported only when its digits pass the Luhn checksum,
/// as in the Python PII redactor.
fn luhn_valid(_text: &str, caps: &Captures) -> bool {
    let digits: Vec<u32> = caps[0].chars().filter_map(|c| c.to_digit(10)).collect();
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if !i.is_multiple_of(2) {
                let x = d * 2;
                if x > 9 {
                    x - 9
                } else {
                    x
                }
            } else {
                d
            }
        })
        .sum();
    !digits.is_empty() && sum.is_multiple_of(10)
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The boundaries of the phone patterns of the Python PII redactor, which
/// the regex crate cannot express as lookarounds: a North American number
/// is not preceded or followed by a digit; an Italian number is not
/// preceded by a word character or "+", nor followed by a word character.
fn phone_boundaries(text: &str, caps: &Captures) -> bool {
    let whole = caps.get(0).unwrap();
    let before = text[..whole.start()].chars().next_back();
    let after = text[whole.end()..].chars().next();
    if caps.name("us").is_some() {
        !before.is_some_and(|c| c.is_ascii_digit()) && !after.is_some_and(|c| c.is_ascii_digit())
    } else {
        !before.is_some_and(|c| is_word(c) || c == '+') && !after.is_some_and(is_word)
    }
}

// Phone numbers, as in the Python PII redactor: North American format
// (3-3-4 digits, optional country code), and Italian numbers, with +39 or
// 0039 or without: mobile numbers (3 and 8 or 9 more digits, compact or in
// groups) and landline numbers (an area code 02, 06 or 0 followed by 2 or 3
// digits, then 5 to 8 digits, or 2 or 3 groups of 2 to 4 digits separated
// by spaces; without +39 a space, "/" or "-" follows the area code).
const US_PHONE: &str = r"(?:\+\d{1,3}[\s.\-]?)?\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}";
const IT_MOBILE: &str = r"3[1-9]\d(?:[ \-]?\d{6,7}|[ \-]\d{3}[ \-]\d{3,4})";
const IT_AREA: &str = r"0(?:[26]|[1-9]\d{1,2})";
const IT_SUBSCRIBER: &str = r"(?:\d{5,8}|\d{2,4} \d{2,4}(?: \d{2,4})?)";

fn phone_regex() -> Regex {
    let italian = format!(
        "(?:(?:\\+|00)39[ .\\-]?(?:{m}|{a}[ ./\\-]?{s})|{m}|{a}[ /\\-]{s})",
        m = IT_MOBILE,
        a = IT_AREA,
        s = IT_SUBSCRIBER
    );
    Regex::new(&format!("(?P<us>{US_PHONE})|(?P<it>{italian})")).unwrap()
}

static PII_PATTERNS: OnceLock<Vec<PiiPattern>> = OnceLock::new();

fn get_pii_patterns() -> &'static Vec<PiiPattern> {
    PII_PATTERNS.get_or_init(|| {
        vec![
            PiiPattern {
                name: "email",
                regex: Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap(),
                mask: "[EMAIL_REDACTED]",
                accept: any_match,
            },
            PiiPattern {
                name: "credit_card",
                regex: Regex::new(r"\b(?:\d{4}[\s\-]?){3}\d{4}\b").unwrap(),
                mask: "[CC_REDACTED]",
                accept: luhn_valid,
            },
            PiiPattern {
                name: "ssn",
                regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
                mask: "[SSN_REDACTED]",
                accept: any_match,
            },
            PiiPattern {
                name: "phone",
                regex: phone_regex(),
                mask: "[PHONE_REDACTED]",
                accept: phone_boundaries,
            },
            PiiPattern {
                name: "iban",
                regex: Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b").unwrap(),
                mask: "[IBAN_REDACTED]",
                accept: any_match,
            },
            PiiPattern {
                name: "ip_address",
                regex: Regex::new(
                    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
                )
                .unwrap(),
                mask: "[IP_REDACTED]",
                accept: any_match,
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
            let current = result.clone();
            let mut match_count: usize = 0;
            let replaced = pattern.regex.replace_all(&current, |caps: &Captures| {
                if (pattern.accept)(&current, caps) {
                    match_count += 1;
                    pattern.mask.to_string()
                } else {
                    caps[0].to_string()
                }
            });
            if match_count > 0 {
                result = replaced.into_owned();
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
            let match_count = pattern
                .regex
                .captures_iter(text)
                .filter(|caps| (pattern.accept)(text, caps))
                .count();
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
        let r = s.redact("Card: 4111-1111-1111-1111");
        assert!(!r.redacted_text.contains("4111-1111-1111-1111"));
        assert!(r.categories.contains(&"credit_card".to_string()));
    }

    #[test]
    fn test_card_number_failing_luhn_is_not_a_card() {
        let mut s = RustPiiScanner::new();
        let r = s.redact("order 4111 1111 1111 1112 was cancelled");
        assert!(r.redacted_text.contains("4111 1111 1111 1112"));
        assert_eq!(r.count, 0);
        assert_eq!(s.scan("order 4111 1111 1111 1112").count, 0);
    }

    #[test]
    fn test_phone_numbers_are_redacted() {
        let mut s = RustPiiScanner::new();
        for text in [
            "call 555-123-4567 today",
            "call +1 555-123-4567 today",
            "chiama il 333 1234567",
            "chiama +39 06 1234 5678",
            "ufficio 02/12345678",
        ] {
            let r = s.redact(text);
            assert!(
                r.redacted_text.contains("[PHONE_REDACTED]"),
                "{text}: {}",
                r.redacted_text
            );
        }
    }

    #[test]
    fn test_codes_that_are_not_phone_numbers() {
        let s = RustPiiScanner::new();
        for text in [
            "ISBN 978-3-16-148410-0 is out of print",
            "build 20261008.1 passed all 4554 checks",
            "upgrade to version 2.14.3",
            "id1234567890",
        ] {
            assert_eq!(s.scan(text).count, 0, "{text}");
        }
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
