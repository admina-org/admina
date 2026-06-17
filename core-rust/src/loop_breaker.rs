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
use std::collections::HashMap;

/// Simple term-frequency vector for cosine similarity.
fn term_frequencies(text: &str) -> HashMap<String, f64> {
    let mut tf: HashMap<String, f64> = HashMap::new();
    let words: Vec<String> = text
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() > 1)
        .map(|w| w.to_string())
        .collect();

    let n = words.len() as f64;
    if n == 0.0 {
        return tf;
    }

    for word in &words {
        *tf.entry(word.clone()).or_insert(0.0) += 1.0;
    }

    // Normalize to TF
    for val in tf.values_mut() {
        *val /= n;
    }
    tf
}

/// Cosine similarity between two term-frequency vectors.
fn cosine_similarity(a: &HashMap<String, f64>, b: &HashMap<String, f64>) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }

    let mut dot = 0.0_f64;
    let mut norm_a = 0.0_f64;
    let mut norm_b = 0.0_f64;

    // Iterate over all keys in both maps
    for (key, val_a) in a.iter() {
        norm_a += val_a * val_a;
        if let Some(val_b) = b.get(key) {
            dot += val_a * val_b;
        }
    }
    for val_b in b.values() {
        norm_b += val_b * val_b;
    }

    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom == 0.0 {
        0.0
    } else {
        dot / denom
    }
}

/// Per-session window state.
struct SessionWindow {
    vectors: Vec<HashMap<String, f64>>,
    consecutive_similar: u32,
}

/// Loop detection via TF-IDF cosine similarity on sliding window.
#[pyclass]
pub struct RustLoopBreaker {
    sessions: HashMap<String, SessionWindow>,
    window_size: usize,
    similarity_threshold: f64,
    max_consecutive: u32,
    total_checks: u64,
    loops_detected: u64,
}

#[pymethods]
impl RustLoopBreaker {
    #[new]
    #[pyo3(signature = (window_size=10, similarity_threshold=0.85, max_consecutive=3))]
    fn new(window_size: usize, similarity_threshold: f64, max_consecutive: u32) -> Self {
        RustLoopBreaker {
            sessions: HashMap::new(),
            window_size,
            similarity_threshold,
            max_consecutive,
            total_checks: 0,
            loops_detected: 0,
        }
    }

    /// Check if a request is part of a reasoning loop.
    /// Returns dict with is_loop, similarity, consecutive_count.
    fn check(&mut self, session_id: &str, content: &str) -> PyResult<Py<PyAny>> {
        self.total_checks += 1;
        let tf = term_frequencies(content);

        let session = self.sessions
            .entry(session_id.to_string())
            .or_insert_with(|| SessionWindow {
                vectors: Vec::new(),
                consecutive_similar: 0,
            });

        // Compute max similarity against window
        let mut max_sim = 0.0_f64;
        for prev in session.vectors.iter() {
            let sim = cosine_similarity(&tf, prev);
            if sim > max_sim {
                max_sim = sim;
            }
        }

        // Track consecutive similar requests
        if max_sim >= self.similarity_threshold {
            session.consecutive_similar += 1;
        } else {
            session.consecutive_similar = 0;
        }

        let is_loop = session.consecutive_similar >= self.max_consecutive;
        let consecutive = session.consecutive_similar;

        if is_loop {
            self.loops_detected += 1;
        }

        // Add to sliding window
        session.vectors.push(tf);
        if session.vectors.len() > self.window_size {
            session.vectors.remove(0);
        }

        Python::attach(|py| {
            let dict = pyo3::types::PyDict::new(py);
            dict.set_item("is_loop", is_loop)?;
            dict.set_item("similarity", max_sim)?;
            dict.set_item("consecutive_similar", consecutive)?;
            dict.set_item("window_size", session.vectors.len())?;
            dict.set_item("engine", "rust")?;
            Ok(dict.unbind().into())
        })
    }

    /// Reset a session's window.
    fn reset_session(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    fn get_stats(&self) -> PyResult<Py<PyAny>> {
        Python::attach(|py| {
            let dict = pyo3::types::PyDict::new(py);
            dict.set_item("total_checks", self.total_checks)?;
            dict.set_item("loops_detected", self.loops_detected)?;
            dict.set_item("active_sessions", self.sessions.len())?;
            dict.set_item("window_size", self.window_size)?;
            dict.set_item("similarity_threshold", self.similarity_threshold)?;
            dict.set_item("engine", "rust")?;
            Ok(dict.unbind().into())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cosine_identical() {
        let a = term_frequencies("hello world test");
        let b = term_frequencies("hello world test");
        let sim = cosine_similarity(&a, &b);
        assert!((sim - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_cosine_different() {
        let a = term_frequencies("hello world");
        let b = term_frequencies("completely different sentence here");
        let sim = cosine_similarity(&a, &b);
        assert!(sim < 0.3);
    }

    #[test]
    fn test_loop_detection() {
        let _lb = RustLoopBreaker::new(10, 0.85, 3);
        // Can't test check() without Python, but test internals
        let tf1 = term_frequencies("get stock price AAPL");
        let tf2 = term_frequencies("get stock price AAPL");
        assert!((cosine_similarity(&tf1, &tf2) - 1.0).abs() < 0.001);
    }
}
