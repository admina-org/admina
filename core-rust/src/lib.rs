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


mod firewall;
mod pii;
mod loop_breaker;
mod forensic;

use pyo3::prelude::*;

/// Returns the version of the Rust core engine.
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Returns engine info for diagnostics.
#[pyfunction]
fn engine_info() -> PyResult<PyObject> {
    Python::with_gil(|py| {
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("engine", "rust")?;
        dict.set_item("version", env!("CARGO_PKG_VERSION"))?;
        dict.set_item("modules", vec!["firewall", "pii", "loop_breaker", "forensic"])?;
        Ok(dict.unbind().into())
    })
}

/// Admina Core Python module.
#[pymodule]
fn admina_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(engine_info, m)?)?;
    m.add_class::<firewall::RustFirewall>()?;
    m.add_class::<firewall::FirewallResult>()?;
    m.add_class::<pii::RustPiiScanner>()?;
    m.add_class::<pii::PiiResult>()?;
    m.add_class::<loop_breaker::RustLoopBreaker>()?;
    m.add_class::<forensic::RustHashChain>()?;
    Ok(())
}
