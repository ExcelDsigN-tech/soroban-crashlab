use crate::CaseBundle;
use serde::{Deserialize, Serialize};

/// Normalized JSON scenario for cross-tool reuse.
///
/// Contains all information needed to reproduce a failing test case,
/// including the seed ID, input payload, execution mode, and expected failure class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureScenario {
    /// Unique identifier for the seed that produced this failure.
    pub seed_id: u64,

    /// Input payload as a hex-encoded string for JSON compatibility.
    pub input_payload: String,

    /// Execution mode or context (e.g., "invoker", "contract", "none").
    pub mode: String,

    /// Expected failure classification (e.g., "runtime-failure", "empty-input").
    pub failure_class: String,
}

impl FailureScenario {
    /// Creates a new scenario from a bundle with the specified mode.
    ///
    /// # Arguments
    ///
    /// * `bundle` - The case bundle containing seed and signature information
    /// * `mode` - The execution mode or context string
    pub fn from_bundle(bundle: &CaseBundle, mode: impl Into<String>) -> Self {
        Self {
            seed_id: bundle.seed.id,
            input_payload: hex::encode(&bundle.seed.payload),
            mode: mode.into(),
            failure_class: bundle.signature.category.clone(),
        }
    }
}

/// Exports a failure scenario as a JSON string.
///
/// # Arguments
///
/// * `bundle` - The case bundle to export
/// * `mode` - The execution mode or context
///
/// # Returns
///
/// A JSON string representation of the failure scenario, or an error if serialization fails.
///
/// This exports the raw bundle payload. For public sharing, prefer
/// [`crate::export_sanitized_scenario_json`] so secret-like fragments are
/// scrubbed before the payload is hex-encoded into JSON.
///
/// # Example
///
/// ```rust
/// use crashlab_core::{to_bundle, CaseSeed};
/// use crashlab_core::scenario_export::export_scenario_json;
///
/// let bundle = to_bundle(CaseSeed { id: 42, payload: vec![1, 2, 3] });
/// let json = export_scenario_json(&bundle, "invoker").unwrap();
/// assert!(json.contains("\"seed_id\": 42"));
/// ```
pub fn export_scenario_json(
    bundle: &CaseBundle,
    mode: impl Into<String>,
) -> Result<String, serde_json::Error> {
    let scenario = FailureScenario::from_bundle(bundle, mode);
    serde_json::to_string_pretty(&scenario)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CaseSeed, to_bundle};

    #[test]
    fn scenario_contains_all_required_fields() {
        let bundle = to_bundle(CaseSeed {
            id: 123,
            payload: vec![0xAA, 0xBB, 0xCC],
        });

        let scenario = FailureScenario::from_bundle(&bundle, "invoker");

        assert_eq!(scenario.seed_id, 123);
        assert!(!scenario.input_payload.is_empty());
        assert_eq!(scenario.mode, "invoker");
        assert!(!scenario.failure_class.is_empty());
    }

    #[test]
    fn payload_is_hex_encoded() {
        let bundle = to_bundle(CaseSeed {
            id: 1,
            payload: vec![0x01, 0x02, 0x03],
        });

        let scenario = FailureScenario::from_bundle(&bundle, "contract");

        // After mutation, payload will be different, but should still be valid hex
        assert!(
            scenario
                .input_payload
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        );
        assert_eq!(scenario.input_payload.len() % 2, 0); // Even length for hex
    }

    #[test]
    fn export_json_produces_valid_json() {
        let bundle = to_bundle(CaseSeed {
            id: 42,
            payload: vec![1, 2, 3, 4],
        });

        let json = export_scenario_json(&bundle, "none").unwrap();

        // Verify it's valid JSON by parsing it back
        let parsed: FailureScenario = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.seed_id, 42);
        assert_eq!(parsed.mode, "none");
    }

    #[test]
    fn json_contains_all_fields() {
        let bundle = to_bundle(CaseSeed {
            id: 999,
            payload: vec![0xFF],
        });

        let json = export_scenario_json(&bundle, "invoker").unwrap();

        assert!(json.contains("\"seed_id\""));
        assert!(json.contains("\"input_payload\""));
        assert!(json.contains("\"mode\""));
        assert!(json.contains("\"failure_class\""));
        assert!(json.contains("999"));
        assert!(json.contains("invoker"));
    }

    #[test]
    fn empty_payload_exports_successfully() {
        let bundle = to_bundle(CaseSeed {
            id: 7,
            payload: vec![],
        });

        let scenario = FailureScenario::from_bundle(&bundle, "contract");

        assert_eq!(scenario.seed_id, 7);
        assert_eq!(scenario.input_payload, ""); // Empty hex string
        assert_eq!(scenario.failure_class, "empty-input");
    }

    #[test]
    fn different_modes_are_preserved() {
        let bundle = to_bundle(CaseSeed {
            id: 1,
            payload: vec![1],
        });

        let scenario_invoker = FailureScenario::from_bundle(&bundle, "invoker");
        let scenario_contract = FailureScenario::from_bundle(&bundle, "contract");
        let scenario_none = FailureScenario::from_bundle(&bundle, "none");

        assert_eq!(scenario_invoker.mode, "invoker");
        assert_eq!(scenario_contract.mode, "contract");
        assert_eq!(scenario_none.mode, "none");
    }

    #[test]
    fn failure_class_matches_bundle_signature() {
        let bundle = to_bundle(CaseSeed {
            id: 50,
            payload: vec![1; 100], // Oversized
        });

        let scenario = FailureScenario::from_bundle(&bundle, "invoker");

        assert_eq!(scenario.failure_class, bundle.signature.category);
    }
}
