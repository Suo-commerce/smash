//! Deterministic provider substitute for offline development and conformance tests.

use crate::protocol::{
    decode_response, Planner, PlannerContext, PlannerError, PlannerOutput,
    MAX_PLANNER_RESPONSE_BYTES,
};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;

/// A finite queue of complete provider responses. No hidden default action and
/// no retry occurs when the script is exhausted or malformed.
#[derive(Clone, Debug)]
pub struct ScriptedPlanner {
    responses: VecDeque<Vec<u8>>,
    pub decisions: usize,
}

impl ScriptedPlanner {
    pub fn new(responses: impl IntoIterator<Item = impl Into<Vec<u8>>>) -> Self {
        Self {
            responses: responses.into_iter().map(Into::into).collect(),
            decisions: 0,
        }
    }

    pub fn from_json(responses: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::new(
            responses
                .into_iter()
                .map(|response| response.into().into_bytes()),
        )
    }

    pub fn remaining(&self) -> usize {
        self.responses.len()
    }

    pub fn validate_script(&self) -> Result<(), PlannerError> {
        if self
            .responses
            .iter()
            .any(|response| response.len() > MAX_PLANNER_RESPONSE_BYTES)
        {
            return Err(PlannerError(
                "script contains an oversized response".to_owned(),
            ));
        }
        Ok(())
    }
}

impl Planner for ScriptedPlanner {
    fn next_experiment(
        &mut self,
        context: &PlannerContext<'_>,
    ) -> Result<PlannerOutput, PlannerError> {
        let bytes = self
            .responses
            .pop_front()
            .ok_or_else(|| PlannerError("scripted planner exhausted".to_owned()))?;
        // Hash every complete response exactly once, before interpreting it.
        let digest = Sha256::digest(&bytes);
        let response_sha256 = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        let action = decode_response(&bytes, context)?;
        self.decisions += 1;
        Ok(PlannerOutput {
            action,
            response_sha256,
        })
    }
}
