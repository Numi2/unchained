use proof_core::validate_private_undelegation_witness;
use risc0_zkvm::{guest::env, serde::to_vec};

fn main() {
    let witness: proof_core::ProofPrivateUndelegationWitness = env::read();
    for input in &witness.shielded.inputs {
        if let Some(accumulator) = input.historical_accumulator.as_ref() {
            let verifier_hint = input
                .historical_accumulator_verifier_hint
                .expect("missing historical accumulator verifier hint");
            let journal = to_vec(accumulator).expect("serialize checkpoint accumulator journal");
            env::verify(verifier_hint, journal.as_slice())
                .expect("invalid checkpoint accumulator receipt");
        }
    }
    let journal =
        validate_private_undelegation_witness(&witness).expect("invalid private undelegation witness");
    env::commit(&journal);
}
