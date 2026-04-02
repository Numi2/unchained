use proof_core::validate_checkpoint_accumulator_step_witness;
use risc0_zkvm::{guest::env, serde::to_vec};

fn main() {
    let witness: proof_core::CheckpointAccumulatorStepWitness = env::read();
    if let Some(prior) = witness.prior_accumulator.as_ref() {
        let journal = to_vec(prior).expect("serialize prior checkpoint accumulator journal");
        env::verify(witness.accumulator_image_id, journal.as_slice())
            .expect("invalid prior checkpoint accumulator receipt");
    }
    let journal =
        validate_checkpoint_accumulator_step_witness(&witness).expect("invalid accumulator step");
    env::commit(&journal);
}
