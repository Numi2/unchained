use proof_core::validate_shielded_tx_witness;
use risc0_zkvm::guest::env;

fn main() {
    let witness: proof_core::ProofShieldedTxWitness = env::read();
    let journal = validate_shielded_tx_witness(&witness).expect("invalid shielded spend witness");
    env::commit(&journal);
}
