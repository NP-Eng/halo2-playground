use halo2_proofs::{circuit::Value, dev::MockProver};
use halo2curves::ff::Field;
use poseidon::Poseidon;
use rand_core::OsRng;

use halo2_proofs::halo2curves::bn256::Fr;

use crate::MyCircuit;

#[test]
fn test_circuit() {
    // ANCHOR: test-circuit
    // The number of rows in our circuit cannot exceed 2^k. Since our example
    // circuit is very small, we can pick a very small value here.
    let k = 6;

    // Prepare the private and public inputs to the circuit!
    let rng = OsRng;
    let a = Fr::random(rng);
    let b = Fr::random(rng);
    let c = Fr::random(rng);
    let d = (a + b) * c;

    // Instantiate the circuit with the private inputs.
    let circuit = MyCircuit {
        a: Value::known(a),
        b: Value::known(b),
        c: Value::known(c),
    };

    // Arrange the public input. We expose the multiplication result in row 0
    // of the instance column, so we position it there in our public inputs.
    let mut public_inputs = vec![d];

    // Given the correct public input, our circuit will verify.
    let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    // If we try some other public input, the proof will fail!
    public_inputs[0] += Fr::one();
    let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
    assert!(prover.verify().is_err());
    // ANCHOR_END: test-circuit
}

#[test]
fn test_poseidon() {
    // Prepare the private and public inputs to the circuit
    let rng = OsRng;
    let a = Fr::random(rng);
    let b = Fr::random(rng);
    let c = Fr::random(rng);
    let d = (a + b) * c;

    // **** out-circuit poseidon computation
    let n_full_rounds = 8;
    let n_half_rounds = 56;
    const T: usize = 3;
    const RATE: usize = 2;

    let mut hasher = Poseidon::<Fr, T, RATE>::new(n_full_rounds, n_half_rounds);
    // absorb inputs
    hasher.update(&[d]);

    // squeeze outputs
    let output = hasher.squeeze();

    println!("OUT ABSORBING {d:?}");
    println!("OUT SQUEEZING {output:?}");

    // **** in-circuit poseidon computation

    // The number of rows in our circuit cannot exceed 2^k. Since our example
    // circuit is very small, we can pick a very small value here.
    let k = 6;

    // Instantiate the circuit with the private inputs.
    let circuit = MyCircuit {
        a: Value::known(a),
        b: Value::known(b),
        c: Value::known(c),
    };

    // Arrange the public input. We expose the multiplication result in row 0
    // of the instance column, so we position it there in our public inputs.
    let public_inputs = vec![output];

    // Given the correct public input, our circuit will verify.
    let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    /*     // If we try some other public input, the proof will fail!
    public_inputs[0] += Fp::one();
    let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
    assert!(prover.verify().is_err()); */
}
