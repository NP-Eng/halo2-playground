use halo2_proofs::circuit::Value;
use halo2curves::ff::Field;

use crate::MyCircuit;

#[test]
fn test_circuit() {
    use halo2_proofs::dev::MockProver;
    use halo2curves::pasta::Fp;
    use rand_core::OsRng;

    // ANCHOR: test-circuit
    // The number of rows in our circuit cannot exceed 2^k. Since our example
    // circuit is very small, we can pick a very small value here.
    let k = 6;

    // Prepare the private and public inputs to the circuit!
    let rng = OsRng;
    let a = Fp::random(rng);
    let b = Fp::random(rng);
    let c = a + b;

    // Instantiate the circuit with the private inputs.
    let circuit = MyCircuit {
        a: Value::known(a),
        b: Value::known(b),
    };

    // Arrange the public input. We expose the multiplication result in row 0
    // of the instance column, so we position it there in our public inputs.
    let mut public_inputs = vec![c];

    // Given the correct public input, our circuit will verify.
    let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    // If we try some other public input, the proof will fail!
    public_inputs[0] += Fp::one();
    let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
    assert!(prover.verify().is_err());
    // ANCHOR_END: test-circuit
}

#[test]
fn test_poseidon() {
    // TODO
    // test that natively calling a poseidon on some values and then verying the result in the circuit passses
    assert!(true);
}
