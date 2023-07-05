use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem, Error},
};
use halo2curves::ff::Field;

use poseidon::Poseidon;
use poseidon_circuit::{
    hash::{PoseidonHashTable, SpongeChip, SpongeConfig},
    poseidon::{
        primitives::{Absorbing, P128Pow5T3, VariableLengthIden3},
        Pow5Chip, Sponge, Pow5Config,
    },
    Bn256Fr as Fp, DEFAULT_STEP,
};

use rand::rngs::OsRng;

use crate::MyCircuit;

#[test]
fn test_circuit() {
    use halo2_proofs::dev::MockProver;
    use halo2curves::pasta::Fp;
    use rand_core::OsRng;

    // ANCHOR: test-circuit
    // The number of rows in our circuit cannot exceed 2^k. Since our example
    // circuit is very small, we can pick a very small value here.
    let k = 4;

    // Prepare the private and public inputs to the circuit!
    let rng = OsRng;
    let a = Fp::random(rng);
    let b = Fp::random(rng);
    let c = Fp::random(rng);
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
    public_inputs[0] += Fp::one();
    let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
    assert!(prover.verify().is_err());
    // ANCHOR_END: test-circuit
}

#[test]
fn test_poseidon() {
    // test that natively calling a poseidon on some values and then verying the result in the circuit passses

    // TODO what are reasonable parameters?
    // **** poseidon computation outside of circuit
    let n_full_rounds = 20;
    let n_half_rounds = 13;
    let n_inputs = 13;
    const T: usize = 3; // according to the constructor, one should have T = RATE + 1. These values match the hard-coded constants of the poseidon circuit
    const RATE: usize = 2;

    let mut hasher = Poseidon::<Fp, T, RATE>::new(n_full_rounds, n_half_rounds);
    let inputs = (0..n_inputs)
        .map(|_| Fp::random(OsRng))
        .collect::<Vec<Fp>>();

    // absorb inputs
    hasher.update(&inputs[..]);

    // squeeze outputs
    let output = hasher.squeeze();

    println!("inputs: {:?}", inputs);
    println!("output: {:?}", output);

    // **** poseidon computation inside circuit
    struct TestCircuit(PoseidonHashTable<Fp>, usize);

    // test circuit derived from table data
    impl Circuit<Fp> for TestCircuit {
        type Config = SpongeConfig<Fp, Pow5Chip<Fp, 3, 2>>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self(PoseidonHashTable::default(), self.1)
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let hash_tbl = [0; 5].map(|_| meta.advice_column());
            SpongeConfig::configure_sub(meta, hash_tbl, DEFAULT_STEP)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let chip = SpongeChip::<Fp, DEFAULT_STEP, Pow5Chip<Fp, 3, 2>>::construct(
                config,
                &self.0,
                self.1,
                false,
                Some(Fp::from(42u64)),
            );
            chip.load(&mut layouter)
        }
    }

    let k = 7;
    let circuit = TestCircuit(
        PoseidonHashTable {
            inputs,
            ..Default::default()
        },
        3,
    );

    let sponge: Sponge<
        Fp,
        Pow5Chip<Fp, T, RATE>,
        P128Pow5T3<Fp>,
        Absorbing<Fp, RATE>,
        VariableLengthIden3,
        T,
        RATE,
    > = Sponge::new(Pow5Chip::<Fp, T, RATE>::construct(), SingleChipLayouter).unwrap();

    let x: SingleChipLayouter;

    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
