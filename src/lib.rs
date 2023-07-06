use std::marker::PhantomData;

use halo2_gadgets::poseidon::{
    primitives::{Absorbing, ConstantLength, Domain, P128Pow5T3, Spec, Squeezing},
    PaddedWord, Pow5Chip, Pow5Config, Sponge,
};
use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};
use halo2curves::pasta::Fp;
// TODO import poseidon types

#[cfg(test)]
mod tests;

// needed for the poseidon config?
// const T: usize = 3;
// const RATE: usize = 3;
// const WIDTH: usize = 3;
// const R_F: usize = 8;
// const R_P: usize = 57;

/// A variable representing a number.
#[derive(Clone)]
struct Number<Fp: Field>(AssignedCell<Fp, Fp>);

// The top-level config that provides all necessary columns and permutations
// for the other configs.
#[derive(Clone, Debug)]
pub struct FieldConfig<Fp: Field, const WIDTH: usize, const RATE: usize> {
    /// For this chip, we will use two advice columns to implement our instructions.
    /// These are also the columns through which we communicate with other parts of
    /// the circuit.
    advice: [Column<Advice>; WIDTH],

    /// Public inputs
    instance: Column<Instance>,

    add_config: AddConfig,
    mul_config: MulConfig,
    sponge_config: Pow5Config<Fp, WIDTH, RATE>,
    // TODO add a poseidon config
    _marker: PhantomData<Fp>,
}

#[derive(Clone, Debug)]
struct AddConfig {
    advice: [Column<Advice>; 2],
    s_add: Selector,
}

#[derive(Clone, Debug)]
struct MulConfig {
    advice: [Column<Advice>; 2],
    s_mul: Selector,
}

/// The top-level chip that will implement the `FieldInstructions`.
struct FieldChip<Fp: Field, const WIDTH: usize, const RATE: usize> {
    config: FieldConfig<Fp, WIDTH, RATE>,
    _marker: PhantomData<Fp>,
}

struct AddChip<Fp: Field> {
    config: AddConfig,
    _marker: PhantomData<Fp>,
}

struct MulChip<Fp: Field> {
    config: MulConfig,
    _marker: PhantomData<Fp>,
}

impl<Fp: Field> Chip<Fp> for AddChip<Fp> {
    type Config = AddConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<Fp: Field> AddChip<Fp> {
    fn construct(config: <Self as Chip<Fp>>::Config, _loaded: <Self as Chip<Fp>>::Loaded) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        advice: [Column<Advice>; 2],
    ) -> <Self as Chip<Fp>>::Config {
        let s_add = meta.selector();

        // Define our addition gate!
        meta.create_gate("add", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let s_add = meta.query_selector(s_add);

            vec![s_add * (lhs + rhs - out)]
        });

        AddConfig { advice, s_add }
    }
}

impl<Fp: Field, const WIDTH: usize, const RATE: usize> FieldChip<Fp, WIDTH, RATE> {
    fn add(
        &self,
        layouter: impl Layouter<Fp>,
        a: Number<Fp>,
        b: Number<Fp>,
    ) -> Result<Number<Fp>, Error> {
        let config = self.config().add_config.clone();

        let add_chip = AddChip::<Fp>::construct(config, ());
        add_chip.add(layouter, a, b)
    }
}

impl<Fp: Field> AddChip<Fp> {
    fn add(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: Number<Fp>,
        b: Number<Fp>,
    ) -> Result<Number<Fp>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "add",
            |mut region: Region<'_, Fp>| {
                // We only want to use a single addition gate in this region,
                // so we enable it at region offset 0; this means it will constrain
                // cells at offsets 0 and 1.
                config.s_add.enable(&mut region, 0)?;

                // The inputs we've been given could be located anywhere in the circuit,
                // but we can only rely on relative offsets inside this region. So we
                // assign new cells inside the region and constrain them to have the
                // same values as the inputs.
                a.0.copy_advice(|| "lhs", &mut region, config.advice[0], 0)?;
                b.0.copy_advice(|| "rhs", &mut region, config.advice[1], 0)?;

                // Now we can compute the addition result, which is to be assigned
                // into the output position.
                let value = a.0.value().copied() + b.0.value();

                // Finally, we do the assignment to the output, returning a
                // variable to be used in another part of the circuit.
                region
                    .assign_advice(|| "lhs + rhs", config.advice[0], 1, || value)
                    .map(Number)
            },
        )
    }
}

impl<Fp: Field> Chip<Fp> for MulChip<Fp> {
    type Config = MulConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<Fp: Field> MulChip<Fp> {
    fn construct(config: <Self as Chip<Fp>>::Config, _loaded: <Self as Chip<Fp>>::Loaded) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        advice: [Column<Advice>; 2],
    ) -> <Self as Chip<Fp>>::Config {
        for column in &advice {
            meta.enable_equality(*column);
        }
        let s_mul = meta.selector();

        // Define our multiplication gate!
        meta.create_gate("mul", |meta| {
            // To implement multiplication, we need three advice cells and a selector
            // cell. We arrange them like so:
            //
            // | a0  | a1  | s_mul |
            // |-----|-----|-------|
            // | lhs | rhs | s_mul |
            // | out |     |       |
            //
            // Gates may refer to any relative offsets we want, but each distinct
            // offset adds a cost to the proof. The most common offsets are 0 (the
            // current row), 1 (the next row), and -1 (the previous row), for which
            // `Rotation` has specific constructors.
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let s_mul = meta.query_selector(s_mul);

            // The polynomial expression returned from `create_gate` will be
            // constrained by the proving system to equal zero. Our expression
            // has the following properties:
            // - When s_mul = 0, any value is allowed in lhs, rhs, and out.
            // - When s_mul != 0, this constrains lhs * rhs = out.
            vec![s_mul * (lhs * rhs - out)]
        });

        MulConfig { advice, s_mul }
    }
}

impl FieldChip<Fp, WIDTH, RATE> {
    fn mul(
        &self,
        layouter: impl Layouter<Fp>,
        a: Number<Fp>,
        b: Number<Fp>,
    ) -> Result<Number<Fp>, Error> {
        let config = self.config().mul_config.clone();
        let mul_chip = MulChip::<Fp>::construct(config, ());
        mul_chip.mul(layouter, a, b)
    }
}

impl<Fp: Field> MulChip<Fp> {
    fn mul(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: Number<Fp>,
        b: Number<Fp>,
    ) -> Result<Number<Fp>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "mul",
            |mut region: Region<'_, Fp>| {
                // We only want to use a single multiplication gate in this region,
                // so we enable it at region offset 0; this means it will constrain
                // cells at offsets 0 and 1.
                config.s_mul.enable(&mut region, 0)?;

                // The inputs we've been given could be located anywhere in the circuit,
                // but we can only rely on relative offsets inside this region. So we
                // assign new cells inside the region and constrain them to have the
                // same values as the inputs.
                a.0.copy_advice(|| "lhs", &mut region, config.advice[0], 0)?;
                b.0.copy_advice(|| "rhs", &mut region, config.advice[1], 0)?;

                // Now we can compute the multiplication result, which is to be assigned
                // into the output position.
                let value = a.0.value().copied() * b.0.value();

                // Finally, we do the assignment to the output, returning a
                // variable to be used in another part of the circuit.
                region
                    .assign_advice(|| "lhs * rhs", config.advice[0], 1, || value)
                    .map(Number)
            },
        )
    }
}

impl<Fp: Field, const WIDTH: usize, const RATE: usize> Chip<Fp> for FieldChip<Fp, WIDTH, RATE> {
    type Config = FieldConfig<Fp, WIDTH, RATE>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl FieldChip<Fp, WIDTH, RATE> {
    fn construct(config: <Self as Chip<Fp>>::Config, _loaded: <Self as Chip<Fp>>::Loaded) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        advice: [Column<Advice>; WIDTH],
        instance: Column<Instance>,
        rc_a: [Column<Fixed>; WIDTH],
        rc_b: [Column<Fixed>; WIDTH],
    ) -> <Self as Chip<Fp>>::Config {
        let add_mul_advice = [advice[0], advice[1]];

        let add_config = AddChip::configure(meta, add_mul_advice);
        let mul_config = MulChip::configure(meta, add_mul_advice);

        let partial_sbox = meta.advice_column();

        let poseidon_config = Pow5Chip::configure::<P128Pow5T3>(
            meta,
            advice.try_into().unwrap(),
            partial_sbox,
            rc_a,
            rc_b,
        );

        meta.enable_equality(instance);

        FieldConfig::<Fp, WIDTH, RATE> {
            advice,
            instance,
            add_config,
            mul_config,
            sponge_config: poseidon_config,
            _marker: PhantomData,
        }
    }
}

impl FieldChip<Fp, WIDTH, RATE> {
    fn load_private(
        &self,
        mut layouter: impl Layouter<Fp>,
        value: Value<Fp>,
    ) -> Result<Number<Fp>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "load private",
            |mut region| {
                region
                    .assign_advice(|| "private input", config.advice[0], 0, || value)
                    .map(Number)
            },
        )
    }

    /// Returns `d = (a + b) * c`.
    fn add_and_mul(
        &self,
        layouter: &mut impl Layouter<Fp>,
        a: Number<Fp>,
        b: Number<Fp>,
        c: Number<Fp>,
    ) -> Result<Number<Fp>, Error> {
        let ab = self.add(layouter.namespace(|| "a + b"), a, b)?;
        self.mul(layouter.namespace(|| "(a + b) * c"), ab, c)
    }

    // fn get_fiat_shamir_challenge(
    //     &self,
    //     layouter: &mut impl Layouter<Fp>,
    //     input: Number<Fp>,
    // ) -> Result<Fp, Error> {
    //     self.squeeze(layouter.namespace(|| "get_fiat_shamir_challenge"), input)
    // }

    fn expose_public(
        &self,
        mut layouter: impl Layouter<Fp>,
        num: Number<Fp>,
        row: usize,
    ) -> Result<(), Error> {
        let config = self.config();

        layouter.constrain_instance(num.0.cell(), config.instance, row)
    }
}

/// The full circuit implementation.
///
/// In this struct we store the private input variables. We use `Value<Fp>` because
/// they won't have any value during key generation. During proving, if any of these
/// were `Value::unknown()` we would get an error.
#[derive(Default)]
pub struct MyCircuit<Fp: Field> {
    a: Value<Fp>,
    b: Value<Fp>,
    c: Value<Fp>,
    // _marker: PhantomData<WIDTH>//: usize, RATE)>,
}

const WIDTH: usize = 3;
const RATE: usize = 2;
const L: usize = 1;

impl Circuit<Fp> for MyCircuit<Fp> {
    // Since we are using a single chip for everything, we can just reuse its config.
    type Config = FieldConfig<Fp, WIDTH, RATE>;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        // We create the two advice columns that FieldChip uses for I/O.
        let advice = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        // let advice = [meta.advice_column(), meta.advice_column()];

        // We also need an instance column to store public inputs.
        let instance = meta.instance_column();

        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        meta.enable_constant(rc_b[0]);

        FieldChip::<Fp, WIDTH, RATE>::configure(
            meta,
            advice.try_into().unwrap(),
            instance,
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let field_chip = FieldChip::<Fp, WIDTH, RATE>::construct(config.clone(), ());
        let config = config.sponge_config;
        let poseidon_chip = Pow5Chip::<Fp, WIDTH, RATE>::construct(config);
        let mut sponge: Sponge<
            Fp,
            Pow5Chip<Fp, WIDTH, RATE>,
            P128Pow5T3,
            Absorbing<halo2_gadgets::poseidon::PaddedWord<Fp>, RATE>,
            ConstantLength<L>,
            WIDTH,
            RATE,
        > = Sponge::new(poseidon_chip, layouter.namespace(|| "new sponge"))?;

        // Load our private values into the circuit.
        let a = field_chip.load_private(layouter.namespace(|| "load a"), self.a)?;
        let b = field_chip.load_private(layouter.namespace(|| "load b"), self.b)?;
        let c = field_chip.load_private(layouter.namespace(|| "load c"), self.c)?;

        // Use `add_and_mul` to get `d = (a + b) * c`.
        let d = field_chip.add_and_mul(&mut layouter, a, b, c)?;

        // We need to pad to the multiple of RATE
        let message = [d.0.clone()];
        for (i, value) in message
            .into_iter()
            .map(PaddedWord::Message)
            .chain(<ConstantLength<L> as Domain<Fp, RATE>>::padding(L).map(PaddedWord::Padding))
            .enumerate()
        {
            sponge.absorb(layouter.namespace(|| format!("absorb_{i}")), value)?;
        }

        // TODO figure out how to tackle multiple absorb-squeeze cycles, since current sponge requires calling `finish_absorbing`.
        let mut sponge = sponge.finish_absorbing(layouter.namespace(|| "finish absorbing"))?;
        let r = sponge.squeeze(layouter.namespace(|| "squeeze"))?;

        // Expose the result as a public input to the circuit.
        // TODO do something about the randomness r
        field_chip.expose_public(layouter.namespace(|| "expose d"), d, 0)
    }
}
