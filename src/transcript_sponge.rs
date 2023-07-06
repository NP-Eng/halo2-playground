use std::{marker::PhantomData, fmt, iter};

use halo2_proofs::{circuit::{Layouter, AssignedCell}, plonk::Error};
use halo2curves::ff::FromUniformBytes;
use poseidon_circuit::poseidon::{primitives::{Spec, Domain}, PoseidonSpongeInstructions, PaddedWord};

pub trait TranscriptSpongeMode {}

/// The type used to hold permutation state.
pub(crate) type State<F, const T: usize> = [F; T];

/// The type used to hold sponge rate.
pub(crate) type TranscriptSpongeRate<F, const RATE: usize> = [Option<F>; RATE];

/// The absorbing state of the `TranscriptSponge`.
#[derive(Debug)]
pub struct TranscriptAbsorbing<F, const RATE: usize>(pub(crate) TranscriptSpongeRate<F, RATE>);
impl<F, const RATE: usize> TranscriptSpongeMode for TranscriptAbsorbing<F, RATE> {}

/// The squeezing state of the `TranscriptSponge`.
#[derive(Debug)]
pub struct TranscriptSqueezing<F, const RATE: usize>(pub(crate) TranscriptSpongeRate<F, RATE>);
impl<F, const RATE: usize> TranscriptSpongeMode for TranscriptSqueezing<F, RATE> {}

impl<F: fmt::Debug, const RATE: usize> TranscriptAbsorbing<F, RATE> {
    pub(crate) fn init_with(val: F) -> Self {
        Self(
            iter::once(Some(val))
                .chain((1..RATE).map(|_| None))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }
}

fn poseidon_sponge<
    F: FromUniformBytes<64> + Ord,
    PoseidonChip: PoseidonSpongeInstructions<F, S, D, T, RATE>,
    S: Spec<F, T, RATE>,
    D: Domain<F, RATE>,
    const T: usize,
    const RATE: usize,
>(
    chip: &PoseidonChip,
    mut layouter: impl Layouter<F>,
    state: &mut State<PoseidonChip::Word, T>,
    input: Option<&TranscriptAbsorbing<PaddedWord<F>, RATE>>,
) -> Result<TranscriptSqueezing<PoseidonChip::Word, RATE>, Error> {
    if let Some(input) = input {
        *state = chip.add_input(&mut layouter, state, input)?;
    }
    *state = chip.permute(&mut layouter, state)?;
    Ok(PoseidonChip::get_output(state))
}

/// A Poseidon sponge.
#[derive(Debug)]
pub struct Sponge<
    F: FromUniformBytes<64> + Ord,
    PoseidonChip: PoseidonSpongeInstructions<F, S, D, T, RATE>,
    S: Spec<F, T, RATE>,
    M: TranscriptSpongeMode,
    D: Domain<F, RATE>,
    const T: usize,
    const RATE: usize,
> {
    chip: PoseidonChip,
    mode: M,
    state: State<PoseidonChip::Word, T>,
    _marker: PhantomData<D>,
}

impl<
        F: FromUniformBytes<64> + Ord,
        PoseidonChip: PoseidonSpongeInstructions<F, S, D, T, RATE>,
        S: Spec<F, T, RATE>,
        D: Domain<F, RATE>,
        const T: usize,
        const RATE: usize,
    > Sponge<F, PoseidonChip, S, TranscriptAbsorbing<PaddedWord<F>, RATE>, D, T, RATE>
{
    /// Constructs a new duplex sponge for the given Poseidon specification.
    pub fn new(chip: PoseidonChip, mut layouter: impl Layouter<F>) -> Result<Self, Error> {
        chip.initial_state(&mut layouter).map(|state| Sponge {
            chip,
            mode: TranscriptAbsorbing(
                (0..RATE)
                    .map(|_| None)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            ),
            state,
            _marker: PhantomData::default(),
        })
    }

    /// Absorbs an element into the sponge.
    pub fn absorb(
        &mut self,
        mut layouter: impl Layouter<F>,
        value: PaddedWord<F>,
    ) -> Result<(), Error> {
        for entry in self.mode.0.iter_mut() {
            if entry.is_none() {
                *entry = Some(value);
                return Ok(());
            }
        }

        // We've already absorbed as many elements as we can
        let _ = poseidon_sponge(
            &self.chip,
            layouter.namespace(|| "PoseidonSponge"),
            &mut self.state,
            Some(&self.mode),
        )?;
        self.mode = TranscriptAbsorbing::init_with(value);

        Ok(())
    }

    /// Transitions the sponge into its squeezing state.
    #[allow(clippy::type_complexity)]
    pub fn finish_absorbing(
        mut self,
        mut layouter: impl Layouter<F>,
    ) -> Result<Sponge<F, PoseidonChip, S, TranscriptSqueezing<PoseidonChip::Word, RATE>, D, T, RATE>, Error>
    {
        let mode = poseidon_sponge(
            &self.chip,
            layouter.namespace(|| "PoseidonSponge"),
            &mut self.state,
            Some(&self.mode),
        )?;

        Ok(Sponge {
            chip: self.chip,
            mode,
            state: self.state,
            _marker: PhantomData::default(),
        })
    }
}

impl<
        F: FromUniformBytes<64> + Ord,
        PoseidonChip: PoseidonSpongeInstructions<F, S, D, T, RATE>,
        S: Spec<F, T, RATE>,
        D: Domain<F, RATE>,
        const T: usize,
        const RATE: usize,
    > Sponge<F, PoseidonChip, S, TranscriptSqueezing<PoseidonChip::Word, RATE>, D, T, RATE>
{
    /// Squeezes an element from the sponge.
    pub fn squeeze(&mut self, mut layouter: impl Layouter<F>) -> Result<AssignedCell<F, F>, Error> {
        loop {
            for entry in self.mode.0.iter_mut() {
                if let Some(inner) = entry.take() {
                    return Ok(inner.into());
                }
            }

            // We've already squeezed out all available elements
            self.mode = poseidon_sponge(
                &self.chip,
                layouter.namespace(|| "PoseidonSponge"),
                &mut self.state,
                None,
            )?;
        }
    }
}
