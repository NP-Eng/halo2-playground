use halo2_playground::MyCircuit;
use halo2_proofs::dev::CircuitLayout;
use plotters::prelude::*;

use halo2curves::pasta::Fp;
fn main() {
    let drawing_area =
        BitMapBackend::new("example-circuit-layout.png", (1024, 768)).into_drawing_area();
    drawing_area.fill(&WHITE).unwrap();
    let drawing_area = drawing_area
        .titled("Example Circuit Layout", ("sans-serif", 60))
        .unwrap();
    let circuit: MyCircuit<Fp> = MyCircuit::default();
    let k = 6; // Suitable size for MyCircuit
    CircuitLayout::default()
        .render(k, &circuit, &drawing_area)
        .unwrap();
}
