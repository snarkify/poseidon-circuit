use ff::{FromUniformBytes, PrimeField};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
};
use poseidon::Spec;

use crate::{
    main_gate::{MainGate, MainGateConfig, RegionCtx},
    poseidon_circuit::PoseidonChip,
};

const T: usize = 4;
const RATE: usize = 3;
const R_F: usize = 8;
const R_P: usize = 56;

#[derive(Clone, Debug)]
pub struct TestCircuitConfig {
    pconfig: MainGateConfig<T>,
    instance: Column<Instance>,
}

pub struct TestCircuit<F: PrimeField> {
    inputs: Vec<F>,
}

impl<F: PrimeField> TestCircuit<F> {
    pub fn new(inputs: Vec<F>) -> Self {
        Self { inputs }
    }
}

impl<F: PrimeField + FromUniformBytes<64>> Circuit<F> for TestCircuit<F> {
    type Config = TestCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { inputs: Vec::new() }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        let mut adv_cols = [(); T + 2].map(|_| meta.advice_column()).into_iter();
        let mut fix_cols = [(); 2 * T + 4].map(|_| meta.fixed_column()).into_iter();
        let pconfig = MainGate::configure(meta, &mut adv_cols, &mut fix_cols);
        Self::Config { pconfig, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let spec = Spec::<F, T, RATE>::new(R_F, R_P);
        let mut pchip = PoseidonChip::new(config.pconfig, spec);
        pchip.update(self.inputs.clone());
        let output = layouter.assign_region(
            || "poseidon hash",
            |region| {
                let ctx = &mut RegionCtx::new(region, 0);
                pchip.squeeze(ctx)
            },
        )?;
        layouter.constrain_instance(output.cell(), config.instance, 0)?;
        Ok(())
    }
}
