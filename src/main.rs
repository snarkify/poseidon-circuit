use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::poly::ipa::commitment::{IPACommitmentScheme, ParamsIPA};
use halo2_proofs::poly::ipa::multiopen::ProverIPA;
use halo2_proofs::poly::{VerificationStrategy, ipa::strategy::SingleStrategy};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer};
use halo2_proofs::plonk::{ConstraintSystem, Column, Circuit, Instance, create_proof, keygen_pk, keygen_vk, verify_proof, Error};
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner};
use halo2curves::pasta::{vesta, EqAffine, Fp};
use ff::{PrimeField, FromUniformBytes};
use rand_core::OsRng;
use poseidon::Spec;

use crate::main_gate::{MainGate, MainGateConfig, RegionCtx};
use crate::poseidon_circuit::PoseidonChip;

pub mod poseidon_hash;
pub mod poseidon_circuit;
pub mod main_gate;

/// A helper trait that defines the constants associated with a hash function
pub trait ROConstantsTrait {
  /// produces constants/parameters associated with the hash function
  fn new(r_f: usize, r_p: usize) -> Self;
}

pub trait ROTrait<C: CurveAffine> {
  /// A type representing constants/parameters associated with the hash function
  type Constants: ROConstantsTrait;

  /// Initializes the hash function
  fn new(constants: Self::Constants) -> Self;

  /// Returns a challenge by hashing the internal state
  fn squeeze(&mut self) -> C::Scalar;
}

/// A helper trait that defines the behavior of a hash function that we use as an RO in the circuit model
pub trait ROCircuitTrait<C: CurveAffine> {
  /// A type representing constants/parameters associated with the hash function
  type Constants: ROConstantsTrait;

  /// Initializes the hash function
  fn new(constants: Self::Constants) -> Self;

  fn squeeze(&mut self, ctx: &mut RegionCtx<'_, C::Scalar>) -> Result<Vec<AssignedCell<C::Scalar, C::Scalar>>, Error>;
}


fn main() {
  const T: usize = 3;
  const RATE: usize = 2;
  const R_F: usize = 4;
  const R_P: usize = 3;
  #[derive(Clone, Debug)]
  struct TestCircuitConfig {
    pconfig: MainGateConfig<T>,
    instance: Column<Instance>
  }

  struct TestCircuit<F: PrimeField> {
    inputs: Vec<F>,
  }

  impl<F:PrimeField> TestCircuit<F> {
    fn new(inputs: Vec<F>) -> Self {
      Self {
          inputs,
      }
    }
  }

  impl<F: PrimeField+FromUniformBytes<64>> Circuit<F> for TestCircuit<F> {
    type Config = TestCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
      Self {
        inputs: Vec::new(),
      }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
      let instance = meta.instance_column();
      meta.enable_equality(instance);
      let mut adv_cols = [(); T+2].map(|_| meta.advice_column()).into_iter();
      let mut fix_cols = [(); 2*T+4].map(|_| meta.fixed_column()).into_iter();
      let pconfig = MainGate::configure(meta, &mut adv_cols, &mut fix_cols);
      Self::Config {
        pconfig,
        instance,
      }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
      let spec = Spec::<F, T, RATE>::new(R_F, R_P);
      let mut pchip = PoseidonChip::new(config.pconfig, spec);
      pchip.update(self.inputs.clone());
      let output = layouter.assign_region(||"poseidon hash", |region|{
                 let ctx = &mut RegionCtx::new(region, 0);
                 pchip.squeeze(ctx)
      })?;
      layouter.constrain_instance(output.cell(), config.instance, 0)?;
      Ok(())
    }
  }

  println!("-----running Poseidon Circuit-----");
  const K:u32 = 10;
  let params: ParamsIPA<vesta::Affine> = ParamsIPA::<EqAffine>::new(K);
  let mut inputs = Vec::new();
  for i in 0..5 {
    inputs.push(Fp::from(i as u64));
  }
  let circuit = TestCircuit::new(inputs);

  let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
  let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");
  let out_hash = Fp::from_str_vartime("13037709793114148810823325920380362524528554380279235267325741570708489436263").unwrap();
  let public_inputs: &[&[Fp]] = &[&[out_hash]];
  let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
  create_proof::<IPACommitmentScheme<_>, ProverIPA<_>, _, _, _, _>(&params, &pk, &[circuit], &[public_inputs], OsRng, &mut transcript)
              .expect("proof generation should not fail");

  let proof = transcript.finalize();
  let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
  let strategy = SingleStrategy::new(&params);
  verify_proof(&params, pk.get_vk(), strategy, &[public_inputs], &mut transcript).unwrap();
  println!("-----poseidon circuit works fine-----");
}
