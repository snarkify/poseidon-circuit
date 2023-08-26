use base64::Engine;

use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::ipa::commitment::{IPACommitmentScheme, ParamsIPA};
use halo2_proofs::poly::ipa::multiopen::ProverIPA;
use halo2_proofs::poly::{ipa::strategy::SingleStrategy, VerificationStrategy};
use halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};

use ff::PrimeField;
use halo2curves::pasta::{vesta, EqAffine, Fp};
use rand_core::OsRng;

use base64::engine::general_purpose;
use serde::Deserialize;
use snarkify_sdk::prover::ProofHandler;

#[path = "../main_gate.rs"]
mod main_gate;
#[path = "../poseidon_circuit.rs"]
mod poseidon_circuit;
#[path = "../test_circuit.rs"]
mod test_circuit;

struct PoseidonProver {}

#[derive(Deserialize)]
pub struct Input {
    private_input: Vec<u64>,
    public_input: String,
}

impl ProofHandler for PoseidonProver {
    type Input = Input;
    type Output = String;
    type Error = ();

    fn prove(data: Self::Input) -> Result<Self::Output, Self::Error> {
        const K: u32 = 10;
        let params: ParamsIPA<vesta::Affine> = ParamsIPA::<EqAffine>::new(K);
        // private input
        let mut inputs = Vec::new();
        for i in 0..5 {
            inputs.push(Fp::from(data.private_input[i]));
        }
        let circuit = test_circuit::TestCircuit::new(inputs);

        let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");
        // let out_hash = Fp::from_str_vartime("13037709793114148810823325920380362524528554380279235267325741570708489436263").unwrap();
        let out_hash = Fp::from_str_vartime(&data.public_input).unwrap();
        let public_inputs: &[&[Fp]] = &[&[out_hash]];
        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
        create_proof::<IPACommitmentScheme<_>, ProverIPA<_>, _, _, _, _>(
            &params,
            &pk,
            &[circuit],
            &[public_inputs],
            OsRng,
            &mut transcript,
        )
        .expect("proof generation should not fail");

        let proof = transcript.finalize();
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let strategy = SingleStrategy::new(&params);
        verify_proof(
            &params,
            pk.get_vk(),
            strategy,
            &[public_inputs],
            &mut transcript,
        )
        .unwrap();
        Ok(general_purpose::STANDARD.encode(proof))
    }
}

fn main() -> Result<(), std::io::Error> {
    snarkify_sdk::run::<PoseidonProver>()
}
