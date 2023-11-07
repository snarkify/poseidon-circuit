use ff::PrimeField;
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::{ProverGWC, VerifierGWC},
        strategy::SingleStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use rand_core::OsRng;

pub mod main_gate;
pub mod poseidon_circuit;
pub mod poseidon_hash;
pub mod ro_types;
pub mod test_circuit;

fn main() {
    println!("-----running Poseidon Circuit-----");
    const K: u32 = 10;
    let params = ParamsKZG::<Bn256>::setup(K, OsRng);
    let mut inputs = Vec::new();
    for i in 0..5 {
        inputs.push(Fr::from(i as u64));
    }
    let circuit = test_circuit::TestCircuit::new(inputs);

    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");
    let out_hash = Fr::from_str_vartime(
        "20304616028358001435806807494046171997958789835068077254356069730773893150537",
    )
    .unwrap();
    let public_inputs: &[&[Fr]] = &[&[out_hash]];
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
    create_proof::<KZGCommitmentScheme<_>, ProverGWC<'_, _>, _, _, _, _>(
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
    assert!(verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierGWC<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(
        &params,
        pk.get_vk(),
        strategy,
        &[public_inputs],
        &mut transcript,
    )
    .is_ok());
    println!("-----poseidon circuit works fine-----");
}
