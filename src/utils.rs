use snark_verifier::{
    halo2_base::halo2_proofs::{
        halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
        plonk::VerifyingKey,
        poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
    }, loader::evm::{compile_solidity, EvmLoader}, system::halo2::{compile, transcript::evm::EvmTranscript, Config}, util::arithmetic::Field, verifier::SnarkVerifier
};
use snark_verifier_sdk::{evm::EvmKzgAccumulationScheme, PlonkVerifier};
use std::{fs, path::Path, rc::Rc};

use crate::schnorr::PrivateKey;

pub fn gen_evm_verifier<AS>(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
    path: Option<&Path>,
) -> Vec<u8>
where
    AS: EvmKzgAccumulationScheme,
{
    let protocol = compile(params, vk, Config::kzg().with_num_instance(num_instance.clone()));
    // deciding key
    let dk = (params.get_g()[0], params.g2(), params.s_g2()).into();

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = PlonkVerifier::<AS>::read_proof(&dk, &protocol, &instances, &mut transcript).unwrap();
    PlonkVerifier::<AS>::verify(&dk, &protocol, &instances, &proof).unwrap();

    let sol_code = loader.solidity_code().replace("pragma solidity 0.8.19", "pragma solidity ^0.8.19");

    if let Some(path) = path {
        path.parent().and_then(|dir| fs::create_dir_all(dir).ok()).unwrap();
        fs::write(path, &sol_code).unwrap();
    }
    let byte_code = compile_solidity(&sol_code);
    byte_code
}


pub fn sample_private_key() -> PrivateKey {
    let mut rng = rand::thread_rng();
    PrivateKey {
        seed: Fq::random(&mut rng),
        sk_sig: Fr::random(&mut rng),
        r_sig: Fr::random(&mut rng),
    }
}

pub fn sample_msg() -> Vec<Fr> {
    let mut rng = rand::thread_rng();
    (0..10).map(|_| Fr::random(&mut rng)).collect()
}
