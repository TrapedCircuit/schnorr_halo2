use std::path::Path;

use snark_verifier::util::arithmetic::Curve;
use snark_verifier::{
    halo2_base::{
        gates::{circuit::builder::RangeCircuitBuilder, RangeChip},
        halo2_proofs::{
            dev::MockProver,
            halo2curves::bn256::{Bn256, Fr, G1Affine},
            plonk::{keygen_pk, keygen_vk},
            poly::kzg::commitment::ParamsKZG,
        },
        Context,
    },
    halo2_ecc::{bn254::FpChip, ecc::EccChip},
};
use snark_verifier_sdk::evm::{evm_verify, gen_evm_proof_shplonk};
use snark_verifier_sdk::{CircuitExt, SHPLONK};
pub mod schnorr;
pub mod utils;
pub mod circuit;

const PATH: &str = "./src/evm_verifier.sol";

fn main() {
    // 1. config
    let k = 20;
    let lookup_bits = 19;
    let (mut builder, range) = sample_setup(k, lookup_bits);
    let (p, q, check_acc) = sample_input();

    // 2. prove
    sample_prove(builder.main(0), &range, p, q, check_acc);

    // 3. calculate params
    let t_cells_lookup = builder.lookup_manager().iter().map(|lm| lm.total_rows()).sum::<usize>();
    let look_up_bits = if t_cells_lookup == 0 { None } else { Some(lookup_bits) };
    builder.config_params.lookup_bits = look_up_bits;
    let config_params = builder.calculate_params(Some(9));

    // 4. mock prove
    MockProver::run(k as u32, &builder, vec![]).unwrap().assert_satisfied();

    // 5. generate proof
    let mut rng = rand::thread_rng();
    let params = ParamsKZG::<Bn256>::setup(k as u32, &mut rng);
    let vk = keygen_vk(&params, &builder).expect("vk should not fail");
    let pk = keygen_pk(&params, vk, &builder).expect("pk should not fail");
    let break_points = builder.break_points();
    drop(builder);
    let mut builder = RangeCircuitBuilder::<Fr>::prover(config_params, break_points);

    let range = RangeChip::new(lookup_bits, builder.lookup_manager().clone());
    sample_prove(builder.main(0), &range, p, q, check_acc);
    let instances = builder.instances();
    let num_instance = builder.num_instance();
    let proof = gen_evm_proof_shplonk(&params, &pk, builder, instances);

    // 6. verify in evm
    let path = Path::new(PATH);
    // let deployment_code =
    //     gen_evm_verifier_shplonk::<RangeCircuitBuilder<Fr>>(&params, pk.get_vk(), vec![num_instance], Some(path));
    let deployment_code = utils::gen_evm_verifier::<SHPLONK>(&params, pk.get_vk(), num_instance, Some(path));
    evm_verify(deployment_code, vec![], proof);
}

pub fn sample_prove(ctx: &mut Context<Fr>, range: &RangeChip<Fr>, p: G1Affine, q: G1Affine, check_acc: G1Affine) {
    let fp_chip = FpChip::new(range, 88, 3);
    let ecc_chip = EccChip::new(&fp_chip);

    let p = ecc_chip.assign_point_unchecked(ctx, p);
    let q = ecc_chip.assign_point_unchecked(ctx, q);
    let real_acc = ecc_chip.assign_constant_point(ctx, check_acc);

    let acc = ecc_chip.add_unequal(ctx, p, q, true);

    ecc_chip.assert_equal(ctx, real_acc, acc);
}

pub fn sample_setup(k: usize, lookup_bits: usize) -> (RangeCircuitBuilder<Fr>, RangeChip<Fr>) {
    let mut builder = RangeCircuitBuilder::<Fr>::default().use_k(k);
    builder.set_lookup_bits(lookup_bits);
    let range = RangeChip::new(lookup_bits, builder.lookup_manager().clone());
    (builder, range)
}

pub fn sample_input() -> (G1Affine, G1Affine, G1Affine) {
    let mut rng = rand::thread_rng();
    let p = G1Affine::random(&mut rng);
    let q = G1Affine::random(&mut rng);
    let check_acc = (p + q).to_affine();
    (p, q, check_acc)
}
