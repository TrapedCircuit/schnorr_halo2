use snark_verifier::{
    halo2_base::{
        gates::{
            circuit::{builder::RangeCircuitBuilder, BaseCircuitParams},
            RangeChip,
        },
        halo2_proofs::{
            halo2curves::bn256::{Bn256, Fr, G1Affine},
            plonk::{keygen_pk, keygen_vk},
            poly::kzg::commitment::ParamsKZG,
        },
        poseidon::hasher::PoseidonSponge,
        Context,
    },
    halo2_ecc::{
        bigint::ProperCrtUint,
        bn254::FpChip,
        ecc::{EcPoint, EccChip},
        fields::FieldChip,
    },
    util::arithmetic::PrimeField,
};
use snark_verifier_sdk::{evm::gen_evm_proof_shplonk, CircuitExt};

use crate::schnorr::{Address, Signature, RF, RP};

const K: usize = 20;
const LOOKUP_BITS: usize = 19;

const LIMB_BITS: usize = 88;
const NUM_LIMB: usize = 3;

pub struct AleoSchnorrCircuit {
    pub params: Option<BaseCircuitParams>,

    pub signature: Signature,
    pub address: Address,
    pub msg: Vec<Fr>,
}

impl AleoSchnorrCircuit {
    pub fn setup(signature: Signature, address: Address, msg: &[Fr]) -> (Self, RangeCircuitBuilder<Fr>, RangeChip<Fr>) {
        let circuit = RangeCircuitBuilder::default().use_k(K).use_lookup_bits(LOOKUP_BITS);
        let range = RangeChip::new(LOOKUP_BITS, circuit.lookup_manager().clone());
        (Self { params: None, signature, address, msg: msg.to_vec() }, circuit, range)
    }

    pub fn evaluate(&self, ctx: &mut Context<Fr>, range: &RangeChip<Fr>) {
        let fp_chip = FpChip::new(range, LIMB_BITS, NUM_LIMB);
        let ecc_chip = EccChip::new(&fp_chip);

        let signature = self.signature.load_witness(ctx, &ecc_chip);
        let address = ecc_chip.assign_point_unchecked(ctx, self.address);
        let msg = ctx.assign_witnesses(self.msg.clone().into_iter());
        let g = ecc_chip.assign_constant_point(ctx, G1Affine::generator());

        let pk_sig = signature.compute_key.pk_sig.clone();
        let pr_sig = signature.compute_key.pr_sig.clone();

        let g_r = {
            let a =
                ecc_chip.scalar_mult::<G1Affine>(ctx, g, vec![signature.response.clone()], Fr::NUM_BITS as usize, 4);
            let b = ecc_chip.scalar_mult::<G1Affine>(
                ctx,
                pk_sig.clone(),
                vec![signature.challenge.clone()],
                Fr::NUM_BITS as usize,
                4,
            );
            ecc_chip.add_unequal(ctx, a, b, true)
        };

        let preimage = {
            let a = vec![g_r, pk_sig, pr_sig, address.clone()]
                .iter()
                .map(|g| Fr::from_bytes(&g.x.value().to_bytes_le().try_into().unwrap()).unwrap()) // Bug here
                .collect::<Vec<_>>();
            let a = ctx.assign_witnesses(a);
            let mut preimage = Vec::with_capacity(4 + self.msg.len());
            preimage.extend(a);
            preimage.extend(msg);
            preimage
        };

        let mut circuit_poseidon = PoseidonSponge::<_, 3, 2>::new::<RF, RP, 0>(ctx);
        circuit_poseidon.update(&preimage);

        let candidate_challenge = circuit_poseidon.squeeze(ctx, fp_chip.gate());
        let candidate_address = signature.compute_key.load_address(ctx, &ecc_chip);

        ctx.constrain_equal(&candidate_challenge, &signature.challenge);
        ecc_chip.assert_equal(ctx, candidate_address, address);
    }

    pub fn evaluate_for_test(
        &self,
        ctx: &mut Context<Fr>,
        range: &RangeChip<Fr>,
    ) -> Vec<EcPoint<Fr, ProperCrtUint<Fr>>> {
        let fp_chip = FpChip::new(range, LIMB_BITS, NUM_LIMB);
        let ecc_chip = EccChip::new(&fp_chip);

        let signature = self.signature.load_witness(ctx, &ecc_chip);
        let address = ecc_chip.assign_point_unchecked(ctx, self.address);
        let msg = ctx.assign_witnesses(self.msg.clone().into_iter());
        let g = ecc_chip.assign_constant_point(ctx, G1Affine::generator());

        let pk_sig = signature.compute_key.pk_sig.clone();
        let pr_sig = signature.compute_key.pr_sig.clone();

        let g_r = {
            let a =
                ecc_chip.scalar_mult::<G1Affine>(ctx, g, vec![signature.response.clone()], Fr::NUM_BITS as usize, 4);
            let b = ecc_chip.scalar_mult::<G1Affine>(
                ctx,
                pk_sig.clone(),
                vec![signature.challenge.clone()],
                Fr::NUM_BITS as usize,
                4,
            );
            ecc_chip.add_unequal(ctx, a, b, true)
        };

        let test = vec![pk_sig.clone(), pr_sig.clone(), address.clone()];

        let preimage = {
            let a = vec![g_r, pk_sig, pr_sig, address.clone()]
                .iter()
                .map(|g| Fr::from_bytes(&g.x.value().to_bytes_le().try_into().unwrap()).unwrap()) // Bug here
                .collect::<Vec<_>>();
            let a = ctx.assign_witnesses(a);
            let mut preimage = Vec::with_capacity(4 + self.msg.len());
            preimage.extend(a);
            preimage.extend(msg);
            preimage
        };

        let mut circuit_poseidon = PoseidonSponge::<_, 3, 2>::new::<RF, RP, 0>(ctx);
        circuit_poseidon.update(&preimage);

        let candidate_challenge = circuit_poseidon.squeeze(ctx, fp_chip.gate());
        let candidate_address = signature.compute_key.load_address(ctx, &ecc_chip);

        ctx.constrain_equal(&candidate_challenge, &signature.challenge);
        ecc_chip.assert_equal(ctx, candidate_address, address);

        test
    }

    pub fn calculate_params(&mut self, circuit: &mut RangeCircuitBuilder<Fr>) {
        let t_cells_lookup = circuit.lookup_manager().iter().map(|lm| lm.total_rows()).sum::<usize>();
        let look_up_bits = if t_cells_lookup == 0 { None } else { Some(LOOKUP_BITS) };
        circuit.config_params.lookup_bits = look_up_bits;
        let config_params = circuit.calculate_params(Some(9));
        self.params = Some(config_params);
    }

    pub fn gen_proof(&mut self, circuit: &mut RangeCircuitBuilder<Fr>) -> Vec<u8> {
        let config_params = self.params.clone().expect("params should be calculated");
        let mut rng = rand::thread_rng();
        let params = ParamsKZG::<Bn256>::setup(K as u32, &mut rng);
        let vk = keygen_vk(&params, circuit).expect("vk should not fail");
        let pk = keygen_pk(&params, vk, circuit).expect("pk should not fail");
        let break_points = circuit.break_points();

        let mut circuit = RangeCircuitBuilder::<Fr>::prover(config_params, break_points);
        let range = RangeChip::new(LOOKUP_BITS, circuit.lookup_manager().clone());
        self.evaluate(circuit.main(0), &range);
        let instances = circuit.instances();
        gen_evm_proof_shplonk(&params, &pk, circuit, instances)
    }
}

pub mod tests {
    use snark_verifier::{
        halo2_base::halo2_proofs::{
            dev::MockProver,
            halo2curves::bn256::{Fr, G1Affine},
        },
        halo2_ecc::{bn254::FpChip, ecc::EccChip},
        util::arithmetic::PrimeField,
    };
    use snark_verifier_sdk::CircuitExt;

    use crate::{
        circuit::{AleoSchnorrCircuit, K, LIMB_BITS, NUM_LIMB},
        schnorr::{ComputeKey, Signature},
        utils::{sample_msg, sample_private_key},
    };
    use snark_verifier::util::arithmetic::Curve;

    #[test]
    fn test_scalar_mul() {
        let mut rng = rand::thread_rng();
        let private_key = sample_private_key();
        let msg = sample_msg();
        let compute_key = ComputeKey::try_from(&private_key).unwrap();
        let address = compute_key.into();
        let (sigature, _test_affine) = Signature::sign_for_test(&private_key, &msg, &mut rng).unwrap();
        assert!(sigature.verify(address, &msg));

        let (aleo, mut circuit, range) = AleoSchnorrCircuit::setup(sigature, address, &msg);
        let _test = aleo.evaluate_for_test(circuit.main(0), &range);

        {
            let ctx = circuit.main(0);
            let fp_chip = FpChip::new(&range, LIMB_BITS, NUM_LIMB);
            let ecc_chip = EccChip::new(&fp_chip);
            let g = G1Affine::generator();
            let fr = Fr::from_u128(2u128);
            let acc = (g * fr).to_affine();

            let g_ = ecc_chip.assign_constant_point(ctx, g);
            let fr_ = ctx.assign_witnesses(vec![fr]);
            let acc_ = ecc_chip.scalar_mult::<G1Affine>(ctx, g_, fr_, Fr::NUM_BITS as usize, 4);
            let real_acc = ecc_chip.assign_constant_point(ctx, acc);

            ecc_chip.assert_equal(ctx, acc_, real_acc);
        }
    }

    #[test]
    fn test_equality() {
        let mut rng = rand::thread_rng();
        let private_key = sample_private_key();
        let msg = sample_msg();
        let compute_key = ComputeKey::try_from(&private_key).unwrap();
        let address = compute_key.into();
        let (sigature, test_affine) = Signature::sign_for_test(&private_key, &msg, &mut rng).unwrap();
        assert!(sigature.verify(address, &msg));

        let (aleo, mut circuit, range) = AleoSchnorrCircuit::setup(sigature, address, &msg);
        let test = aleo.evaluate_for_test(circuit.main(0), &range);

        {
            let fp_chip = FpChip::new(&range, LIMB_BITS, NUM_LIMB);
            let ecc_chip = EccChip::new(&fp_chip);

            let test_affine =
                test_affine.iter().map(|g| ecc_chip.assign_point_unchecked(circuit.main(0), *g)).collect::<Vec<_>>();

            for (i, (a, b)) in test.into_iter().zip(test_affine.into_iter()).enumerate() {
                println!("i: {}", i);
                ecc_chip.assert_equal(circuit.main(0), a, b);
            }
        }
    }

    #[test]
    fn test_mock_run() {
        let mut rng = rand::thread_rng();
        let private_key = sample_private_key();
        let msg = sample_msg();
        let compute_key = ComputeKey::try_from(&private_key).unwrap();
        let address = compute_key.into();
        let signature = Signature::sign(&private_key, &msg, &mut rng).unwrap();
        assert!(signature.verify(address, &msg));

        let (mut aleo, mut circuit, range) = AleoSchnorrCircuit::setup(signature, address, &msg);
        aleo.evaluate(circuit.main(0), &range);
        aleo.calculate_params(&mut circuit);

        MockProver::run(K as u32, &circuit, circuit.instances()).unwrap().assert_satisfied();
    }
}
