use snark_verifier::{halo2_base::{
    gates::{
        circuit::{builder::RangeCircuitBuilder, BaseCircuitParams},
        RangeChip,
    },
    halo2_proofs::halo2curves::bn256::{Fq, Fr, G1Affine},
}, halo2_ecc::{bn254::FpChip, ecc::EccChip, fields::FieldChip}};

use crate::schnorr::{Address, Signature};

const K: usize = 20;
const LOOKUP_BITS: usize = 19;

const LIMB_BITS: usize = 88;
const NUM_LIMB: usize = 3;

pub struct AleoSchnorrCircuit {
    pub circuit: RangeCircuitBuilder<Fr>,
    pub range: RangeChip<Fr>,
    pub params: Option<BaseCircuitParams>,

    pub signature: Signature,
    pub address: Address,
    pub msg: Vec<Fq>,
}

impl AleoSchnorrCircuit {
    pub fn setup(signature: Signature, address: Address, msg: &[Fq]) -> Self {
        let circuit = RangeCircuitBuilder::default().use_k(K).use_lookup_bits(LOOKUP_BITS);
        let range = RangeChip::new(LOOKUP_BITS, circuit.lookup_manager().clone());
        Self { circuit, range, params: None, signature, address, msg: msg.to_vec() }
    }

    pub fn evaluate(&mut self) {
        let ctx = self.circuit.main(0);
        let fp_chip = FpChip::new(&self.range, LIMB_BITS, NUM_LIMB);
        let ecc_chip = EccChip::new(&fp_chip);

        let signature = self.signature.load_witness(ctx, &ecc_chip);
        let address = ecc_chip.assign_point_unchecked(ctx, self.address);
        let msg = self.msg.iter().map(|fq| fp_chip.load_private(ctx, *fq)).collect::<Vec<_>>();
        let g = ecc_chip.assign_constant_point(ctx, G1Affine::generator());

        let pk_sig = signature.compute_key.pk_sig.clone();
        let pr_sig = signature.compute_key.pr_sig.clone();

        let g_r = {
            let result = ecc_chip.scalar_mult(ctx, g, vec![signature.response.clone()], max_bits, window_bits)
        };
    }


}
