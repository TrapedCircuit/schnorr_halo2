use rand::{CryptoRng, Rng};
use snark_verifier::halo2_base::halo2_proofs::halo2curves::bn256::{Fq, Fr, G1Affine};
use snark_verifier::halo2_base::{AssignedValue, Context};
use snark_verifier::halo2_ecc::bigint::ProperCrtUint;
use snark_verifier::halo2_ecc::bn254::FpChip;
use snark_verifier::halo2_ecc::ecc::{EcPoint, EccChip};
use snark_verifier::util::arithmetic::{Curve, Field};

pub const RF: usize = 8;
pub const RP: usize = 57;

#[derive(Clone, Copy)]
pub struct Signature {
    pub challenge: Fr,
    pub response: Fr,
    pub compute_key: ComputeKey,
}

#[derive(Clone)]
pub struct SignatureCircuit {
    pub challenge: AssignedValue<Fr>,
    pub response: AssignedValue<Fr>,
    pub compute_key: ComputeKeyCircuit,
}

impl Signature {
    pub fn sign<R: Rng + CryptoRng>(pk: &PrivateKey, msg: &[Fr], rng: &mut R) -> anyhow::Result<Self> {
        let nonce = Fr::random(rng);
        let g_r = (G1Affine::generator() * nonce).to_affine();

        let compute_key = ComputeKey::try_from(pk)?;
        let pk_sig = compute_key.pk_sig;
        let pr_sig = compute_key.pr_sig;
        let address: Address = compute_key.into();

        let mut preimage = Vec::with_capacity(4 + msg.len());
        preimage.extend(vec![g_r, pk_sig, pr_sig, address].iter().map(|g| Fr::from_bytes(&g.x.to_bytes()).unwrap()));
        preimage.extend(msg.iter());

        let mut native_poseidon = pse_poseidon::Poseidon::<Fr, 3, 2>::new(RF, RP);
        native_poseidon.update(&preimage);

        let challenge = native_poseidon.squeeze();
        let response = nonce - (challenge * pk.sk_sig);

        Ok(Self { challenge, response, compute_key })
    }

    pub fn sign_for_test<R: Rng + CryptoRng>(pk: &PrivateKey, msg: &[Fr], rng: &mut R) -> anyhow::Result<(Self, Vec<Fr>)> {
        let nonce = Fr::random(rng);
        let g_r = (G1Affine::generator() * nonce).to_affine();

        let compute_key = ComputeKey::try_from(pk)?;
        let pk_sig = compute_key.pk_sig;
        let pr_sig = compute_key.pr_sig;
        let address: Address = compute_key.into();

        let mut preimage = Vec::with_capacity(4 + msg.len());
        preimage.extend(vec![g_r, pk_sig, pr_sig, address].iter().map(|g| Fr::from_bytes(&g.x.to_bytes()).unwrap()));
        preimage.extend(msg.iter());

        println!("preimage1: {:?}", preimage);

        let mut native_poseidon = pse_poseidon::Poseidon::<Fr, 3, 2>::new(RF, RP);
        native_poseidon.update(&preimage);

        let challenge = native_poseidon.squeeze();
        let response = nonce - (challenge * pk.sk_sig);

        Ok((Self { challenge, response, compute_key }, preimage))
    }

    pub fn verify(&self, address: Address, msg: &[Fr]) -> bool {
        let pk_sig = self.compute_key.pk_sig;
        let pr_sig = self.compute_key.pr_sig;

        let a = G1Affine::generator() * self.response;
        println!("a_1: {:?}", a.x);
        let b = pk_sig * self.challenge;
        println!("b_1: {:?}", b.x);
        let g_r = (G1Affine::generator() * self.response + (pk_sig * self.challenge)).to_affine();
        println!("g_r1: {:?}", g_r.x);

        let mut preimage = Vec::with_capacity(4 + msg.len());
        preimage.extend(vec![g_r, pk_sig, pr_sig, address].iter().map(|g| Fr::from_bytes(&g.x.to_bytes()).unwrap()));
        preimage.extend(msg.iter());

        let mut native_poseidon = pse_poseidon::Poseidon::<Fr, 3, 2>::new(RF, RP);
        native_poseidon.update(&preimage);

        let candidate_challenge = native_poseidon.squeeze();
        let candidate_address: Address = self.compute_key.into();

        self.challenge == candidate_challenge && candidate_address == address
    }

    pub fn load_witness(&self, ctx: &mut Context<Fr>, ecc_chip: &EccChip<Fr, FpChip<Fr>>) -> SignatureCircuit {
        let [challenge, response]: [_; 2] = ctx.assign_witnesses([self.challenge, self.response]).try_into().unwrap();
        SignatureCircuit {
            challenge,
            response,
            compute_key: self.compute_key.load_witness(ctx, ecc_chip),
        }
    }
}

#[derive(Clone, Copy)]
pub struct ComputeKey {
    pub pk_sig: G1Affine,
    pub pr_sig: G1Affine,
    pub sk_prf: Fr,
}

impl ComputeKey {
    pub fn load_witness(&self, ctx: &mut Context<Fr>, ecc_chip: &EccChip<Fr, FpChip<Fr>>) -> ComputeKeyCircuit {
        ComputeKeyCircuit {
            pk_sig: ecc_chip.assign_point_unchecked(ctx, self.pk_sig),
            pr_sig: ecc_chip.assign_point_unchecked(ctx, self.pr_sig),
            sk_prf: ctx.assign_witnesses([self.sk_prf])[0],
        }
    }
}

#[derive(Clone)]
pub struct ComputeKeyCircuit {
    pub pk_sig: EcPoint<Fr, ProperCrtUint<Fr>>,
    pub pr_sig: EcPoint<Fr, ProperCrtUint<Fr>>,
    pub sk_prf: AssignedValue<Fr>,
}

impl ComputeKeyCircuit {
    pub fn load_address(&self, ctx: &mut Context<Fr>, ecc_chip: &EccChip<Fr, FpChip<Fr>>) -> EcPoint<Fr, ProperCrtUint<Fr>> {
        let g = G1Affine::generator();
        let g = ecc_chip.assign_point_unchecked(ctx, g);
        let pk_prf = ecc_chip.scalar_mult::<G1Affine>(ctx, g, vec![self.sk_prf.clone()], ecc_chip.field_chip().limb_bits, 4);
        let pk_prf = ecc_chip.add_unequal(ctx, pk_prf, self.pk_sig.clone(), true);
        let pk_prf = ecc_chip.add_unequal(ctx, pk_prf, self.pr_sig.clone(), true);
        pk_prf
    }
}



impl TryFrom<&PrivateKey> for ComputeKey {
    type Error = anyhow::Error;

    fn try_from(private_key: &PrivateKey) -> Result<Self, Self::Error> {
        let pk_sig = G1Affine::generator() * private_key.sk_sig;
        let pr_sig = G1Affine::generator() * private_key.r_sig;
        Ok(Self { pk_sig: pk_sig.to_affine(), pr_sig: pr_sig.to_affine(), sk_prf: private_key.sk_sig })
    }
}

pub type Address = G1Affine;

impl Into<G1Affine> for ComputeKey {
    fn into(self) -> G1Affine {
        let pk_prf = G1Affine::generator() * self.sk_prf;
        (pk_prf + self.pk_sig + self.pr_sig).to_affine()
    }
}

#[derive(Clone, Copy)]
pub struct PrivateKey {
    pub seed: Fq,
    pub sk_sig: Fr,
    pub r_sig: Fr,
}

pub mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_sign_verify() {
        let mut rng = OsRng;
        let private_key =
            PrivateKey { seed: Fq::random(&mut rng), sk_sig: Fr::random(&mut rng), r_sig: Fr::random(&mut rng) };
        let public_key = ComputeKey::try_from(&private_key).unwrap();

        let msg = vec![Fr::random(&mut rng), Fr::random(&mut rng), Fr::random(&mut rng)];
        let signature = Signature::sign(&private_key, &msg, &mut rng).unwrap();

        assert!(signature.verify(public_key.into(), &msg));
    }

    #[test]
    fn test_sign_verify_fail() {
        let mut rng = OsRng;
        let private_key =
            PrivateKey { seed: Fq::random(&mut rng), sk_sig: Fr::random(&mut rng), r_sig: Fr::random(&mut rng) };
        let public_key = ComputeKey::try_from(&private_key).unwrap();

        let msg = vec![Fr::random(&mut rng), Fr::random(&mut rng), Fr::random(&mut rng)];
        let signature = Signature::sign(&private_key, &msg, &mut rng).unwrap();

        let mut wrong_msg = msg.clone();
        wrong_msg[0] = Fr::random(&mut rng);

        assert!(!signature.verify(public_key.into(), &wrong_msg));
    }
}
