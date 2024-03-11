use rand::{CryptoRng, Rng};
use snark_verifier::halo2_base::halo2_proofs::halo2curves::bn256::{Fq, Fr, G1Affine};
use snark_verifier::halo2_base::{AssignedValue, Context};
use snark_verifier::halo2_ecc::bigint::ProperCrtUint;
use snark_verifier::halo2_ecc::ecc::EcPoint;
use snark_verifier::util::arithmetic::{Curve, Field};

const RF: usize = 8;
const RP: usize = 57;

#[derive(Clone, Copy)]
pub struct Signature {
    pub challege: Fr,
    pub response: Fr,
    pub compute_key: ComputeKey,
}

impl Signature {
    pub fn sign<R: Rng + CryptoRng>(pk: &PrivateKey, msg: &[Fq], rng: &mut R) -> anyhow::Result<Self> {
        let nonce = Fr::random(rng);
        let g_r = (G1Affine::generator() * nonce).to_affine();

        let compute_key = ComputeKey::try_from(pk)?;
        let pk_sig = compute_key.pk_sig;
        let pr_sig = compute_key.pr_sig;
        let address: Address = compute_key.into();

        let mut preimage = Vec::with_capacity(4 + msg.len());
        preimage.extend(vec![g_r, pk_sig, pr_sig, address].iter().map(|g| g.x));
        preimage.extend(msg.iter());

        let mut native_poseidon = pse_poseidon::Poseidon::<Fq, 3, 2>::new(RF, RP);
        native_poseidon.update(&preimage);

        let challenge = Fr::from_bytes(&native_poseidon.squeeze().to_bytes()).unwrap(); // TODO: handle error
        let response = nonce - (challenge * pk.sk_sig);

        Ok(Self { challege: challenge, response, compute_key })
    }

    pub fn verify(&self, address: Address, msg: &[Fq]) -> bool {
        let pk_sig = self.compute_key.pk_sig;
        let pr_sig = self.compute_key.pr_sig;

        let g_r = (G1Affine::generator() * self.response + (pk_sig * self.challege)).to_affine();

        let mut preimage = Vec::with_capacity(4 + msg.len());
        preimage.extend(vec![g_r, pk_sig, pr_sig, address].iter().map(|g| g.x));
        preimage.extend(msg.iter());

        let mut native_poseidon = pse_poseidon::Poseidon::<Fq, 3, 2>::new(RF, RP);
        native_poseidon.update(&preimage);

        let candidate_challenge = Fr::from_bytes(&native_poseidon.squeeze().to_bytes()).unwrap(); // TODO: handle error
        let candidate_address: Address = self.compute_key.into();

        self.challege == candidate_challenge && candidate_address == address
    }

    pub fn verify_in_circuit(
        &self,
        ctx: &mut Context<Fr>,
        address: EcPoint<Fq, ProperCrtUint<Fr>>,
        msg: &[ProperCrtUint<Fr>],
    ) -> AssignedValue<Fr> {
        unimplemented!()
    }
}

#[derive(Clone, Copy)]
pub struct ComputeKey {
    pub pk_sig: G1Affine,
    pub pr_sig: G1Affine,
    pub sk_prf: Fr,
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

        let msg = vec![Fq::random(&mut rng), Fq::random(&mut rng), Fq::random(&mut rng)];
        let signature = Signature::sign(&private_key, &msg, &mut rng).unwrap();

        assert!(signature.verify(public_key.into(), &msg));
    }
}
