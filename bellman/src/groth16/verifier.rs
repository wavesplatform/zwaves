use pairing::{
    Engine,
    CurveProjective,
    CurveAffine,
    PrimeField,
    Field
};

use super::{
    Proof,
    VerifyingKey,
    TruncatedVerifyingKey
};

use ::{
    SynthesisError
};

pub fn truncate_verifying_key<E: Engine>(
    vk: &VerifyingKey<E>
) -> TruncatedVerifyingKey<E>
{
    TruncatedVerifyingKey {
        alpha_g1: vk.alpha_g1.clone(),
        beta_g2: vk.beta_g2.clone(),
        gamma_g2: vk.gamma_g2.clone(),
        delta_g2: vk.delta_g2.clone(),
        ic: vk.ic.clone()
    }
}

pub fn verify_proof<'a, E: Engine>(
    tvk: &'a TruncatedVerifyingKey<E>,
    proof: &Proof<E>,
    public_inputs: &[E::Fr]
) -> Result<bool, SynthesisError>
{
    if (public_inputs.len() + 1) != tvk.ic.len() {
        return Err(SynthesisError::MalformedVerifyingKey);
    }

    let mut acc = tvk.ic[0].into_projective();

    for (i, b) in public_inputs.iter().zip(tvk.ic.iter().skip(1)) {
        acc.add_assign(&b.mul(i.into_repr()));
    }

    // The original verification equation is:
    // A * B = alpha * beta + inputs * gamma + C * delta
    // ... however, we rearrange it so that it is:
    // (-A) * B + alpha * beta + inputs * gamma + C * delta == 1

    let mut neg_a = proof.a.clone();
    neg_a.negate();

    Ok(E::final_exponentiation(
        &E::miller_loop([
            (&neg_a.prepare(), &proof.b.prepare()),
            (&tvk.alpha_g1.prepare(), &tvk.beta_g2.prepare()),
            (&acc.into_affine().prepare(), &tvk.gamma_g2.prepare()),
            (&proof.c.prepare(), &tvk.delta_g2.prepare())
        ].into_iter())
    ).unwrap() == E::Fqk::one())
}
