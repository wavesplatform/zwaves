use std::sync::Arc;

use serde::{Deserialize, Serialize, Serializer};
use bellman::groth16::{VerifyingKey, PreparedVerifyingKey};
use pairing::bls12_381::Bls12;
use pairing::{Engine, CurveAffine};

#[derive(Serialize, Deserialize, Debug)]
pub struct Fq12 {
    pub(crate) c0: Fq6,
    pub(crate) c1: Fq6,
}

impl Fq12 {
    pub fn from_bls12(g1: pairing::bls12_381::Fq12) -> Fq12 {
        unsafe {
            std::mem::transmute(g1)
        }
    }
    pub fn to_bls12(self) -> pairing::bls12_381::Fq12 {
        unsafe {
            std::mem::transmute(self)
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Fq6 {
    pub(crate) c0: Fq2,
    pub(crate) c1: Fq2,
    pub(crate) c2: Fq2,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Fq2 {
    pub(crate) c0: Fq,
    pub(crate) c1: Fq,
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct Fq(pub(crate) [u64; 6]);

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct G1Affine {
    pub(crate) x: Fq,
    pub(crate) y: Fq,
    pub(crate) infinity: bool,
}

impl G1Affine {
    pub fn from_bls12(g1: pairing::bls12_381::G1Affine) -> G1Affine {
        unsafe {
            std::mem::transmute(g1)
        }
    }
    pub fn to_bls12(self) -> pairing::bls12_381::G1Affine {
        unsafe {
            std::mem::transmute(self)
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct G2Affine {
    pub(crate) x: Fq2,
    pub(crate) y: Fq2,
    pub(crate) infinity: bool,
}

impl G2Affine {
    pub fn from_bls12(g2: pairing::bls12_381::G2Affine) -> G2Affine {
        unsafe {
            std::mem::transmute(g2)
        }
    }
    pub fn to_bls12(self) -> pairing::bls12_381::G2Affine {
        unsafe {
            std::mem::transmute(self)
        }
    }
}

impl G2Prepared {
    pub fn from_bls12(g1: pairing::bls12_381::G2Prepared) -> G2Prepared {
        unsafe {
            std::mem::transmute(g1)
        }
    }
    pub fn to_bls12(g1: G2Prepared) -> pairing::bls12_381::G2Prepared {
        unsafe {
            std::mem::transmute(g1)
        }
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct G2Prepared {
    pub(crate) coeffs: Vec<(Fq2, Fq2, Fq2)>,
    pub(crate) infinity: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Bls12PreparedVerifyingKey {
    /// Pairing result of alpha*beta
    pub(crate) alpha_g1: G1Affine,
    pub(crate) beta_g2: G2Affine,
    /// -gamma in G2
    pub(crate) neg_gamma_g2: G2Prepared,
    /// -delta in G2
    pub(crate) neg_delta_g2: G2Prepared,
    /// Copy of IC from `VerifiyingKey`.
    pub(crate) ic: Vec<G1Affine>,
}

impl Bls12PreparedVerifyingKey {
    pub fn from_bls12(
        vk: VerifyingKey<Bls12>
    ) -> Bls12PreparedVerifyingKey {
        let mut gamma = vk.gamma_g2;
        gamma.negate();
        let mut delta = vk.delta_g2;
        delta.negate();

        Bls12PreparedVerifyingKey {
            alpha_g1: G1Affine::from_bls12(vk.alpha_g1),
            beta_g2: G2Affine::from_bls12(vk.beta_g2),
            neg_gamma_g2: G2Prepared::from_bls12(gamma.prepare()),
            neg_delta_g2: G2Prepared::from_bls12(delta.prepare()),
            ic: vk.ic.iter().map(|x| G1Affine::from_bls12(*x)).collect()
        }
    }

    pub fn to_groth16(self) -> PreparedVerifyingKey<Bls12> {
        let open = OpenPreparedVerifyingKey {
            alpha_g1_beta_g2: Fq12::from_bls12(Bls12::pairing(self.alpha_g1.to_bls12(), G2Affine::to_bls12(self.beta_g2))),
            neg_gamma_g2: self.neg_gamma_g2,
            neg_delta_g2: self.neg_delta_g2,
            ic: self.ic.clone()
        };
        unsafe {
            std::mem::transmute(open)
        }
    }
}

pub struct OpenPreparedVerifyingKey {
    /// Pairing result of alpha*beta
    alpha_g1_beta_g2: Fq12,
    /// -gamma in G2
    neg_gamma_g2: G2Prepared,
    /// -delta in G2
    neg_delta_g2: G2Prepared,
    /// Copy of IC from `VerifiyingKey`.
    ic: Vec<G1Affine>
}