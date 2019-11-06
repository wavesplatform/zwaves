use serde::{Serialize, Serializer, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Fq12 {
    pub(crate) c0: Fq6,
    pub(crate) c1: Fq6,
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

#[derive(Serialize, Deserialize, Debug)]
pub struct Fq(pub(crate) [u64; 6]);

#[derive(Serialize, Deserialize, Debug)]
pub struct G1Affine {
    pub(crate) x: Fq,
    pub(crate) y: Fq,
    pub(crate) infinity: bool
}

#[derive(Serialize, Deserialize, Debug)]
pub struct G2Affine {
    pub(crate) x: Fq2,
    pub(crate) y: Fq2,
    pub(crate) infinity: bool
}

#[derive(Serialize, Deserialize, Debug)]
pub struct G2Prepared {
    pub(crate) coeffs: Vec<(Fq2, Fq2, Fq2)>,
    pub(crate) infinity: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OpenPreparedVerifyingKey {
    /// Pairing result of alpha*beta
    pub(crate) alpha_g1_beta_g2: Fq12,
    /// -gamma in G2
    pub(crate) neg_gamma_g2: G2Prepared,
    /// -delta in G2
    pub(crate) neg_delta_g2: G2Prepared,
    /// Copy of IC from `VerifiyingKey`.
    pub(crate) ic: Vec<G1Affine>,
}