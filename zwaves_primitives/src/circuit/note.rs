
use pairing::{Engine, Field, PrimeField, PrimeFieldRepr, BitIterator};

use bellman::{SynthesisError, ConstraintSystem, LinearCombination, Variable};

use sapling_crypto::jubjub::{JubjubEngine, JubjubParams, JubjubBls12};
use sapling_crypto::circuit::{pedersen_hash};
use sapling_crypto::circuit::num::{AllocatedNum, Num};
use sapling_crypto::circuit::boolean::{AllocatedBit, Boolean};



pub struct Note<E: JubjubEngine> {
    assetId: AllocatedNum<E>,
    amount: AllocatedNum<E>,
    nativeAmount: AllocatedNum<E>,
    owner: AllocatedNum<E>,
    txid: AllocatedNum<E>
}