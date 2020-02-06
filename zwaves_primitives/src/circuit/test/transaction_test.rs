extern crate num;

use bellman::{Circuit, ConstraintSystem, SynthesisError};

use sapling_crypto::jubjub::{JubjubEngine, JubjubParams, JubjubBls12};
use sapling_crypto::circuit::num::{AllocatedNum, Num};
use sapling_crypto::circuit::boolean::{AllocatedBit, Boolean};
use sapling_crypto::circuit::test::TestConstraintSystem;
use sapling_crypto::pedersen_hash::{Personalization};


use pairing::bls12_381::{Bls12, Fr, FrRepr};
use pairing::{PrimeField, Field};


use crate::pedersen_hasher;
use crate::circuit::merkle_proof;
use crate::transactions::{NoteData, pubkey, note_hash};
use crate::circuit::transactions::{transfer, Note, nullifier};


use rand::os::OsRng;
use rand::Rng;
use num::BigInt;
use num::Num as NumTrait;
use std::str::FromStr;

struct MerkleTreeAccumulator(Vec<Vec<Fr>>);

const PROOF_LENGTH:usize = 32;

lazy_static! {
    static ref JUBJUB_PARAMS: JubjubBls12 = JubjubBls12::new();
    static ref MERKLE_DEFAULTS: Vec<Fr> = {
        let mut c = Fr::zero();
        let mut res = vec![];
        for i in 0 .. PROOF_LENGTH+1 {
            res.push(c);
            c = pedersen_hasher::compress::<Bls12>(&c, &c,  Personalization::MerkleTree(i), &JUBJUB_PARAMS)
        }
        res
    };
}



impl MerkleTreeAccumulator {
    pub fn new() -> Self {
        let mut res = MerkleTreeAccumulator(vec![]);
        for _ in 0 .. PROOF_LENGTH+1 {
            res.0.push(vec![]);
        }
        res
    }

    pub fn cell(&self, row: usize, index: usize) -> Fr {
        assert!(row <= PROOF_LENGTH, "too big row");
        if index < self.0[row].len() {
            self.0[row][index]
        } else {
            MERKLE_DEFAULTS[row]
        }
    }

    pub fn size(&self) -> usize {
        self.0[0].len()
    }

    pub fn pushMany(&mut self, elements: &[Fr]) {
        let index = self.size();
        let s = elements.len();
        self.0[0].extend_from_slice(elements);

        for i in 1..PROOF_LENGTH+1 {
            let rl = self.0[i].len();
            self.0[i].extend(vec![Fr::zero(); 1 + (index+s>>i) - rl]);
            
            for j in (index >> i) .. (index+s>>i) + 1 {
                self.0[i][j] = pedersen_hasher::compress::<Bls12>(&self.cell(i-1, j*2), &self.cell(i-1, j*2+1), Personalization::MerkleTree(i-1), &JUBJUB_PARAMS);
            }
        }
    }

    pub fn root(&self) -> Fr {
        self.cell(PROOF_LENGTH, 0)
    }

    pub fn proof(&self, index: usize) -> Vec<Fr> {
        (0..PROOF_LENGTH).map(|i| self.cell(i, (index >> i) ^ 1)).collect::<Vec<Fr>>()
    }
}



fn gen_rand_fr_limited<R: ::rand::Rng>(n: usize, rng: &mut R) -> Fr {
    let f :Fr = rng.gen();
    if n == 256 {
        return f;
    }
    let mut f = f.into_repr();
    let i = n>>6;
    let j = n&63;

    let c = f.as_ref()[i];
    f.as_mut()[i] = c & ((1<< j)-1);

    for k in i + 1 .. 4 {
        f.as_mut()[k] = 0;
    }
    Fr::from_repr(f).unwrap()
}

fn rand_note<R: ::rand::Rng>(asset_id: Option<Fr>, amount: Option<Fr>, native_amount: Option<Fr>, txid:Option<Fr>, owner: Option<Fr>, rng: &mut R) -> NoteData<Bls12> {
    NoteData::<Bls12> {
        asset_id: asset_id.unwrap_or(gen_rand_fr_limited(64, rng)),
        amount: amount.unwrap_or(gen_rand_fr_limited(32, rng)),
        native_amount: native_amount.unwrap_or(gen_rand_fr_limited(32, rng)),
        txid: txid.unwrap_or(rng.gen()),
        owner: owner.unwrap_or(rng.gen())
    }
}





pub fn alloc_note_data<E: JubjubEngine, CS:ConstraintSystem<E>>(
    mut cs: CS, 
    data: Option<NoteData<E>>) -> Result<Note<E>, SynthesisError> {
        Ok(match data {
            Some(data) => {
                Note {
                    asset_id: AllocatedNum::alloc(cs.namespace(|| "alloc asset_id"), || Ok(data.asset_id)).unwrap(),
                    amount: AllocatedNum::alloc(cs.namespace(|| "alloc amount"), || Ok(data.amount)).unwrap(),
                    native_amount: AllocatedNum::alloc(cs.namespace(|| "alloc native_amount"), || Ok(data.native_amount)).unwrap(),
                    txid: AllocatedNum::alloc(cs.namespace(|| "alloc txid"), || Ok(data.txid)).unwrap(),
                    owner: AllocatedNum::alloc(cs.namespace(|| "alloc owner"), || Ok(data.owner)).unwrap()
                }
            },
            None => {
                Note {
                    asset_id: AllocatedNum::alloc(cs.namespace(|| "alloc asset_id"), || Err(SynthesisError::AssignmentMissing)).unwrap(),
                    amount: AllocatedNum::alloc(cs.namespace(|| "alloc amount"), || Err(SynthesisError::AssignmentMissing)).unwrap(),
                    native_amount: AllocatedNum::alloc(cs.namespace(|| "alloc native_amount"), || Err(SynthesisError::AssignmentMissing)).unwrap(),
                    txid: AllocatedNum::alloc(cs.namespace(|| "alloc txid"), || Err(SynthesisError::AssignmentMissing)).unwrap(),
                    owner: AllocatedNum::alloc(cs.namespace(|| "alloc owner"), || Err(SynthesisError::AssignmentMissing)).unwrap()
                }
            }
        })
}

pub fn alloc_proof_data<E: JubjubEngine, CS:ConstraintSystem<E>>(
    mut cs: CS, 
    data: Option<Vec<(E::Fr, bool)>>) -> Result<Vec<(AllocatedNum<E>, Boolean)>, SynthesisError> {
    Ok(match data {
        Some(data) => {
            data.iter().enumerate().map(|(i, (sibling, path))| 
                (
                    AllocatedNum::alloc(cs.namespace(|| format!("sibling[{}]", i)), || Ok(sibling.clone())).unwrap(),
                    Boolean::Is(AllocatedBit::alloc(cs.namespace(|| format!("path[{}]", i)), Some(path.clone())).unwrap())
                )
            ).collect::<Vec<(AllocatedNum<E>, Boolean)>>()
        },
        None => {
            (0..PROOF_LENGTH).map(|i| 
                (
                    AllocatedNum::alloc(cs.namespace(|| format!("sibling[{}]", i)), || Err(SynthesisError::AssignmentMissing)).unwrap(),
                    Boolean::Is(AllocatedBit::alloc(cs.namespace(|| format!("path[{}]", i)), None).unwrap())
                )
            ).collect::<Vec<(AllocatedNum<E>, Boolean)>>()
        }
    })
}





// Unoptimized, for test cases only

fn fr2big(a:Fr) -> BigInt {
    BigInt::from_str_radix(&format!("{}", a)[5..69], 16).unwrap() 
}

fn big2fr(a:BigInt) -> Fr {
    Fr::from_str(&format!("{}", a)).unwrap() 
}





#[test]
pub fn test_merkle_tree_struct(){
    let mut rng = OsRng::new().unwrap();
    let n_notes = 64;

    let note_hashes = (0..n_notes).map(|_| rng.gen()).collect::<Vec<_>>();
    let index = rng.gen_range(0, n_notes);

    let mut mt = MerkleTreeAccumulator::new();
    mt.pushMany(&note_hashes);
    let sibling = mt.proof(index as usize);
    let leaf_data = note_hashes[index];
    let cmp_root = crate::pedersen_hasher::merkle_root::<Bls12>(&sibling, index as u64, &leaf_data, &JUBJUB_PARAMS);
    assert!(cmp_root == mt.root(), "merkle proof results should be equal");
    
}





#[test]
pub fn test_merkle_proof(){
    let mut rng = OsRng::new().unwrap();
    let n_notes = 64;

    let note_hashes = (0..n_notes).map(|_| rng.gen()).collect::<Vec<_>>();
    let index = rng.gen_range(0, n_notes);
    let index_bits = (0..PROOF_LENGTH).map(|j| (index>>j) & 1 == 1).collect::<Vec<_>>();


    let mut mt = MerkleTreeAccumulator::new();
    mt.pushMany(&note_hashes);

    let mut cs = TestConstraintSystem::<Bls12>::new();
    let sibling = mt.proof(index as usize);
    let proof_data = sibling.iter().zip(index_bits.iter()).map(|(&f, &b)| (f, b)).collect::<Vec<_>>();
    let proof = alloc_proof_data(cs.namespace(|| "alloc proof {}"), Some(proof_data)).unwrap();

    let leaf_data = note_hashes[index];
    let leaf = AllocatedNum::alloc(cs.namespace(|| "alloc leaf"), || Ok(leaf_data)).unwrap();

    let res = merkle_proof::merkle_proof(cs.namespace(|| "exec merkle proof"), &proof, &leaf, &JUBJUB_PARAMS).unwrap();
    if !cs.is_satisfied() {
        let not_satisfied = cs.which_is_unsatisfied().unwrap_or("");
        assert!(false, format!("Constraints not satisfied: {}", not_satisfied));
    }
    assert!(crate::pedersen_hasher::merkle_root::<Bls12>(&sibling, index as u64, &leaf_data, &JUBJUB_PARAMS) == res.get_value().unwrap(), "merkle proof results should be equal");
}




#[test]
fn test_transaction() {
    let mut rng = OsRng::new().unwrap();

    let n_notes = 64;
    let sk_data: Fr = rng.gen();
    let pk = pubkey::<Bls12>(&sk_data, &JUBJUB_PARAMS);

    let notes = (0..n_notes).map(|_| rand_note(Some(Fr::zero()), None, None, None, Some(pk), &mut rng)).collect::<Vec<_>>();

    let note_hashes = notes.iter().map(|n| note_hash::<Bls12>(n, &JUBJUB_PARAMS)).collect::<Vec<_>>();

    let mut mt = MerkleTreeAccumulator::new();
    mt.pushMany(&note_hashes);

    let i0 = rng.gen_range(0, n_notes);
    let i1 = rng.gen_range(0, n_notes-1);

    let indexes = [i0, if i1 < i0 {i1} else {i1+1}];
    let indexes_bits = indexes.iter().map(|i| (0..PROOF_LENGTH).map(|j| (i>>j) & 1 == 1).collect::<Vec<_>>());

    let mut cs = TestConstraintSystem::<Bls12>::new();

    let in_note_data = indexes.iter().map(|&i| notes[i].clone()).collect::<Vec<_>>();
    let in_note = in_note_data.iter().enumerate().map(|(i, note)| alloc_note_data(cs.namespace(|| format!("alloc in_note {}", i)), Some(note.clone())).unwrap()).collect::<Vec<_>>();
    
    let in_proof = indexes.iter().zip(indexes_bits).map(|(&i, bits)| {
        let proof = mt.proof(i as usize).iter().zip(bits.iter()).map(|(&f, &b)| (f, b)).collect::<Vec<_>>();
        alloc_proof_data(cs.namespace(|| format!("alloc in_proof {}", i)), Some(proof)).unwrap()
    }).collect::<Vec<_>>();

    let all_amount = fr2big(notes[indexes[0]].amount.clone()) + fr2big(notes[indexes[1]].amount.clone());
    
    let all_native_amount = fr2big(notes[indexes[0]].native_amount.clone()) + fr2big(notes[indexes[1]].native_amount.clone());


    let all_amount_p1 = &all_amount/BigInt::from(7);
    let all_native_amount_p1 = &all_amount/BigInt::from(5);

    let all_amount_p2 = &all_amount/BigInt::from(5);
    let all_native_amount_p2 = &all_amount/BigInt::from(3);


    let out_note_data = [
        rand_note(Some(Fr::zero()), Some(big2fr(&all_amount - &all_amount_p1 + &all_amount_p2)), Some(big2fr(&all_native_amount - &all_native_amount_p1 + &all_native_amount_p2)), None, None, &mut rng),
        rand_note(Some(Fr::zero()), Some(big2fr(all_amount_p1.clone())), Some(big2fr(all_native_amount_p1.clone())), None, None, &mut rng)
    ];

    let out_note = out_note_data.iter().enumerate().map(|(i, note)| alloc_note_data(cs.namespace(|| format!("alloc out_note {}", i)), Some(note.clone())).unwrap()).collect::<Vec<_>>();

    let sk = AllocatedNum::alloc(cs.namespace(|| "alloc sk"), || Ok(sk_data)).unwrap();
    
    let packed_asset_bn = (all_native_amount_p2<< 128) + (all_amount_p2<< 64);

    let packed_asset = AllocatedNum::alloc(cs.namespace(|| "alloc packed_asset"), || Ok(big2fr(packed_asset_bn))).unwrap();
    let root_hash =  AllocatedNum::alloc(cs.namespace(|| "alloc root_hash"), || Ok(mt.root())).unwrap();

    let (out_hash, nf) = transfer(cs.namespace(||"exec transfer"), &in_note, &in_proof, &out_note, &root_hash, &sk, &packed_asset, &JUBJUB_PARAMS).unwrap();

    if !cs.is_satisfied() {
        let not_satisfied = cs.which_is_unsatisfied().unwrap_or("");
        assert!(false, format!("Constraints not satisfied: {}", not_satisfied));
    }

    let nf_computed = in_note_data.iter().map(|note| {
        let hash = crate::transactions::note_hash(note, &JUBJUB_PARAMS);
        crate::transactions::nullifier::<Bls12>(&hash, &sk_data, &JUBJUB_PARAMS)
    });

    let out_hash_computed = out_note_data.iter().map(|note| crate::transactions::note_hash(note, &JUBJUB_PARAMS));

    assert!(out_hash.iter().zip(out_hash_computed).all(|(a, b)| a.get_value().unwrap() == b), "out hashes should be the same");
    assert!(nf.iter().zip(nf_computed).all(|(a, b)| a.get_value().unwrap() == b), "nullifiers should be the same");

}





#[test]
fn test_transaction_withdraw() {
    let mut rng = OsRng::new().unwrap();

    let n_notes = 64;
    let sk_data: Fr = rng.gen();
    let pk = pubkey::<Bls12>(&sk_data, &JUBJUB_PARAMS);

    let notes = (0..n_notes).map(|_| rand_note(Some(Fr::zero()), None, None, None, Some(pk), &mut rng)).collect::<Vec<_>>();

    let note_hashes = notes.iter().map(|n| note_hash::<Bls12>(n, &JUBJUB_PARAMS)).collect::<Vec<_>>();

    let mut mt = MerkleTreeAccumulator::new();
    mt.pushMany(&note_hashes);

    let i0 = rng.gen_range(0, n_notes);
    let i1 = rng.gen_range(0, n_notes-1);

    let indexes = [i0, if i1 < i0 {i1} else {i1+1}];
    let indexes_bits = indexes.iter().map(|i| (0..PROOF_LENGTH).map(|j| (i>>j) & 1 == 1).collect::<Vec<_>>());

    let mut cs = TestConstraintSystem::<Bls12>::new();

    let in_note_data = indexes.iter().map(|&i| notes[i].clone()).collect::<Vec<_>>();
    let in_note = in_note_data.iter().enumerate().map(|(i, note)| alloc_note_data(cs.namespace(|| format!("alloc in_note {}", i)), Some(note.clone())).unwrap()).collect::<Vec<_>>();
    
    let in_proof = indexes.iter().zip(indexes_bits).map(|(&i, bits)| {
        let proof = mt.proof(i as usize).iter().zip(bits.iter()).map(|(&f, &b)| (f, b)).collect::<Vec<_>>();
        alloc_proof_data(cs.namespace(|| format!("alloc in_proof {}", i)), Some(proof)).unwrap()
    }).collect::<Vec<_>>();

    let all_amount = fr2big(notes[indexes[0]].amount.clone()) + fr2big(notes[indexes[1]].amount.clone());
    
    let all_native_amount = fr2big(notes[indexes[0]].native_amount.clone()) + fr2big(notes[indexes[1]].native_amount.clone());


    let all_amount_p1 = &all_amount/BigInt::from(7);
    let all_native_amount_p1 = &all_amount/BigInt::from(5);

    let all_amount_p2 = &all_amount/BigInt::from(-5);
    let all_native_amount_p2 = &all_amount/BigInt::from(-3);


    let out_note_data = [
        rand_note(Some(Fr::zero()), Some(big2fr(&all_amount - &all_amount_p1 + &all_amount_p2)), Some(big2fr(&all_native_amount - &all_native_amount_p1 + &all_native_amount_p2)), None, None, &mut rng),
        rand_note(Some(Fr::zero()), Some(big2fr(all_amount_p1.clone())), Some(big2fr(all_native_amount_p1.clone())), None, None, &mut rng)
    ];

    let out_note = out_note_data.iter().enumerate().map(|(i, note)| alloc_note_data(cs.namespace(|| format!("alloc out_note {}", i)), Some(note.clone())).unwrap()).collect::<Vec<_>>();

    let sk = AllocatedNum::alloc(cs.namespace(|| "alloc sk"), || Ok(sk_data)).unwrap();

    let u64num = BigInt::from_str("18446744073709551616").unwrap();
    
    let packed_asset_bn = ((&u64num+&all_native_amount_p2)<< 128) + ((&u64num+&all_amount_p2)<< 64);

    let packed_asset = AllocatedNum::alloc(cs.namespace(|| "alloc packed_asset"), || Ok(big2fr(packed_asset_bn))).unwrap();
    let root_hash =  AllocatedNum::alloc(cs.namespace(|| "alloc root_hash"), || Ok(mt.root())).unwrap();

    let (out_hash, nf) = transfer(cs.namespace(||"exec transfer"), &in_note, &in_proof, &out_note, &root_hash, &sk, &packed_asset, &JUBJUB_PARAMS).unwrap();

    if !cs.is_satisfied() {
        let not_satisfied = cs.which_is_unsatisfied().unwrap_or("");
        assert!(false, format!("Constraints not satisfied: {}", not_satisfied));
    }

    let nf_computed = in_note_data.iter().map(|note| {
        let hash = crate::transactions::note_hash(note, &JUBJUB_PARAMS);
        crate::transactions::nullifier::<Bls12>(&hash, &sk_data, &JUBJUB_PARAMS)
    });

    let out_hash_computed = out_note_data.iter().map(|note| crate::transactions::note_hash(note, &JUBJUB_PARAMS));

    assert!(out_hash.iter().zip(out_hash_computed).all(|(a, b)| a.get_value().unwrap() == b), "out hashes should be the same");
    assert!(nf.iter().zip(nf_computed).all(|(a, b)| a.get_value().unwrap() == b), "nullifiers should be the same");

}


#[test]
fn test_nullifier() -> Result<(), SynthesisError> {
    let rng = &mut OsRng::new().unwrap();
    let params = JubjubBls12::new();


    let mut cs = TestConstraintSystem::<Bls12>::new();

    let nh = rng.gen::<Fr>();
    let sk = rng.gen::<Fr>();


    let nf = crate::transactions::nullifier::<Bls12>(&nh, &sk, &params);


    let nh_a = AllocatedNum::alloc(cs.namespace(|| "var nh_a"), || Ok(nh))?;
    let sk_a = AllocatedNum::alloc(cs.namespace(|| "var sk_a"), || Ok(sk))?;
    let sk_bits = sk_a.into_bits_le_strict(cs.namespace(|| "var sk_bits"))?;

    let nf_a = nullifier(&mut cs, &nh_a, &sk_bits, &params)?;

    if !cs.is_satisfied() {
        let not_satisfied = cs.which_is_unsatisfied().unwrap_or("");
        assert!(false, format!("Constraints not satisfied: {}", not_satisfied));
    }
    assert!(nf_a.get_value().unwrap() == nf, "Nf value should be the same");

    Ok(())
}