use pairing::{PrimeField, Field, PrimeFieldRepr};
use itertools::Itertools;
use std::mem::transmute;


#[derive(Debug)]
pub struct FrReprIterator<R:PrimeFieldRepr> {
    pub data : R,
    size : usize,
    pos : usize
}

impl<R:PrimeFieldRepr> FrReprIterator<R> {
    pub fn new(data:R) -> Self {
        let size = data.as_ref().len();
        Self {
            data,
            size,
            pos: 0 as usize
        }
    }
}

impl<R:PrimeFieldRepr> Iterator for FrReprIterator<R> {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        if self.pos == self.size {
            None
        } else {
            let res = Some(self.data.as_ref()[self.pos]);
            self.pos += 1;
            res
        }
    }
}





pub fn fr_repr_cmp<R:PrimeFieldRepr>(x: &R, y: &R) -> ::std::cmp::Ordering {
    for (a, b) in x.as_ref().iter().rev().zip(y.as_ref().iter().rev()) {
        if a < b {
            return ::std::cmp::Ordering::Less;
        } else if a > b {
            return ::std::cmp::Ordering::Greater;
        }
    }
    ::std::cmp::Ordering::Equal
}




pub fn affine<P:PrimeField>(mut x: P::Repr) -> P {


    let nlimbs = P::char().as_ref().len();
    let rem_bits = nlimbs*64 - P::NUM_BITS as usize;

    let mut red = P::char();
    for _ in 0..rem_bits {
        red.add_nocarry(&red.clone());
    }

    for i in 0 .. rem_bits+1 {
        if fr_repr_cmp(&x, &red) != ::std::cmp::Ordering::Less {
            x.sub_noborrow(&red);
        }
        
        if i!=rem_bits {
            red.shr(1);
        }
    }
    P::from_repr(x).unwrap()
}


pub fn f2f<A:PrimeField, B:PrimeField>(x:&A) -> B 
{
    let mut repr = B::char();
    repr.as_mut().iter_mut().zip(x.into_repr().as_ref().iter()).for_each(|(r, s)| *r = *s);
    affine(repr)
}




pub fn fr_to_repr_u64<P:PrimeField>(x: &P) -> impl IntoIterator<Item=u64> {
    FrReprIterator::new(x.into_repr())
}


pub fn fr_to_repr_u8<P:PrimeField>(x: &P) -> impl IntoIterator<Item=u8> {
    FrReprIterator::new(x.into_repr()).flat_map(|x| (0..64).step_by(8).map(move |i| ((x >> i) & 0xff) as u8))
}


pub fn fr_to_repr_bool<P:PrimeField>(x: &P) -> impl IntoIterator<Item=bool> {
    FrReprIterator::new(x.into_repr()).flat_map(|x| (0..64).map(move |i| ((x >> i) & 1) > 0))
}


pub fn repr_u64_to_fr<'a, I:IntoIterator<Item=&'a u64>, P:PrimeField>(r:I) -> P {
    let mut res = P::char();
    res.as_mut().iter_mut().zip(r).for_each(|(a, b)| *a = *b);
    affine(res)
}


pub fn repr_u8_to_fr<'a, I:IntoIterator<Item=&'a u8>, P:PrimeField>(r:I) -> P {
    let mut res = P::char();
    let chunks = r.into_iter().chunks(8);
    let r = chunks.into_iter().map(|c| c.fold(0u64, |x, &y| (x<<8) + y as u64));
    res.as_mut().iter_mut().zip(r).for_each(|(a, b)| *a = b);
    affine(res)
}


pub fn repr_bool_to_fr<'a, I:IntoIterator<Item=&'a bool>, P:PrimeField>(r:I) -> P {
    let mut res = P::char();
    let chunks = r.into_iter().chunks(64);
    let r = chunks.into_iter().map(|c| c.fold(0u64, |x, &y| (x<<1) + y as u64));
    res.as_mut().iter_mut().zip(r).for_each(|(a, b)| *a = b);
    affine(res)
}

#[cfg(test)]
mod fieldtools_tests {
    use super::*;
    use pairing::bls12_381::{Fr};

    #[test]
    fn test_fr_to_repr_bool() {
        let f = Fr::one();
        let v = fr_to_repr_u64(&f);

        assert!(v.into_iter().enumerate().all(|(i,x)| (i > 0) ^ (x == 1) ), "Should be converted into 1, 0, 0, 0, ...");
    }

}


