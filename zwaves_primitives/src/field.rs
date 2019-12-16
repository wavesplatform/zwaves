use pairing::{PrimeField, PrimeFieldRepr};
use itertools::Itertools;

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

    let mut red = P::char().clone();
    for i in 0..rem_bits {
        red.add_nocarry(&red.clone());
    }

    for i in 0 .. rem_bits+1 {
        if fr_repr_cmp(&x, &red) == ::std::cmp::Ordering::Less {
            break;
        }
        x.sub_noborrow(&red);
        if i!=rem_bits {
            red.shr(1);
        }
    }
    P::from_repr(x).unwrap()
}

pub fn fr_to_repr_u64<P:PrimeField>(x: &P) -> impl IntoIterator<Item=u64> {
    let mut repr = x.into_repr();
    unsafe {
        let l = repr.as_ref().len();
        let z = repr.as_mut().as_mut_ptr();
        ::core::mem::forget(repr);
        Vec::from_raw_parts(z, l, l)
    }
}


pub fn fr_to_repr_u8<P:PrimeField>(x: &P) -> impl IntoIterator<Item=u8> {
    let mut repr = x.into_repr();
    unsafe {
        let l = repr.as_ref().len();
        let z = repr.as_mut().as_mut_ptr();
        ::core::mem::forget(repr);
        Vec::from_raw_parts(z, l, l).into_iter()
            .flat_map(|x| (0..64).step_by(8).map(move |i| ((x >> i) & 0xff) as u8))
    }
}


pub fn fr_to_repr_bool<P:PrimeField>(x: &P) -> impl IntoIterator<Item=bool> {
    let mut repr = x.into_repr();
    unsafe {
        let l = repr.as_ref().len();
        let z = repr.as_mut().as_mut_ptr();
        ::core::mem::forget(repr);
        Vec::from_raw_parts(z, l, l).into_iter()
            .flat_map(|x| (0..64).map(move |i| (x >> i) > 0))
    }
}


pub fn repr_u64_to_fr<'a, I:IntoIterator<Item=&'a u64>, P:PrimeField>(r:I) -> P {
    let mut res = P::char();
    res.as_mut().iter_mut().zip(r).for_each(|(a, b)| *a = *b);
    affine(res)
}


pub fn repr_u8_to_fr<'a, I:IntoIterator<Item=&'a u8>, P:PrimeField>(r:I) -> P {
    let mut res = P::char();
    let r = r.into_iter().chunks(8).into_iter().map(|c| c.fold(0u64, |x, &y| (x<<8) + y as u64));
    res.as_mut().iter_mut().zip(r).for_each(|(a, b)| *a = b);
    affine(res)
}


pub fn repr_bool_to_fr<'a, I:IntoIterator<Item=&'a bool>, P:PrimeField>(r:I) -> P {
    let mut res = P::char();
    let r = r.into_iter().chunks(64).into_iter().map(|c| c.fold(0u64, |x, &y| (x<<1) + y as u64));
    res.as_mut().iter_mut().zip(r).for_each(|(a, b)| *a = b);
    affine(res)
}


