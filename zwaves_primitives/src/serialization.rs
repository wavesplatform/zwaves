use pairing::{Engine, PrimeField, Field, PrimeFieldRepr};


use std::{mem, io, iter};
use std::io::{Read, Write};
use byteorder::{BigEndian, ReadBytesExt};



pub fn read_fr_repr_be<Fr:PrimeField>(data: &[u8]) -> io::Result<Fr::Repr> {
    let mut fr_repr = Fr::zero().into_repr();

    match fr_repr.read_be(data) {
        Err(e) => return Err(e),
        _ => {}
    }
    Ok(fr_repr)
}

pub fn read_fr_vec<Fr:PrimeField>(data: &[u8]) -> io::Result<Vec<Fr>> {
    let mut inputs = vec![];
    
    let mut offset = 0;
    let fr_repr_sz = mem::size_of::<Fr::Repr>();

    loop {
        let fr_repr =  match read_fr_repr_be::<Fr>(&data[offset..]) {
            Ok(x) => x,
            _ => break
        };

        offset+=fr_repr_sz;
        let fr = Fr::from_repr(fr_repr).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, "not in field"))?;
        inputs.push(fr);
    }

    Ok(inputs)
}

pub fn write_fr_iter<'a, I, Fr>(source: I, data: &mut [u8]) -> io::Result<()> where Fr:PrimeField, I: IntoIterator<Item = &'a Fr> {
    let fr_repr_sz = mem::size_of::<Fr::Repr>();
    for (i, e) in source.into_iter().enumerate() {
        e.into_repr().write_be(&mut data[fr_repr_sz*i ..])?;
    }
    Ok(())
}