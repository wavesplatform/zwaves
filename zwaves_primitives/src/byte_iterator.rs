#[derive(Debug)]
pub struct ByteIteratorLe<E> {
  t: E,
  n: usize,
  len: usize,
}

impl<E: AsRef<[u64]>> ByteIteratorLe<E> {
    pub fn new(t: E) -> Self {
        let len = t.as_ref().len() * 8;
        ByteIteratorLe { t, n: 0, len }
    }
}

impl<E: AsRef<[u64]>> Iterator for ByteIteratorLe<E> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        if self.n == self.len {
        None
        } else {
        let part = self.n / 8;
        let byte = self.n - (8 * part);
        self.n += 1;

        Some(((self.t.as_ref()[part] >> (8*byte)) & 0xFF) as u8)
        }
    }
}


