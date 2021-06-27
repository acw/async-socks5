#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

#[cfg(test)]
pub fn arbitrary_socks_string(g: &mut Gen) -> String {
    loop {
        let mut potential = String::arbitrary(g);

        potential.truncate(255);
        let bytestring = potential.as_bytes();

        if bytestring.len() > 0 && bytestring.len() < 256 {
            return potential;
        }
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! standard_roundtrip {
    ($name: ident, $t: ty) => {
        #[cfg(test)]
        quickcheck! {
            fn $name(xs: $t) -> bool {
                let mut buffer = vec![];
                task::block_on(xs.write(&mut buffer)).unwrap();
                let mut cursor = Cursor::new(buffer);
                let ys = <$t>::read(Pin::new(&mut cursor));
                xs == task::block_on(ys).unwrap()
            }
        }
    };
}
