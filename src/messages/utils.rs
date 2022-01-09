#[doc(hidden)]
#[macro_export]
macro_rules! standard_roundtrip {
    ($name: ident, $t: ty) => {
        proptest! {
            #[test]
            fn $name(xs: $t) {
                let mut buffer = vec![];
                task::block_on(xs.write(&mut buffer)).unwrap();
                let mut cursor = Cursor::new(buffer);
                let ys = <$t>::read(&mut cursor);
                assert_eq!(xs, task::block_on(ys).unwrap());
            }
        }
    };
}
