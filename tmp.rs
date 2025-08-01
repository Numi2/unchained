
use std::any::TypeId;

fn main() {
    let vec = vec![1u8,2,3];
    if TypeId::of::<Vec<u8>>() == TypeId::of::<Vec<u8>>() {
        let x = unsafe { std::mem::transmute::<Vec<u8>, Vec<u8>>(vec) };
        println!("{:?}", x);
    }
}
