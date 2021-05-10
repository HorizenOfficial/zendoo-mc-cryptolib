use std::slice;

#[allow(dead_code)]
pub(crate) fn read_double_raw_pointer<T: Copy>(
    input: *const *const T,
    input_len: usize,
) -> Vec<T> {

    //Read *const T from *const *const T
    assert!(!input.is_null());
    let input_raw = unsafe { slice::from_raw_parts(input, input_len) };

    //Read T from *const T
    let mut input = vec![];
    for &ptr in input_raw.iter() {
        assert!(!ptr.is_null());
        input.push(unsafe { *ptr });
    }
    input
}

pub(crate)  fn free_pointer<T> (ptr: *mut T) {
    if ptr.is_null() { return };

    unsafe { drop( Box::from_raw(ptr)) }
}