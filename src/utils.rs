use algebra::{CanonicalDeserialize, SemanticallyValid, CanonicalSerialize};
use cctp_primitives::utils::serialization::{deserialize_from_buffer_checked, deserialize_from_buffer};
use crate::error::{set_last_error, IO_ERROR};
use crate::macros::read_raw_pointer;
use std::{
    io::{Error as IoError, ErrorKind},
    ptr::null_mut,
    any::type_name,
    slice,
};

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

pub(crate) fn deserialize_to_raw_pointer<T: CanonicalDeserialize + SemanticallyValid>(buffer: &[u8], checked: bool) -> *mut T {

    match if checked {
        deserialize_from_buffer_checked(buffer)
    } else {
        deserialize_from_buffer(buffer)
    }{
        Ok(t) => Box::into_raw(Box::new(t)),
        Err(_) => {
            let e = IoError::new(
                ErrorKind::InvalidData,
                format!("unable to read {} from buffer", type_name::<T>()),
            );
            set_last_error(Box::new(e), IO_ERROR);
            return null_mut();
        }
    }
}

pub(crate) fn serialize_from_raw_pointer<T: CanonicalSerialize>(
    to_write: *const T,
    buffer: &mut [u8],
) {
    CanonicalSerialize::serialize(read_raw_pointer(to_write), buffer)
        .expect(format!("unable to write {} to buffer", type_name::<T>()).as_str())
}

pub(crate)  fn free_pointer<T> (ptr: *mut T) {
    if ptr.is_null() { return };

    unsafe { drop( Box::from_raw(ptr)) }
}