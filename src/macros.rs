use std::{
    io::{Error as IoError, ErrorKind},
    ptr::null_mut,
    any::type_name,
    slice,
    convert::TryInto
};

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(C)]
pub enum CctpErrorCode {
    OK,
    NullPtr,
    InvalidValue,
    InvalidBufferData,
    InvalidBufferLength,
    CompressError,
    UncompressError,
    MerkleRootBuildError,
    GenericError
}

#[repr(C)]
pub struct BufferWithSize {
    data: *mut u8,
    len: usize,
}

/// Check that `buffer` it's a valid buffer with non-zero data
pub(crate) fn check_buffer(buffer: *const BufferWithSize) -> (bool, CctpErrorCode)
{
    if buffer.is_null() {
        //println!("===> ERR CODE {:?}", CctpErrorCode::NullPtr);
        return (false, CctpErrorCode::NullPtr)
    }

    let data_attr = unsafe { (*buffer).data };
    if data_attr.is_null() {
        //println!("===> ERR CODE {:?}", CctpErrorCode::InvalidBufferData);
        return (false, CctpErrorCode::InvalidBufferData)
    }

    let len_attr = unsafe { (*buffer).len };
    if len_attr == 0 {
        //println!("===> ERR CODE {:?}", CctpErrorCode::InvalidBufferLength);
        return (false, CctpErrorCode::InvalidBufferLength)
    }

    (true, CctpErrorCode::OK)
}

/// Check that `buffer` it's a valid buffer with non-zero data
/// whose length must be equal to `len`.
pub(crate) fn check_buffer_length(buffer: *const BufferWithSize, len: usize) -> (bool, CctpErrorCode)
{
    let (is_ok, err) = check_buffer(buffer);
    if !is_ok { return (false, err) }

    let len_attr = unsafe { (*buffer).len };
    if len_attr != len {
        println!("===> ERR: buf_len={}, expected={}", len_attr, len);
        return (false, CctpErrorCode::InvalidBufferLength)
    }

    (true, CctpErrorCode::OK)
}


pub(crate) fn free_buffer_with_size(buffer: *mut BufferWithSize) {
    unsafe {
        let buffer = Box::from_raw(buffer);
        Vec::from_raw_parts((*buffer).data, (*buffer).len, (*buffer).len);
    };
}

/// Convert a BufferWithSize to a &[u8], considering that `in_buffer`
/// might be null, and enforces that its length is equal to `checked_len`.
pub(crate) fn get_optional_buffer_constant_size<'a>(in_buffer: *const BufferWithSize, checked_len: usize) -> (Option<&'a [u8]>, CctpErrorCode) {
    let (is_ok, _ret_code) = check_buffer_length(in_buffer, checked_len);
    if !is_ok {
        return (None, CctpErrorCode::OK);
    }
    let optional_data = Some(unsafe {
        if (*in_buffer).len != checked_len
        {
            return (None, CctpErrorCode::InvalidBufferLength);
        }
        slice::from_raw_parts((*in_buffer).data, (*in_buffer).len)
    });
    (optional_data, CctpErrorCode::OK)
}

macro_rules! try_get_optional_buffer_constant_size {
    ($in_buffer:expr, $checked_len:expr, $ret_code:expr, $err_ret:expr) => {{
        let (optional_data, ret_code) = get_optional_buffer_constant_size($in_buffer, $checked_len);
        *$ret_code = ret_code;
        if ret_code != CctpErrorCode::OK {
            dbg!(ret_code);
            return $err_ret;
        }
        match optional_data {
            Some(optional_data) => Some(optional_data.try_into().unwrap()),
            None => None,
        }
    }};
}

/// Convert a BufferWithSize to a &[u8], considering that `in_buffer`
/// and enforces that its length is equal to `checked_len`.
pub(crate) fn get_buffer_constant_size<'a>(in_buffer: *const BufferWithSize, checked_len: usize) -> (Option<&'a [u8]>, CctpErrorCode) {
    let (is_ok, ret_code) = check_buffer_length(in_buffer, checked_len);
    if !is_ok {
        return (None, ret_code);
    }
    let data = Some(unsafe { slice::from_raw_parts((*in_buffer).data, (*in_buffer).len)});
    (data, CctpErrorCode::OK)
}

macro_rules! try_get_buffer_constant_size {
    ($in_buffer:expr, $checked_len:expr, $ret_code:expr, $err_ret:expr) => {{
        let (data, ret_code) = get_buffer_constant_size($in_buffer, $checked_len);
        *$ret_code = ret_code;

        match data {
            Some(x) => {x.try_into().unwrap()}
            None => {
                dbg!(ret_code);
                return $err_ret;
            }
        }
    }};
}

/// Convert a BufferWithSize to a &[u8].
pub(crate) fn get_buffer_variable_size<'a>(in_buffer: *const BufferWithSize) -> (Option<&'a [u8]>, CctpErrorCode) {
    let (is_ok, ret_code) = check_buffer(in_buffer);
    if !is_ok {
        return (None, ret_code);
    }
    let data = Some(unsafe { slice::from_raw_parts((*in_buffer).data, (*in_buffer).len)});
    (data, CctpErrorCode::OK)
}

macro_rules! try_get_buffer_variable_size {
    ($in_buffer:expr, $ret_code:expr, $err_ret:expr) => {{
        let (data, ret_code) = get_buffer_variable_size($in_buffer);
        *$ret_code = ret_code;

        match data {
            Some(x) => {x}
            None => {
                dbg!(ret_code);
                return $err_ret;
            }
        }
    }};
}

/// Convert a BufferWithSize to a &[u8], considering that `in_buffer` might be null
pub(crate) fn get_optional_buffer_variable_size<'a>(in_buffer: *const BufferWithSize) -> (Option<&'a [u8]>, CctpErrorCode) {
    let (is_ok, _ret_code) = check_buffer(in_buffer);
    if !is_ok {
        return (None, CctpErrorCode::OK);
    }
    let optional_data = Some(unsafe {
        slice::from_raw_parts((*in_buffer).data, (*in_buffer).len)
    });
    (optional_data, CctpErrorCode::OK)
}

macro_rules! try_get_optional_buffer_variable_size {
    ($in_buffer:expr, $ret_code:expr, $err_ret:expr) => {{
        let (optional_data, ret_code) = get_optional_buffer_variable_size($in_buffer);
        *$ret_code = ret_code;
        if ret_code != CctpErrorCode::OK {
            dbg!(ret_code);
            return $err_ret;
        }
        optional_data
    }};
}

/// Convert a *const T to a &[T].
pub(crate) fn get_obj_list<'a, T>(in_list: *const T, in_list_size: usize) -> (Option<&'a [T]>, CctpErrorCode) {
    if in_list.is_null() {
        return (None, CctpErrorCode::NullPtr)
    }

    let data = Some(unsafe { slice::from_raw_parts(in_list, in_list_size)});
    (data, CctpErrorCode::OK)
}

macro_rules! try_get_obj_list {
    ($in_list:expr, $in_list_size:expr, $ret_code: expr, $err_ret:expr) => {{
        let (data, ret_code) = get_obj_list($in_list, $in_list_size);
        *$ret_code = ret_code;

        match data {
            Some(x) => {x}
            None => {
                dbg!(ret_code);
                return $err_ret;
            }
        }
    }};
}

/// Convert a *const T to a &[T] considering that `in_list` might be null.
pub(crate) fn get_optional_obj_list<'a, T>(in_list: *const T, in_list_size: usize) -> (Option<&'a [T]>, CctpErrorCode) {
    if in_list.is_null() {
        return (None, CctpErrorCode::OK)
    }
    let data = Some(unsafe { slice::from_raw_parts(in_list, in_list_size)});
    (data, CctpErrorCode::OK)
}

macro_rules! try_get_optional_obj_list {
    ($in_list:expr, $in_list_size:expr, $ret_code: expr, $err_ret: expr) => {{
        let (optional_data, ret_code) = get_obj_list($in_list, $in_list_size);
        *$ret_code = ret_code;

        if ret_code != CctpErrorCode::OK {
            dbg!(ret_code);
            return $err_ret;
        }
        optional_data
    }};
}

pub(crate) fn get_constant_length_buffers_list<'a>(
    buff_list: *const BufferWithSize,
    buff_list_size: usize,
    single_buff_checked_size: usize,
) -> (Option<Vec<&'a [u8]>>, CctpErrorCode)
{
    let ret_code = CctpErrorCode::OK;

    // First read a list of BufferWithSize structs
    let (bws_list, ret_code) = get_obj_list(buff_list, buff_list_size);
    if ret_code != CctpErrorCode::OK {
        return (None, ret_code);
    }
    let bws_list = bws_list.unwrap();

    // Then, read the byte array inside each BufferWithSize
    let mut final_buff = Vec::with_capacity(buff_list_size);
    for bws in bws_list {

        if bws.data.is_null() {
            return (None, CctpErrorCode::InvalidBufferData)
        }

        if bws.len != single_buff_checked_size {
            println!("===> ERR: buf_len={}, expected={}", bws.len, single_buff_checked_size);
            return (None, CctpErrorCode::InvalidBufferLength)
        }

        let buff = unsafe { slice::from_raw_parts( bws.data, bws.len )};
        final_buff.push(buff);
    }

    (Some(final_buff), CctpErrorCode::OK)
}

macro_rules! try_get_constant_length_buffers_list {
    ($buff_list:expr, $buff_list_size:expr, $single_buff_checked_size: expr, $ret_code: expr, $err_ret: expr) => {{
        let (data, ret_code) = get_constant_length_buffers_list($buff_list, $buff_list_size, $single_buff_checked_size);
        *$ret_code = ret_code;

        match data {
            Some(x) => {x}
            None => {
                dbg!(ret_code);
                return $err_ret;
            }
        }
    }};
}

pub(crate) fn get_optional_constant_length_buffers_list<'a>(
    buff_list: *const BufferWithSize,
    buff_list_size: usize,
    single_buff_checked_size: usize,
) -> (Option<Vec<&'a [u8]>>, CctpErrorCode)
{
    let ret_code = CctpErrorCode::OK;

    // First read a list of BufferWithSize structs
    let (bws_list, ret_code) = get_optional_obj_list(buff_list, buff_list_size);

    // Either an error or the list is not present
    if ret_code != CctpErrorCode::OK || bws_list.is_none() {
        return (None, ret_code);
    }

    let bws_list = bws_list.unwrap();

    // Then, read the byte array inside each BufferWithSize
    let mut final_buff = Vec::with_capacity(buff_list_size);
    for bws in bws_list {

        if bws.data.is_null() {
            return (None, CctpErrorCode::InvalidBufferData)
        }

        if bws.len != single_buff_checked_size {
            println!("===> ERR: buf_len={}, expected={}", bws.len, single_buff_checked_size);
            return (None, CctpErrorCode::InvalidBufferLength)
        }

        let buff = unsafe { slice::from_raw_parts( bws.data, bws.len )};
        final_buff.push(buff);
    }

    (Some(final_buff), CctpErrorCode::OK)
}

macro_rules! try_get_optional_constant_length_buffers_list {
    ($buff_list:expr, $buff_list_size:expr, $single_buff_checked_size: expr, $ret_code:expr, $err_ret:expr) => {{
        let (optional_data, ret_code) = get_optional_constant_length_buffers_list($buff_list, $buff_list_size, $single_buff_checked_size);
        *$ret_code = ret_code;

        if ret_code != CctpErrorCode::OK {
            dbg!(ret_code);
            return $err_ret;
        }
        optional_data
    }};
}

pub(crate) fn read_raw_pointer<'a, T>(input: *const T) -> (Option<&'a T>, CctpErrorCode) {
    if input.is_null() {
        return (None, CctpErrorCode::NullPtr);
    }
    (Some(unsafe { &*input }), CctpErrorCode::OK)
}

macro_rules! try_read_raw_pointer {
    ($input:expr, $ret_code:expr, $err_ret:expr) => {{
        let (data, ret_code) = read_raw_pointer($input);
        *$ret_code = ret_code;

        match data {
            Some(x) => {x}
            None => {
                dbg!(ret_code);
                return $err_ret;
            }
        }
    }};
}

pub(crate) fn read_mut_raw_pointer<'a, T>(input: *mut T) -> (Option<&'a mut T>, CctpErrorCode) {
    if input.is_null() {
        return (None, CctpErrorCode::NullPtr);
    }
    (Some(unsafe { &mut *input }), CctpErrorCode::OK)
}

macro_rules! try_read_mut_raw_pointer {
    ($input:expr, $ret_code:expr, $err_ret:expr) => {{
        let (data, ret_code) = read_mut_raw_pointer($input);
        *$ret_code = ret_code;

        match data {
            Some(x) => {x}
            None => {
                dbg!(ret_code);
                return $err_ret;
            }
        }
    }};
}