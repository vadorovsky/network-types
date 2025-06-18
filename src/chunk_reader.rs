use core::ptr;

/// Errors that can occur during parsing or optional header chunks
#[derive(Debug, PartialEq, Eq)]
pub enum ChunkReaderError {
    /// The attached `usize` values indicate the number of bytes that were successfully read (`bytes_read`)
    /// and total bytes attempted to read (`count`) before the unexpected end of the packet.
    UnexpectedEndOfPacket { bytes_read: usize, count: usize },
    /// This variant can be used if `chunk_len` passed by the caller is not equal to the expected size for the type.
    InvalidChunkLength { expected: usize, found: usize },
}

/// Trait for types that can be created from a big-endian byte array of a known compile-time size N.
pub trait FromBytesWithKnownSize<const N: usize>: Sized {
    /// Creates an instance of `Self` from a byte array of size N.
    fn from_be_bytes_array(bytes: [u8; N]) -> Self;
}

/// Implementation for u32
impl FromBytesWithKnownSize<4> for u32 {
    fn from_be_bytes_array(bytes: [u8; 4]) -> Self {
        u32::from_be_bytes(bytes)
    }
}

/// Implementation for u64
impl FromBytesWithKnownSize<8> for u64 {
    fn from_be_bytes_array(bytes: [u8; 8]) -> Self {
        u64::from_be_bytes(bytes)
    }
}

/// Generic function to read chunks of type T.
/// T must implement FromBytesWithKnownSize<N>, where N is the size of T in bytes.
/// The chunk_len_param is the chunk size expected by the caller, which is validated against N.
pub(crate) unsafe fn read_chunks<T, const N: usize>(
    start_ptr: *const u8,
    end_ptr: *const u8,
    buffer: &mut [T],
    chunk_len_param: usize, // The chunk length provided by the caller
) -> Result<usize, ChunkReaderError>
where
    T: FromBytesWithKnownSize<N>,
{
    if chunk_len_param != N {
        return Err(ChunkReaderError::InvalidChunkLength {
            expected: N,
            found: chunk_len_param,
        });
    }

    let mut current_ptr = start_ptr;
    let mut count = 0;

    while current_ptr < end_ptr && count < buffer.len() {
        if current_ptr.add(N) > end_ptr {
            return Err(ChunkReaderError::UnexpectedEndOfPacket {
                bytes_read: count * N, // Number of chunks read * size of each chunk
                count,                 // Number of chunks successfully read
            });
        }
        
        let mut block_bytes_arr = [0u8; N];
        ptr::copy_nonoverlapping(
            current_ptr,
            block_bytes_arr.as_mut_ptr(),
            N,
        );

        buffer[count] = T::from_be_bytes_array(block_bytes_arr);

        current_ptr = current_ptr.add(N);
        count += 1;
    }
    Ok(count)
}
