/// Reads a variable-length buffer from a TC context with a maximum length of 32 bytes.
///
/// This macro reads up to `$max_len` bytes from the given TC context `$tc_ctx`
/// starting at offset `$off`. The actual number of bytes read is determined by `$len`.
///
/// The `$max_len` is capped at 32 bytes due to limitations in the eBPF verifier,
/// which restricts the complexity of loops in kernel space to ensure termination.
/// This macro will fail to compile if `$max_len` is greater than 32.
///
/// # Arguments
/// * `$tc_ctx`: The traffic control context to read from.
/// * `$off`: A mutable variable holding the current offset, which will be advanced.
/// * `$buf`: The destination buffer to write the bytes into.
/// * `$len`: The number of bytes to read.
/// * `$max_len`: The maximum number of bytes to read, cannot exceed 32.
///
/// # Returns
/// `Ok(())` on success. On failure to load a byte from the context returns an `Err`.
#[macro_export]
macro_rules! read_var_buf_32 {
    ($tc_ctx:expr, $off:ident, $buf:expr, $len:expr, $max_len:expr) => {
        (|| -> Result<(), ()> {
            // This will cause a compile-time error if $max_len is greater than 32.
            const _: () = assert!($max_len <= 32, "$max_len cannot be greater than 32");
            for i in 0..core::cmp::min(16, $max_len) {
                if usize::from(i as u8) >= $len {
                    return Ok(());
                }
                $buf[i] = $tc_ctx.load($off).map_err(|_| ())?;
                $off += 1;
            }
            if $max_len > 16 {
                for i in 16..$max_len {
                    if usize::from(i as u8) >= $len {
                        return Ok(());
                    }
                    $buf[i] = $tc_ctx.load($off).map_err(|_| ())?;
                    $off += 1;
                }
            }
            Ok(())
        })()
    };
}

/// Reads a QUIC variable-length integer from a TC context into a buffer.
///
/// This macro reads a variable-length integer, storing its raw bytes in `$buf`.
/// It takes `$len_byte` (the first byte of the var-int) which it stores as the
/// first byte of the buffer. It then calculates the total length of the var-int
/// from the first two bits of `$len_byte` and reads the remaining bytes.
///
/// # Arguments
/// * `$tc_ctx`: The traffic control context to read from.
/// * `$off`: A mutable variable holding the current offset, which will be advanced.
/// * `$buf`: The destination buffer to write the bytes into.
/// * `$len_byte`: The first byte of the variable-length integer.
/// * `$max_len`: The maximum capacity of the buffer cannot exceed 16.
///
/// # Returns
/// `Ok(())` on success. On failure to load a byte from the context returns an `Err`.
#[macro_export]
macro_rules! read_var_buf_from_len_byte_16 {
    ($tc_ctx:expr, $off:ident, $buf:expr, $len_byte:expr, $max_len:expr) => {
        (|| -> Result<(), ()> {
            const _: () = assert!($max_len <= 16, "$max_len cannot be greater than 16");
            let len = 1 << ($len_byte >> 6);
            if $max_len < 1 {
                return Err(());
            }
            $buf[0] = $len_byte;
            for i in 1..core::cmp::min(16, $max_len) {
                if i >= len {
                    return Ok(());
                }
                $buf[i] = $tc_ctx.load($off).map_err(|_| ())?;
                $off += 1;
            }
            Ok(())
        })()
    };
}
