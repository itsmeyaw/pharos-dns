use std::fmt::{self, Write};

struct Buffer {
    bytes: [u8; 128],
    len: usize,
}

impl Write for Buffer {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(fmt::Error)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}

pub(super) fn write_float(output: &mut impl Write, value: f64) -> fmt::Result {
    if value.is_nan() {
        return output.write_str("NaN");
    }
    if value == f64::INFINITY {
        return output.write_str("+Inf");
    }
    if value == f64::NEG_INFINITY {
        return output.write_str("-Inf");
    }
    if value != 0.0 && (value.abs() < 0.0001 || value.abs() >= 1_000_000.0) {
        let mut buffer = Buffer {
            bytes: [0; 128],
            len: 0,
        };
        write!(buffer, "{value:e}")?;
        let text = std::str::from_utf8(&buffer.bytes[..buffer.len]).map_err(|_| fmt::Error)?;
        let (mantissa, exponent) = text.split_once('e').ok_or(fmt::Error)?;
        let exponent: i32 = exponent.parse().map_err(|_| fmt::Error)?;
        return write!(
            output,
            "{mantissa}e{}{abs:02}",
            if exponent < 0 { '-' } else { '+' },
            abs = exponent.unsigned_abs()
        );
    }
    write!(output, "{value}")
}
