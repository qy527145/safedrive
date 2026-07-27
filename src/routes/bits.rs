//! Bit-level wire helpers shared by the compact share codecs
//! (`share_codec` for `sd://` file shares, `ds_codec` for `sdds://`
//! datasource-config shares).

pub(super) const MAX_STRING_BYTES: usize = 16 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum DecodeError {
    UnsupportedVersion(u8),
    Invalid,
}

pub(super) fn validate_string(value: &str) -> Result<(), &'static str> {
    if value.len() > MAX_STRING_BYTES {
        Err("string too long")
    } else {
        Ok(())
    }
}

#[derive(Default)]
pub(super) struct BitWriter {
    bytes: Vec<u8>,
    used: u8,
}

impl BitWriter {
    pub(super) fn write_bit(&mut self, bit: bool) {
        self.write_bits(bit as u64, 1);
    }

    pub(super) fn write_bits(&mut self, value: u64, count: u8) {
        for shift in (0..count).rev() {
            if self.used == 0 {
                self.bytes.push(0);
            }
            let bit = ((value >> shift) & 1) as u8;
            let last = self.bytes.len() - 1;
            self.bytes[last] |= bit << (7 - self.used);
            self.used = (self.used + 1) & 7;
        }
    }

    pub(super) fn write_bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.write_bits(*byte as u64, 8);
        }
    }

    pub(super) fn write_varint(&mut self, mut value: u64) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            self.write_bits(byte as u64, 8);
            if value == 0 {
                break;
            }
        }
    }

    pub(super) fn write_string(&mut self, value: &str) -> Result<(), &'static str> {
        validate_string(value)?;
        self.write_varint(value.len() as u64);
        self.write_bytes(value.as_bytes());
        Ok(())
    }

    pub(super) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

pub(super) struct BitReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> BitReader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub(super) fn read_bit(&mut self) -> Result<bool, DecodeError> {
        Ok(self.read_bits(1)? != 0)
    }

    pub(super) fn read_bits(&mut self, count: u8) -> Result<u64, DecodeError> {
        if count > 64 || self.position + count as usize > self.bytes.len() * 8 {
            return Err(DecodeError::Invalid);
        }
        let mut value = 0u64;
        for _ in 0..count {
            let byte = self.bytes[self.position / 8];
            let bit = (byte >> (7 - self.position % 8)) & 1;
            value = (value << 1) | bit as u64;
            self.position += 1;
        }
        Ok(value)
    }

    pub(super) fn read_bytes(&mut self, output: &mut [u8]) -> Result<(), DecodeError> {
        for byte in output {
            *byte = self.read_bits(8)? as u8;
        }
        Ok(())
    }

    pub(super) fn read_varint(&mut self) -> Result<u64, DecodeError> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let byte = self.read_bits(8)? as u8;
            if shift == 63 && byte > 1 {
                return Err(DecodeError::Invalid);
            }
            value |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(DecodeError::Invalid)
    }

    pub(super) fn read_string(&mut self) -> Result<String, DecodeError> {
        let len = usize::try_from(self.read_varint()?).map_err(|_| DecodeError::Invalid)?;
        if len > MAX_STRING_BYTES {
            return Err(DecodeError::Invalid);
        }
        let mut bytes = vec![0; len];
        self.read_bytes(&mut bytes)?;
        String::from_utf8(bytes).map_err(|_| DecodeError::Invalid)
    }

    pub(super) fn finish(mut self) -> Result<(), DecodeError> {
        let remaining = self.bytes.len() * 8 - self.position;
        if remaining >= 8 {
            return Err(DecodeError::Invalid);
        }
        while self.position < self.bytes.len() * 8 {
            if self.read_bit()? {
                return Err(DecodeError::Invalid);
            }
        }
        Ok(())
    }
}
