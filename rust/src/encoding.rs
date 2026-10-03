use alloc::vec::Vec;

use crate::error::Error;
use crate::wipe::SecretBytes;

pub(crate) const SEQUENCE: u8 = 0x30;

pub(crate) const INTEGER: u8 = 0x02;

pub(crate) const BIT_STRING: u8 = 0x03;

pub(crate) const OCTET_STRING: u8 = 0x04;

pub(crate) const OBJECT_IDENTIFIER: u8 = 0x06;

pub(crate) const CONTEXT_0: u8 = 0x80;

pub(crate) const CONTEXT_0_CONSTRUCTED: u8 = 0xA0;

pub(crate) const CONTEXT_1: u8 = 0x81;

const fn header_size(length: usize) -> usize {
    if length < 0x80 {
        2
    } else {
        2 + (usize::BITS - length.leading_zeros()).div_ceil(8) as usize
    }
}

fn write_header(out: &mut Vec<u8>, tag: u8, length: usize) {
    out.push(tag);

    if length < 0x80 {
        out.push(length as u8);
    } else {
        let size = header_size(length) - 2;

        out.push(0x80 | size as u8);

        out.extend_from_slice(&length.to_be_bytes()[size_of::<usize>() - size..]);
    }
}

pub(crate) fn element(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(header_size(content.len()) + content.len());

    write_header(&mut out, tag, content.len());

    out.extend_from_slice(content);

    out
}

fn write_algorithm(out: &mut Vec<u8>, oid: &[u8]) {
    write_header(out, SEQUENCE, header_size(oid.len()) + oid.len());

    write_header(out, OBJECT_IDENTIFIER, oid.len());

    out.extend_from_slice(oid);
}

const fn algorithm_size(oid: &[u8]) -> usize {
    let inner = header_size(oid.len()) + oid.len();

    header_size(inner) + inner
}

pub(crate) fn encode_public_key(oid: &[u8], key: &[u8]) -> Vec<u8> {
    let bits = 1 + key.len();

    let body = algorithm_size(oid) + header_size(bits) + bits;

    let mut out = Vec::with_capacity(header_size(body) + body);

    write_header(&mut out, SEQUENCE, body);

    write_algorithm(&mut out, oid);

    write_header(&mut out, BIT_STRING, bits);

    out.push(0);

    out.extend_from_slice(key);

    out
}

pub(crate) fn encode_private_key(oid: &[u8], key: &[u8]) -> SecretBytes {
    let body = 3 + algorithm_size(oid) + header_size(key.len()) + key.len();

    let mut out = Vec::with_capacity(header_size(body) + body);

    write_header(&mut out, SEQUENCE, body);

    out.extend_from_slice(&[INTEGER, 1, 0]);

    write_algorithm(&mut out, oid);

    write_header(&mut out, OCTET_STRING, key.len());

    out.extend_from_slice(key);

    SecretBytes::from_vec(out)
}

pub(crate) struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    // DER only: a single-byte tag and the shortest definite length.
    pub(crate) fn read(&mut self, tag: u8) -> Result<&'a [u8], Error> {
        let rest = &self.data[self.offset..];

        let [found, first, ..] = *rest else {
            return Err(Error::InvalidEncoding);
        };

        if found != tag {
            return Err(Error::InvalidEncoding);
        }

        let mut start = 2;

        let length = if first < 0x80 {
            usize::from(first)
        } else {
            let size = usize::from(first & 0x7F);

            let bytes = rest
                .get(2..2 + size)
                .filter(|bytes| (1..=4).contains(&size) && bytes[0] != 0)
                .ok_or(Error::InvalidEncoding)?;

            let length = bytes
                .iter()
                .fold(0usize, |value, &byte| (value << 8) | usize::from(byte));

            if length < 0x80 {
                return Err(Error::InvalidEncoding);
            }

            start += size;

            length
        };

        let content = rest
            .get(start..)
            .and_then(|content| content.get(..length))
            .ok_or(Error::InvalidEncoding)?;

        self.offset += start + length;

        Ok(content)
    }

    pub(crate) fn peek(&self) -> Option<u8> {
        self.data.get(self.offset).copied()
    }

    pub(crate) fn finish(&self) -> Result<(), Error> {
        if self.offset == self.data.len() {
            Ok(())
        } else {
            Err(Error::InvalidEncoding)
        }
    }
}

pub(crate) fn only(data: &[u8], tag: u8) -> Result<&[u8], Error> {
    let mut reader = Reader::new(data);

    let content = reader.read(tag)?;

    reader.finish()?;

    Ok(content)
}

fn read_algorithm<'a>(reader: &mut Reader<'a>) -> Result<&'a [u8], Error> {
    only(reader.read(SEQUENCE)?, OBJECT_IDENTIFIER)
}

fn unused_bits_free(bits: &[u8]) -> Result<&[u8], Error> {
    match bits.split_first() {
        Some((0, key)) => Ok(key),
        _ => Err(Error::InvalidEncoding),
    }
}

// SubjectPublicKeyInfo: returns the algorithm OID and the key bytes.
pub(crate) fn decode_public_key(data: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let mut reader = Reader::new(only(data, SEQUENCE)?);

    let oid = read_algorithm(&mut reader)?;

    let bits = reader.read(BIT_STRING)?;

    reader.finish()?;

    Ok((oid, unused_bits_free(bits)?))
}

pub(crate) struct PrivateKeyInfo<'a> {
    pub(crate) oid: &'a [u8],
    pub(crate) key: &'a [u8],
    pub(crate) public_key: Option<&'a [u8]>,
}

// PKCS#8 OneAsymmetricKey (RFC 5958): version 0 or 1, attributes ignored, and the optional
// public key returned so that the caller can check that it matches.
pub(crate) fn decode_private_key(data: &[u8]) -> Result<PrivateKeyInfo<'_>, Error> {
    let mut reader = Reader::new(only(data, SEQUENCE)?);

    let version = reader.read(INTEGER)?;

    if version != [0] && version != [1] {
        return Err(Error::InvalidEncoding);
    }

    let oid = read_algorithm(&mut reader)?;

    let key = reader.read(OCTET_STRING)?;

    if reader.peek() == Some(CONTEXT_0_CONSTRUCTED) {
        reader.read(CONTEXT_0_CONSTRUCTED)?;
    }

    let mut public_key = None;

    if reader.peek() == Some(CONTEXT_1) {
        if version != [1] {
            return Err(Error::InvalidEncoding);
        }

        public_key = Some(unused_bits_free(reader.read(CONTEXT_1)?)?);
    }

    reader.finish()?;

    Ok(PrivateKeyInfo {
        oid,
        key,
        public_key,
    })
}

// Arithmetic instead of table lookups, so that private keys never index memory with secret
// values.
fn base64_character(value: u32) -> u8 {
    let value = value as i32;

    let mut character = value + 65;

    character += ((25 - value) >> 8) & 6;

    character -= ((51 - value) >> 8) & 75;

    character -= ((61 - value) >> 8) & 15;

    character += ((62 - value) >> 8) & 3;

    character as u8
}

// -1 marks a character outside the alphabet.
fn base64_value(character: u8) -> i32 {
    let c = i32::from(character);

    let mut value = -1;

    value += (((0x40 - c) & (c - 0x5B)) >> 8) & (c - 64);

    value += (((0x60 - c) & (c - 0x7B)) >> 8) & (c - 70);

    value += (((0x2F - c) & (c - 0x3A)) >> 8) & (c + 5);

    value += (((0x2A - c) & (c - 0x2C)) >> 8) & 63;

    value += (((0x2E - c) & (c - 0x30)) >> 8) & 64;

    value
}

fn base64_chunk(chunk: &[u8], out: &mut Vec<u8>) {
    let mut padded = [0u8; 4];

    padded[1..=chunk.len()].copy_from_slice(chunk);

    let value = u32::from_be_bytes(padded);

    for (index, shift) in [18, 12, 6, 0].into_iter().enumerate() {
        if index <= chunk.len() {
            out.push(base64_character((value >> shift) & 0x3F));
        } else {
            out.push(b'=');
        }
    }
}

fn base64_decode(text: &[u8]) -> Result<SecretBytes, Error> {
    if !text.len().is_multiple_of(4) {
        return Err(Error::InvalidEncoding);
    }

    let padding = if text.ends_with(b"==") {
        2
    } else {
        usize::from(text.ends_with(b"="))
    };

    let mut out = SecretBytes::zeroed(text.len() / 4 * 3 - padding);

    let chunks = text.len() / 4;

    let mut invalid = 0u32;

    for (index, chunk) in text.chunks_exact(4).enumerate() {
        let used = if index + 1 == chunks { 4 - padding } else { 4 };

        let mut value = 0u32;

        for (position, &character) in chunk.iter().enumerate() {
            let digit = if position < used {
                base64_value(character)
            } else {
                0
            };

            invalid |= (digit >> 31) as u32;

            value = (value << 6) | (digit as u32 & 0x3F);
        }

        // Canonical padding: the bits that no output byte carries must be zero.
        invalid |= value & ((1 << (8 * (4 - used))) - 1);

        let bytes = value.to_be_bytes();

        let start = 3 * index;

        let end = (start + 3).min(out.len());

        out[start..end].copy_from_slice(&bytes[1..1 + end - start]);
    }

    if invalid != 0 {
        return Err(Error::InvalidEncoding);
    }

    Ok(out)
}

// ASCII whitespace, including the vertical tab that u8::is_ascii_whitespace leaves out.
const fn is_space(character: u8) -> bool {
    matches!(character, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C)
}

const BEGIN: &[u8] = b"-----BEGIN ";

const END: &[u8] = b"-----END ";

const DASHES: &[u8] = b"-----";

pub(crate) fn pem_encode(label: &[u8], der: &[u8]) -> Vec<u8> {
    let lines = der.len().div_ceil(48);

    let size = BEGIN.len()
        + END.len()
        + 2 * (label.len() + DASHES.len() + 1)
        + 4 * der.len().div_ceil(3)
        + lines;

    let mut out = Vec::with_capacity(size);

    for part in [BEGIN, label, DASHES, b"\n"] {
        out.extend_from_slice(part);
    }

    // 48 input bytes make one 64-character line, so only the last line can carry padding.
    for line in der.chunks(48) {
        for chunk in line.chunks(3) {
            base64_chunk(chunk, &mut out);
        }

        out.push(b'\n');
    }

    for part in [END, label, DASHES, b"\n"] {
        out.extend_from_slice(part);
    }

    out
}

pub(crate) fn pem_decode(label: &[u8], data: &[u8]) -> Result<SecretBytes, Error> {
    let start = data
        .iter()
        .position(|&c| !is_space(c))
        .unwrap_or(data.len());

    let end = data
        .iter()
        .rposition(|&c| !is_space(c))
        .map_or(start, |last| last + 1);

    let data = &data[start..end];

    let header = BEGIN.len() + label.len() + DASHES.len();

    let footer = END.len() + label.len() + DASHES.len();

    let framed = data.len() >= header + footer
        && data[..header] == [BEGIN, label, DASHES].concat()
        && data[data.len() - footer..] == [END, label, DASHES].concat();

    if !framed {
        return Err(Error::InvalidEncoding);
    }

    let body = &data[header..data.len() - footer];

    if body.iter().fold(0, |high, &c| high | c) & 0x80 != 0 {
        return Err(Error::InvalidEncoding);
    }

    let mut text = SecretBytes::zeroed(body.iter().filter(|&&c| !is_space(c)).count());

    for (target, &c) in text.iter_mut().zip(body.iter().filter(|&&c| !is_space(c))) {
        *target = c;
    }

    base64_decode(&text)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn base64_alphabet() {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        for (value, &character) in alphabet.iter().enumerate() {
            assert_eq!(base64_character(value as u32), character);

            assert_eq!(base64_value(character), value as i32);
        }

        for character in 0..=255u8 {
            if !alphabet.contains(&character) {
                assert_eq!(base64_value(character), -1, "{character}");
            }
        }
    }

    #[test]
    fn base64_round_trip() {
        let data: Vec<u8> = (0..=255).collect();

        for length in 0..data.len() {
            let mut text = Vec::new();

            for chunk in data[..length].chunks(3) {
                base64_chunk(chunk, &mut text);
            }

            assert_eq!(&base64_decode(&text).expect("decodes")[..], &data[..length]);
        }
    }

    #[test]
    fn base64_rejects() {
        for text in [
            &b"QQ="[..],
            b"QR==",
            b"QUJ=",
            b"Q===",
            b"====",
            b"QQ==QQ==",
            b"Q\x00==",
            b"QUJD\xC3\xA9",
        ] {
            assert_eq!(base64_decode(text).err(), Some(Error::InvalidEncoding));
        }

        assert_eq!(&base64_decode(b"QQ==").expect("decodes")[..], b"A");

        assert_eq!(&base64_decode(b"QUI=").expect("decodes")[..], b"AB");
    }

    #[test]
    fn der_lengths() {
        for length in [0, 1, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x10000] {
            let encoded = element(OCTET_STRING, &std::vec![7; length]);

            assert_eq!(encoded.len(), header_size(length) + length);

            assert_eq!(only(&encoded, OCTET_STRING).expect("parses").len(), length);
        }

        // The non-minimal lengths come with their full content, so the length rule itself must
        // reject them rather than a truncation check.
        let with_content = |header: &[u8], length: usize| [header, &std::vec![7; length]].concat();

        for bad in [
            with_content(&[0x04, 0x81, 0x7F], 0x7F),
            with_content(&[0x04, 0x82, 0x00, 0x80], 0x80),
            with_content(&[0x04, 0x83, 0x00, 0x01, 0x00], 0x100),
            with_content(&[0x04, 0x80], 0),
            with_content(&[0x04, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00], 0),
            with_content(&[0x04, 0x02], 1),
            with_content(&[0x04, 0x01], 2),
            with_content(&[0x05, 0x01], 1),
            std::vec![0x04],
        ] {
            assert_eq!(only(&bad, OCTET_STRING).err(), Some(Error::InvalidEncoding));
        }
    }
}
