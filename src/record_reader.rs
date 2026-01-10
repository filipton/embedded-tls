use crate::key_schedule::ReadKeySchedule;
use embedded_io::{Error, Read as BlockingRead};
use embedded_io_async::Read as AsyncRead;

use crate::{
    config::TlsCipherSuite,
    record::{RecordHeader, ServerRecord},
    TlsError,
};

pub struct RecordReader<'a> {
    pub(crate) buf: &'a mut [u8],
    /// The number of decoded bytes in the buffer
    decoded: usize,
    /// The number of read but not yet decoded bytes in the buffer
    pending: usize,
}

pub struct RecordReaderBorrowMut<'a> {
    pub(crate) buf: &'a mut [u8],
    /// The number of decoded bytes in the buffer
    decoded: &'a mut usize,
    /// The number of read but not yet decoded bytes in the buffer
    pending: &'a mut usize,
}

impl<'a> RecordReader<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        if buf.len() < 16640 {
            warn!("Read buffer is smaller than 16640 bytes, which may cause problems!");
        }
        Self {
            buf,
            decoded: 0,
            pending: 0,
        }
    }

    pub fn reborrow_mut(&mut self) -> RecordReaderBorrowMut<'_> {
        RecordReaderBorrowMut {
            buf: self.buf,
            decoded: &mut self.decoded,
            pending: &mut self.pending,
        }
    }

    pub async fn read<'m, CipherSuite: TlsCipherSuite>(
        &'m mut self,
        transport: &mut impl AsyncRead,
        key_schedule: &mut ReadKeySchedule<CipherSuite>,
    ) -> Result<ServerRecord<'m, CipherSuite>, TlsError> {
        read(
            self.buf,
            &mut self.decoded,
            &mut self.pending,
            transport,
            key_schedule,
        )
        .await
    }

    pub fn read_blocking<'m, CipherSuite: TlsCipherSuite>(
        &'m mut self,
        transport: &mut impl BlockingRead,
        key_schedule: &mut ReadKeySchedule<CipherSuite>,
    ) -> Result<ServerRecord<'m, CipherSuite>, TlsError> {
        read_blocking(
            self.buf,
            &mut self.decoded,
            &mut self.pending,
            transport,
            key_schedule,
        )
    }
}

impl RecordReaderBorrowMut<'_> {
    pub async fn read<'m, CipherSuite: TlsCipherSuite>(
        &'m mut self,
        transport: &mut impl AsyncRead,
        key_schedule: &mut ReadKeySchedule<CipherSuite>,
    ) -> Result<ServerRecord<'m, CipherSuite>, TlsError> {
        read(
            self.buf,
            self.decoded,
            self.pending,
            transport,
            key_schedule,
        )
        .await
    }

    pub fn read_blocking<'m, CipherSuite: TlsCipherSuite>(
        &'m mut self,
        transport: &mut impl BlockingRead,
        key_schedule: &mut ReadKeySchedule<CipherSuite>,
    ) -> Result<ServerRecord<'m, CipherSuite>, TlsError> {
        read_blocking(
            self.buf,
            self.decoded,
            self.pending,
            transport,
            key_schedule,
        )
    }
}

pub async fn read<'m, CipherSuite: TlsCipherSuite>(
    buf: &'m mut [u8],
    decoded: &mut usize,
    pending: &mut usize,
    transport: &mut impl AsyncRead,
    key_schedule: &mut ReadKeySchedule<CipherSuite>,
) -> Result<ServerRecord<'m, CipherSuite>, TlsError> {
    advance(buf, decoded, pending, transport, RecordHeader::LEN).await?;
    let header = record_header(buf, *decoded)?;

    let record_len = RecordHeader::LEN + header.content_length();
    advance(buf, decoded, pending, transport, record_len).await?;
    consume(
        buf,
        decoded,
        pending,
        header,
        key_schedule.transcript_hash(),
    )
}

pub fn read_blocking<'m, CipherSuite: TlsCipherSuite>(
    buf: &'m mut [u8],
    decoded: &mut usize,
    pending: &mut usize,
    transport: &mut impl BlockingRead,
    key_schedule: &mut ReadKeySchedule<CipherSuite>,
) -> Result<ServerRecord<'m, CipherSuite>, TlsError> {
    advance_blocking(buf, decoded, pending, transport, RecordHeader::LEN)?;
    let header = record_header(buf, *decoded)?;

    let record_len = RecordHeader::LEN + header.content_length();
    advance_blocking(buf, decoded, pending, transport, record_len)?;
    consume(
        buf,
        decoded,
        pending,
        header,
        key_schedule.transcript_hash(),
    )
}

async fn advance(
    buf: &mut [u8],
    decoded: &mut usize,
    pending: &mut usize,
    transport: &mut impl AsyncRead,
    amount: usize,
) -> Result<(), TlsError> {
    ensure_contiguous(buf, decoded, pending, amount)?;

    while *pending < amount {
        let read = transport
            .read(&mut buf[*decoded + *pending..])
            .await
            .map_err(|e| TlsError::Io(e.kind()))?;
        if read == 0 {
            return Err(TlsError::IoError);
        }
        *pending += read;
    }

    Ok(())
}

fn advance_blocking(
    buf: &mut [u8],
    decoded: &mut usize,
    pending: &mut usize,
    transport: &mut impl BlockingRead,
    amount: usize,
) -> Result<(), TlsError> {
    ensure_contiguous(buf, decoded, pending, amount)?;

    while *pending < amount {
        let read = transport
            .read(&mut buf[*decoded + *pending..])
            .map_err(|e| TlsError::Io(e.kind()))?;
        if read == 0 {
            return Err(TlsError::IoError);
        }
        *pending += read;
    }

    Ok(())
}

fn record_header(buf: &[u8], decoded: usize) -> Result<RecordHeader, TlsError> {
    RecordHeader::decode(unwrap!(buf[decoded..][..RecordHeader::LEN].try_into().ok()))
}

fn consume<'m, CipherSuite: TlsCipherSuite>(
    buf: &'m mut [u8],
    decoded: &mut usize,
    pending: &mut usize,
    header: RecordHeader,
    digest: &mut CipherSuite::Hash,
) -> Result<ServerRecord<'m, CipherSuite>, TlsError> {
    let content_len = header.content_length();
    let record_len = RecordHeader::LEN + content_len;

    let slice = &mut buf[*decoded + RecordHeader::LEN..][..content_len];

    let record = ServerRecord::decode(header, slice, digest)?;

    *decoded += record_len;
    *pending -= record_len;

    Ok(record)
}

fn ensure_contiguous(
    buf: &mut [u8],
    decoded: &mut usize,
    pending: &mut usize,
    len: usize,
) -> Result<(), TlsError> {
    if *decoded + len > buf.len() {
        if len > buf.len() {
            error!(
                "Record too large for buffer. Size: {} Buffer size: {}",
                len,
                buf.len()
            );
            return Err(TlsError::InsufficientSpace);
        }
        buf.copy_within(*decoded..*decoded + *pending, 0);
        *decoded = 0;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use super::*;
    use crate::{Aes128GcmSha256, content_types::ContentType, key_schedule::KeySchedule};

    struct ChunkRead<'a>(&'a [u8], usize);

    impl embedded_io::ErrorType for ChunkRead<'_> {
        type Error = Infallible;
    }

    impl BlockingRead for ChunkRead<'_> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let len = usize::min(self.1, buf.len());
            let len = usize::min(len, self.0.len());
            buf[..len].copy_from_slice(&self.0[..len]);
            self.0 = &self.0[len..];
            Ok(len)
        }
    }

    #[test]
    fn can_read_blocking() {
        can_read_blocking_case(1);
        can_read_blocking_case(2);
        can_read_blocking_case(3);
        can_read_blocking_case(4);
        can_read_blocking_case(5);
        can_read_blocking_case(6);
        can_read_blocking_case(7);
        can_read_blocking_case(8);
        can_read_blocking_case(9);
        can_read_blocking_case(10);
        can_read_blocking_case(11);
        can_read_blocking_case(12);
        can_read_blocking_case(13);
        can_read_blocking_case(14);
        can_read_blocking_case(15);
        can_read_blocking_case(16);
    }

    fn can_read_blocking_case(chunk_size: usize) {
        let mut transport = ChunkRead(
            &[
                // Header
                ContentType::ApplicationData as u8,
                0x03,
                0x03,
                0x00,
                0x04,
                // Data
                0xde,
                0xad,
                0xbe,
                0xef,
                // Header
                ContentType::ApplicationData as u8,
                0x03,
                0x03,
                0x00,
                0x02,
                // Data
                0xaa,
                0xbb,
            ],
            chunk_size,
        );

        let mut buf = [0; 32];
        let mut reader = RecordReader::new(&mut buf);
        let mut key_schedule = KeySchedule::<Aes128GcmSha256>::new();

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert_eq!([0xde, 0xad, 0xbe, 0xef], data.data.as_slice());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(4, reader.decoded);
            assert_eq!(0, reader.pending);
        }

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert_eq!([0xaa, 0xbb], data.data.as_slice());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(6, reader.decoded);
            assert_eq!(0, reader.pending);
        }
    }

    #[test]
    fn can_read_blocking_must_rotate_buffer() {
        let mut transport = [
            // Header
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            0x00,
            0x04,
            // Data
            0xde,
            0xad,
            0xbe,
            0xef,
            // Header
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            0x00,
            0x02,
            // Data
            0xaa,
            0xbb,
        ]
        .as_slice();

        let mut buf = [0; 4]; // cannot contain both data portions
        let mut reader = RecordReader::new(&mut buf);
        let mut key_schedule = KeySchedule::<Aes128GcmSha256>::new();

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert_eq!([0xde, 0xad, 0xbe, 0xef], data.data.as_slice());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(4, reader.decoded);
            assert_eq!(0, reader.pending);
        }

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert_eq!([0xaa, 0xbb], data.data.as_slice());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(2, reader.decoded);
            assert_eq!(0, reader.pending);
        }
    }

    #[test]
    fn can_read_empty_record() {
        let mut transport = [
            // Header
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            0x00,
            0x00,
            // Header
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            0x00,
            0x00,
        ]
        .as_slice();

        let mut buf = [0; 32];
        let mut reader = RecordReader::new(&mut buf);
        let mut key_schedule = KeySchedule::<Aes128GcmSha256>::new();

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert!(data.data.is_empty());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(0, reader.decoded);
            assert_eq!(0, reader.pending);
        }

        {
            if let ServerRecord::ApplicationData(data) = reader
                .read_blocking(&mut transport, key_schedule.read_state())
                .unwrap()
            {
                assert!(data.data.is_empty());
            } else {
                panic!("Wrong server record");
            }

            assert_eq!(0, reader.decoded);
            assert_eq!(0, reader.pending);
        }
    }
}
