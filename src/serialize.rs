use crate::errors::{DeserializationError, SerializationError};
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn read_string<R: AsyncRead + Send + Unpin>(
    r: &mut R,
) -> Result<String, DeserializationError> {
    let mut length_buffer = [0; 1];

    if r.read(&mut length_buffer).await? == 0 {
        return Err(DeserializationError::NotEnoughData);
    }

    let target = length_buffer[0] as usize;

    if target == 0 {
        return Err(DeserializationError::InvalidEmptyString);
    }

    let mut bytestring = vec![0; target];
    read_amt(r, target, &mut bytestring).await?;

    Ok(String::from_utf8(bytestring)?)
}

pub async fn write_string<W: AsyncWrite + Send + Unpin>(
    s: &str,
    w: &mut W,
) -> Result<(), SerializationError> {
    let bytestring = s.as_bytes();

    if bytestring.is_empty() || bytestring.len() > 255 {
        return Err(SerializationError::InvalidStringLength(s.to_string()));
    }

    w.write_all(&[bytestring.len() as u8]).await?;
    w.write_all(bytestring)
        .await
        .map_err(SerializationError::IOError)
}

pub async fn read_amt<R: AsyncRead + Send + Unpin>(
    r: &mut R,
    amt: usize,
    buffer: &mut [u8],
) -> Result<(), DeserializationError> {
    let mut amt_read = 0;

    while amt_read < amt {
        let chunk_amt = r.read(&mut buffer[amt_read..]).await?;

        if chunk_amt == 0 {
            return Err(DeserializationError::NotEnoughData);
        }

        amt_read += chunk_amt;
    }

    Ok(())
}
