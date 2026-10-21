use crate::{
    credentials::{Algorithm, CredentialRecord},
    Error, Result,
};
use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

pub fn generate_current(record: &CredentialRecord) -> Result<Zeroizing<String>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::General("system clock precedes Unix epoch".into()))?
        .as_secs();
    generate_at(record, now)
}
pub fn generate_at(record: &CredentialRecord, timestamp: u64) -> Result<Zeroizing<String>> {
    record.validate()?;
    let elapsed = timestamp
        .checked_sub(record.t0)
        .ok_or_else(|| Error::InvalidConfiguration("time precedes configured epoch".into()))?;
    let counter = (elapsed / record.period).to_be_bytes();
    let secret = record.decoded_secret()?;
    macro_rules! digest {
        ($hash:ty) => {{
            let mut mac = Hmac::<$hash>::new_from_slice(&secret)
                .map_err(|_| Error::InvalidConfiguration("invalid HMAC key".into()))?;
            mac.update(&counter);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }};
    }
    let digest = match record.algorithm {
        Algorithm::SHA1 => digest!(sha1::Sha1),
        Algorithm::SHA256 => digest!(sha2::Sha256),
        Algorithm::SHA512 => digest!(sha2::Sha512),
    };
    let offset = (digest[digest.len() - 1] & 0xf) as usize;
    let truncated = u32::from_be_bytes(
        digest[offset..offset + 4]
            .try_into()
            .expect("HMAC truncation is in bounds"),
    ) & 0x7fff_ffff;
    Ok(Zeroizing::new(format!(
        "{:0width$}",
        truncated % 10u32.pow(record.digits),
        width = record.digits as usize
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(algorithm: Algorithm, length: usize, digits: u32) -> CredentialRecord {
        let secret: Vec<u8> = b"1234567890".iter().copied().cycle().take(length).collect();
        CredentialRecord::new(
            &data_encoding::BASE32_NOPAD.encode(&secret),
            algorithm,
            digits,
            30,
            0,
            None,
            None,
        )
        .unwrap()
    }
    #[test]
    fn official_rfc6238_vectors() {
        let times = [
            59,
            1111111109,
            1111111111,
            1234567890,
            2000000000,
            20000000000,
        ];
        let vectors = [
            (
                Algorithm::SHA1,
                20,
                [
                    "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
                ],
            ),
            (
                Algorithm::SHA256,
                32,
                [
                    "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
                ],
            ),
            (
                Algorithm::SHA512,
                64,
                [
                    "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
                ],
            ),
        ];
        for (algorithm, length, codes) in vectors {
            for (&time, code) in times.iter().zip(codes) {
                assert_eq!(
                    &*generate_at(&record(algorithm, length, 8), time).unwrap(),
                    code
                );
                assert_eq!(
                    &*generate_at(&record(algorithm, length, 6), time).unwrap(),
                    &code[2..]
                );
            }
        }
    }
    #[test]
    fn boundaries_period_and_epoch() {
        let mut record = record(Algorithm::SHA1, 20, 6);
        assert_eq!(&*generate_at(&record, 0).unwrap(), "755224");
        assert_eq!(&*generate_at(&record, 29).unwrap(), "755224");
        assert_eq!(&*generate_at(&record, 30).unwrap(), "287082");
        record.period = 60;
        record.t0 = 100;
        assert!(generate_at(&record, 99).is_err());
        assert_eq!(&*generate_at(&record, 159).unwrap(), "755224");
        assert_eq!(&*generate_at(&record, 160).unwrap(), "287082");
        record.period = 0;
        assert!(generate_at(&record, 160).is_err());
    }
}
