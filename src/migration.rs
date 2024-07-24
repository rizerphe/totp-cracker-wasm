use base64::{engine::general_purpose, Engine as _};
use prost::{Enumeration, Message};
use totp_rs::qrcodegen_image;
use url::form_urlencoded;
use wasm_bindgen::prelude::*;

#[derive(Clone, PartialEq, Message)]
struct MigrationPayload {
    #[prost(message, repeated, tag = "1")]
    otp_parameters: Vec<OtpParameters>,
    #[prost(int32, optional, tag = "2")]
    version: Option<i32>,
    #[prost(int32, optional, tag = "3")]
    batch_size: Option<i32>,
    #[prost(int32, optional, tag = "4")]
    batch_index: Option<i32>,
    #[prost(int32, optional, tag = "5")]
    batch_id: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
struct OtpParameters {
    #[prost(bytes, optional, tag = "1")]
    secret: Option<Vec<u8>>,
    #[prost(string, optional, tag = "2")]
    name: Option<String>,
    #[prost(string, optional, tag = "3")]
    issuer: Option<String>,
    #[prost(enumeration = "Algorithm", optional, tag = "4")]
    algorithm: Option<i32>,
    #[prost(enumeration = "DigitCount", optional, tag = "5")]
    digits: Option<i32>,
    #[prost(enumeration = "OtpType", optional, tag = "6")]
    type_: Option<i32>,
    #[prost(int64, optional, tag = "7")]
    counter: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Enumeration)]
#[repr(i32)]
enum Algorithm {
    Unspecified = 0,
    Sha1 = 1,
    Sha256 = 2,
    Sha512 = 3,
    Md5 = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Enumeration)]
#[repr(i32)]
#[wasm_bindgen]
pub enum DigitCount {
    Unspecified = 0,
    Six = 1,
    Eight = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Enumeration)]
#[repr(i32)]
enum OtpType {
    Unspecified = 0,
    Hotp = 1,
    Totp = 2,
}

#[wasm_bindgen]
pub struct OtpCode {
    digit_count: DigitCount,
    secret: Vec<u8>,
    issuer: Option<String>,
    account_name: String,
}

#[wasm_bindgen]
impl OtpCode {
    #[wasm_bindgen(constructor)]
    pub fn new(
        secret: Vec<u8>,
        issuer: Option<String>,
        account_name: String,
        n_digits: usize,
    ) -> Self {
        Self {
            digit_count: match n_digits {
                6 => DigitCount::Six,
                8 => DigitCount::Eight,
                _ => DigitCount::Unspecified,
            },
            secret,
            issuer,
            account_name,
        }
    }
}

#[wasm_bindgen]
pub fn create_migration_uri(codes: Vec<OtpCode>) -> String {
    let otp_parameters: Vec<OtpParameters> = codes
        .into_iter()
        .map(|code| OtpParameters {
            secret: Some(code.secret),
            name: Some(code.account_name),
            issuer: code.issuer,
            algorithm: Some(Algorithm::Sha1 as i32),
            digits: Some(code.digit_count as i32),
            type_: Some(OtpType::Totp as i32),
            counter: None,
        })
        .collect();

    let payload = MigrationPayload {
        otp_parameters,
        version: Some(1),
        batch_size: Some(1),
        batch_index: Some(0),
        batch_id: Some(1),
    };

    let encoded_payload = payload.encode_to_vec();
    let base64_payload = general_purpose::STANDARD.encode(&encoded_payload);
    let encoded_data =
        form_urlencoded::byte_serialize(base64_payload.as_bytes()).collect::<String>();

    format!("otpauth-migration://offline?data={}", encoded_data)
}

#[wasm_bindgen]
pub fn create_migration_qr(codes: Vec<OtpCode>) -> Result<String, String> {
    let uri = create_migration_uri(codes);
    qrcodegen_image::draw_base64(&uri)
}
