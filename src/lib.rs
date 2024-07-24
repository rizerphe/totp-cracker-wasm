use rayon::prelude::*;
use totp_rs::{Algorithm, TOTP};

use wasm_bindgen::prelude::*;
mod migration;

pub use migration::{create_migration_qr, create_migration_uri, OtpCode};
pub use wasm_bindgen_rayon::init_thread_pool;

fn starting_secret(
    thread_id: usize,
    attempt_no: usize,
    n_iterations: usize,
    n_threads: usize,
) -> Vec<u8> {
    let mut secret: Vec<u8> = vec![0; 20];

    // Set last digits depending on attempt_no and thread_id
    let mut starting_point = (attempt_no * n_threads + thread_id) * n_iterations;
    let mut i = 0;
    while starting_point > 0 {
        secret[i] = (starting_point % 256) as u8;
        starting_point /= 256;
        i += 1;
        if i >= secret.len() {
            break;
        }
    }

    secret
}

fn try_choose_secret(
    target_time: u64,
    target_token: String,
    n_threads: usize,
    thread_id: usize,
    attempt_no: usize,
    iterations: usize,
) -> Option<Vec<u8>> {
    let mut secret: Vec<u8> = starting_secret(thread_id, attempt_no, iterations, n_threads);

    let mut totp = TOTP::new(
        Algorithm::SHA1,
        target_token.len(),
        1,
        30,
        secret.clone(),
        None,
        "".to_string(),
    )
    .unwrap();

    for _ in 0..iterations {
        // Increment secret
        for i in 0..secret.len() {
            secret[i] += 1;
            if secret[i] != 0 {
                break;
            }
        }
        totp.secret = secret.clone();

        let token = totp.generate(target_time);
        if token == target_token {
            return Some(secret);
        }
    }
    return None;
}

fn verify_target_token(token: String) -> bool {
    // Make sure the token is all digits, at least 6 long,
    // and at most 8 long
    if token.len() < 6 || token.len() > 8 {
        return false;
    }
    for c in token.chars() {
        if !c.is_digit(10) {
            return false;
        }
    }
    true
}

#[wasm_bindgen]
pub fn try_find(
    target_time: u64,
    target_token: String,
    n_threads: usize,
    attempt_no: usize,
    iterations: usize,
    job_id: usize,
) -> Result<Option<Vec<u8>>, String> {
    if !verify_target_token(target_token.clone()) {
        return Err("Invalid target token".to_string());
    }

    let v = (0..n_threads).collect::<Vec<_>>();

    // try to find one per thread
    let found = v
        .par_iter()
        .map(|i| {
            let totp = try_choose_secret(
                target_time,
                target_token.clone(),
                n_threads,
                *i,
                attempt_no + job_id * 100_000,
                iterations,
            );
            totp
        })
        .collect::<Vec<_>>();

    // find the first one that is not None
    for f in found {
        if f.is_some() {
            return Ok(f);
        }
    }
    Ok(None)
}

#[wasm_bindgen]
pub fn get_qr_code(
    secret: Vec<u8>,
    issuer: Option<String>,
    account_name: String,
    n_digits: usize,
) -> Result<String, String> {
    let totp = TOTP::new(
        Algorithm::SHA1,
        n_digits,
        1,
        30,
        secret,
        issuer,
        account_name,
    )
    .unwrap();
    totp.get_qr_base64()
}
