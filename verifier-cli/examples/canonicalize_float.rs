use std::process::ExitCode;

use vestrix_verifier_cli::canonical::canonicalize_float;

fn main() -> ExitCode {
    for bits_hex in std::env::args().skip(1) {
        if bits_hex.len() != 16 {
            eprintln!("invalid binary64 hex {bits_hex:?}: expected 16 hex characters");
            return ExitCode::from(2);
        }
        let bits = match u64::from_str_radix(&bits_hex, 16) {
            Ok(bits) => bits,
            Err(error) => {
                eprintln!("invalid binary64 hex {bits_hex:?}: {error}");
                return ExitCode::from(2);
            }
        };
        let rendered =
            canonicalize_float(f64::from_bits(bits)).unwrap_or_else(|_| "<rejected>".to_owned());
        println!("{bits_hex}\t{rendered}");
    }
    ExitCode::SUCCESS
}
