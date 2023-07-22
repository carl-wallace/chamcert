use crate::args::ChamCertArgs;
use crate::utils::configure_logging;
use clap::Parser;
use crate::base::generate_base;
use crate::csr::generate_csr;

mod args;
mod utils;
mod base;
mod csr;

/// Error type for chamcert
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[allow(dead_code)]
pub enum Error {
    BadInput,
    Config,
    Io,
    Unrecognized,
    ParseError,
    /// Asn1Error is used to propagate error information from the x509 crate.
    Asn1(der::Error),
    Signature,
    MissingParameter,
}

/// Result type for chamcert
pub type Result<T> = core::result::Result<T, Error>;

fn main() {
    let args = ChamCertArgs::parse();
    configure_logging(&args);

    if args.base.is_some() {
        if let Err(e) = generate_base(&args) {
            println!("Failed: {:?}", e);
        }
    }
    else if args.csr.is_some() {
        if let Err(e) = generate_csr(&args) {
            println!("Failed: {:?}", e);
        }
    }
    else {
        println!("ERROR: you must specify either --base or --csr along with required options");
    }
}
