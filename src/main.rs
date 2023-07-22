use crate::args::ChamCertArgs;
use crate::utils::configure_logging;
use clap::Parser;
use crate::base::generate_base;
use crate::check::check;
use crate::request::generate_request;

pub mod args;
pub mod utils;
pub mod base;
pub mod request;
pub mod dcd;
pub mod keygen;
pub mod pqc_oids;
pub mod check;

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
    KeyError,
}
impl From<der::Error> for Error {
    fn from(err: der::Error) -> Error {
        Error::Asn1(err)
    }
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
    else if args.request.is_some() {
        if let Err(e) = generate_request(&args) {
            println!("Failed: {:?}", e);
        }
    }
    else if args.check.is_some() {
        if let Err(e) = check(&args) {
            println!("Failed: {:?}", e);
        }
    }
    else {
        println!("ERROR: you must specify either --base, --check or --csr along with required options");
    }
}
