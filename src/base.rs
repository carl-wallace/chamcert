use std::path::Path;
use crate::args::ChamCertArgs;
use crate::utils::get_file_as_byte_vec;
use crate::{Error, Result};

pub fn generate_base(args: &ChamCertArgs) -> Result<()> {
    let ca_cert_bytes = match &args.ca_cert {
        Some(ca_cert) => get_file_as_byte_vec(Path::new(ca_cert)),
        None => return Err(Error::MissingParameter)
    }?;
    let ca_key_bytes = match &args.ca_key {
        Some(ca_key) => get_file_as_byte_vec(Path::new(ca_key)),
        None => return Err(Error::MissingParameter)
    }?;
    let delta_cert_bytes = match &args.delta {
        Some(delta) => get_file_as_byte_vec(Path::new(delta)),
        None => return Err(Error::MissingParameter)
    }?;

    println!("{:?}", args);
    Ok(())
}