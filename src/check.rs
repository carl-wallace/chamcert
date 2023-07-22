use std::path::Path;
use crate::args::ChamCertArgs;
use crate::utils::get_file_as_byte_vec;
use crate::{Error, Result};

pub fn check(args: &ChamCertArgs) -> Result<()> {
    let base_bytes = match &args.check {
        Some(check) => get_file_as_byte_vec(Path::new(check)),
        None => return Err(Error::MissingParameter)
    }?;
    let delta_bytes = match &args.reference {
        Some(reference) => get_file_as_byte_vec(Path::new(reference)),
        None => return Err(Error::MissingParameter)
    }?;

    println!("{:?}", args);
    Ok(())
}