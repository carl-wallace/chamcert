use std::path::Path;
use crate::args::ChamCertArgs;
use crate::{Error, Result};
use crate::utils::get_file_as_byte_vec;

pub fn generate_request(args: &ChamCertArgs) -> Result<()> {
    let template_cert_bytes = match &args.template_cert {
        Some(template_cert) => get_file_as_byte_vec(Path::new(template_cert)),
        None => return Err(Error::MissingParameter)
    }?;

    println!("{:?}", args);
    Ok(())
}