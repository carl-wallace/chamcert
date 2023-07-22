use crate::args::ChamCertArgs;
use crate::utils::get_file_as_byte_vec;
use crate::{Error, Result};
use std::path::Path;

pub fn generate_request(args: &ChamCertArgs) -> Result<()> {
    let _template_cert_bytes = match &args.template_cert {
        Some(template_cert) => get_file_as_byte_vec(Path::new(template_cert)),
        None => return Err(Error::MissingParameter),
    }?;

    println!("This has not been implemented yet");
    Ok(())
}
