use crate::args::ChamCertArgs;
use crate::dcd::{
    DeltaCertificateRequestSignatureValue, DeltaCertificateRequestValue,
    ID_CE_DELTA_CERTIFICATE_REQUEST, ID_CE_DELTA_CERTIFICATE_SIGNATURE,
};
use crate::utils::get_file_as_byte_vec;
use crate::{Error, Result};
use certval::{populate_5280_pki_environment, verify_signature_message_pqcrypto, PkiEnvironment};
use der::asn1::SetOfVec;
use der::{Decode, Encode};
use std::path::Path;
use x509_cert::request::{CertReq, CertReqInfo};

fn get_dcr(cri: &CertReqInfo) -> Result<DeltaCertificateRequestValue> {
    for attr in cri.attributes.iter() {
        if attr.oid == ID_CE_DELTA_CERTIFICATE_REQUEST {
            return Ok(DeltaCertificateRequestValue::from_der(
                &attr.values.get(0).unwrap().to_der()?,
            )?);
        }
    }
    Err(Error::Unrecognized)
}
fn get_and_remove_delta_sig(
    cri: &mut CertReqInfo,
) -> Result<DeltaCertificateRequestSignatureValue> {
    let mut retval = None;
    let mut new_attrs = SetOfVec::new();
    for attr in cri.attributes.iter() {
        if attr.oid == ID_CE_DELTA_CERTIFICATE_SIGNATURE {
            retval = Some(DeltaCertificateRequestSignatureValue::from_der(
                &attr.values.get(0).unwrap().to_der()?,
            )?);
        } else {
            new_attrs.insert(attr.clone())?;
        }
    }
    cri.attributes = new_attrs;
    if let Some(retval) = retval {
        Ok(retval)
    } else {
        Err(Error::Unrecognized)
    }
}
pub fn request_check(args: &ChamCertArgs) -> Result<()> {
    let csr_bytes = match &args.request_check {
        Some(check) => get_file_as_byte_vec(Path::new(check)),
        None => return Err(Error::MissingParameter),
    }?;

    let mut csr = CertReq::from_der(&csr_bytes)?;

    let mut pe = PkiEnvironment::default();
    populate_5280_pki_environment(&mut pe);
    #[cfg(feature = "pqc")]
    pe.add_verify_signature_message_callback(verify_signature_message_pqcrypto);

    let der_info = csr.info.to_der()?;
    pe.verify_signature_message(
        &pe,
        &der_info,
        csr.signature.raw_bytes(),
        &csr.algorithm,
        &csr.info.public_key,
    )?;

    let delta_sig = get_and_remove_delta_sig(&mut csr.info)?;
    let dcd = get_dcr(&csr.info)?;
    let der_info_delta = csr.info.to_der()?;
    pe.verify_signature_message(
        &pe,
        &der_info_delta,
        delta_sig.raw_bytes(),
        &csr.algorithm,
        &dcd.spki,
    )?;

    println!("Success");
    Ok(())
}
