use crate::args::ChamCertArgs;
use crate::dcd::{DeltaCertificateDescriptor, ID_CE_DELTA_CERTIFICATE_DESCRIPTOR};
use crate::utils::{buffer_to_hex, get_file_as_byte_vec};
use crate::{Error, Result};
use der::{Decode, Encode};
use std::path::Path;
use x509_cert::Certificate;

fn get_dcd(cert: &Certificate) -> Result<DeltaCertificateDescriptor> {
    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts {
            if ext.extn_id == ID_CE_DELTA_CERTIFICATE_DESCRIPTOR {
                return Ok(DeltaCertificateDescriptor::from_der(
                    ext.extn_value.as_bytes(),
                )?);
            }
        }
    }
    Err(Error::Unrecognized)
}

fn reconstruct(base: &Certificate) -> Result<Certificate> {
    let dcd = get_dcd(base)?;
    // The following procedure describes how to reconstruct a Delta Certificate from a Base Certificate:
    //
    // Create an initial Delta Certificate template by copying the Base Certificate excluding the
    // DCD extension.
    let mut initial_delta = base.clone();
    if initial_delta.tbs_certificate.extensions.is_none() {
        return Err(Error::Unrecognized);
    }

    let mut found = false;
    let mut exts = initial_delta.tbs_certificate.extensions.clone().unwrap();
    for (i, ext) in exts.iter().enumerate() {
        if ext.extn_id == ID_CE_DELTA_CERTIFICATE_DESCRIPTOR {
            exts.remove(i);
            found = true;
            break;
        }
    }
    if !found {
        return Err(Error::Unrecognized);
    }
    initial_delta.tbs_certificate.extensions = Some(exts);

    // Replace the value of the serialNumber field of the Delta Certificate template with the value
    // of the DCD extension's serialNumber field.
    initial_delta.tbs_certificate.serial_number = dcd.serial;

    // If the DCD extension contains a value for the signature field, then replace the value of the
    // signature field of the Delta Certificate template with the value of the DCD extension's
    // signature field.
    if let Some(sig) = dcd.sig_alg {
        initial_delta.tbs_certificate.signature = sig;
    }

    // If the DCD extension contains a value for the issuer field, then replace the value of the
    // issuer field of the Delta Certificate template with the value of the DCD extension's issuer
    // field.
    if let Some(issuer) = dcd.issuer {
        initial_delta.tbs_certificate.issuer = issuer;
    }

    // If the DCD extension contains a value for the validity field, then replace the value of the
    // validity field of the Delta Certificate template with the value of the DCD extension's validity field.
    if let Some(validity) = dcd.validity {
        initial_delta.tbs_certificate.validity = validity;
    }

    // Replace the value of the subjectPublicKeyInfo field of the Delta Certificate template with
    // the value of the DCD extension's subjectPublicKeyInfo field.
    initial_delta.tbs_certificate.subject_public_key_info = dcd.spki;

    // If the DCD extension contains a value for the subject field, then replace the value of the
    // subject field of the Delta Certificate template with the value of the DCD extension's
    // subject field.
    if let Some(subject) = dcd.subject {
        initial_delta.tbs_certificate.subject = subject;
    }

    // If the DCD extension contains a value for the extensions field, then iterate over the DCD
    // extension's "extensions" field, replacing the criticality and/or extension value of each
    // identified extension in the Delta Certificate template. If any extension is present in the
    // field that does not appear in the Delta Certificate template, then this reconstruction
    // process MUST fail.
    if let Some(exts) = dcd.exts {
        if initial_delta.tbs_certificate.extensions.is_none() {
            return Err(Error::Unrecognized);
        }

        let mut new_exts = initial_delta.tbs_certificate.extensions.unwrap();
        for ext in exts {
            let mut found = false;
            for text in new_exts.iter_mut() {
                if text.extn_id == ext.extn_id {
                    found = true;
                    text.critical = ext.critical;
                    text.extn_value = ext.extn_value.clone();
                }
            }
            if !found {
                return Err(Error::Unrecognized);
            }
        }
        initial_delta.tbs_certificate.extensions = Some(new_exts);
    }

    // Replace the value of the signature field of the Delta Certificate template with the value of
    // the DCD extension's signatureValue field.
    initial_delta.signature = dcd.sig_value;

    Ok(initial_delta)
}

pub fn check(args: &ChamCertArgs) -> Result<()> {
    let base_cert_bytes = match &args.check {
        Some(check) => get_file_as_byte_vec(Path::new(check)),
        None => return Err(Error::MissingParameter),
    }?;
    let delta_cert_bytes = match &args.reference {
        Some(reference) => get_file_as_byte_vec(Path::new(reference)),
        None => return Err(Error::MissingParameter),
    }?;

    let base_cert = Certificate::from_der(&base_cert_bytes)?;
    let reconstructed = reconstruct(&base_cert)?;
    let reconstructed_bytes = reconstructed.to_der()?;
    if reconstructed_bytes != delta_cert_bytes {
        println!("Reconstructed does not match");
        println!("Reference cert: {}", buffer_to_hex(&delta_cert_bytes));
        println!("Reconstructed : {}", buffer_to_hex(&reconstructed_bytes));
        return Err(Error::Unrecognized);
    } else {
        println!("Reconstructed certificate matches the reference");
    }

    Ok(())
}
