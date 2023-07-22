use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use const_oid::db::rfc5912::{ECDSA_WITH_SHA_256, SECP_256_R_1};
use der::asn1::{BitString, OctetString, UtcTime};
use crate::args::ChamCertArgs;
use crate::utils::{generate_signature, get_file_as_byte_vec};
use crate::{Error, Result};
use x509_cert::{Certificate, TbsCertificate, Version};
use der::{Decode, Encode, EncodePem};
use der::pem::LineEnding;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use crate::dcd::{DeltaCertificateDescriptor, ID_CE_DELTA_CERTIFICATE_DESCRIPTOR};
use crate::keygen::generate_keypair;
use rand_core::OsRng;
use rand_core::RngCore;
use x509_cert::ext::Extension;

/// Takes a delta certificate, a CA signing key and a CA signing certificate and generates a base
/// certificate featuring a deltaCertificateDescriptor extension containing the dehydrated delta.
/// The delta additionally serves as a (partial) template for the base certificate when no template
/// cert is provided.
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

    let ca_cert = Certificate::from_der(&ca_cert_bytes)?;
    let delta_cert = Certificate::from_der(&delta_cert_bytes)?;

    let template_cert = match &args.template_cert {
        Some(template_cert) => {
            let template_cert_bytes = get_file_as_byte_vec(Path::new(template_cert))?;
            Certificate::from_der(&template_cert_bytes)?
        }
        None => {delta_cert.clone()}
    };

    let ten_years_duration = Duration::from_secs(365 * 24 * 60 * 60 * 10);
    let ten_years_time = match SystemTime::now().checked_add(ten_years_duration) {
        Some(t) => t,
        None => return Err(Error::Unrecognized),
    };
    let not_after = Time::UtcTime(
        UtcTime::from_unix_duration(
            ten_years_time
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Unrecognized)?,
        )
            .map_err(|_| Error::Unrecognized)?,
    );
    let base_validity = Validity {
        not_before: Time::UtcTime(
            UtcTime::from_unix_duration(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| Error::Unrecognized)?,
            )
                .map_err(|_| Error::Unrecognized)?,
        ),
        not_after,
    };
    // The signature of the Delta Certificate must be known so that its value can be included in
    // the signatureValue field of the delta certificate descriptor extension. Given this, Delta
    // Certificate will necessarily need to be issued prior to the issuance of the Base Certificate.

    // After the Delta Certificate is issued, the certification authority compares the signature,
    // issuer, validity, subject, subjectPublicKeyInfo, and extensions fields of the Delta
    // Certificate and the to-be-signed certificate which will contain the DCD extension. The
    // certification authority then populates the DCD extension with the values of the fields which
    // differ from the Base Certificate. The CA MUST encode extensions in the Base Certificate in
    // the same order used for the Delta Certificate, with the exception of the DCD extension itself.
    let sig_alg = if template_cert.tbs_certificate.signature != delta_cert.tbs_certificate.signature {
        Some(delta_cert.tbs_certificate.signature.clone())
    }
    else {
        None
    };
    let issuer = if template_cert.tbs_certificate.issuer != delta_cert.tbs_certificate.issuer {
        Some(delta_cert.tbs_certificate.issuer.clone())
    }
    else {
        None
    };
    let validity = if base_validity != delta_cert.tbs_certificate.validity {
        Some(delta_cert.tbs_certificate.validity.clone())
    }
    else {
        None
    };
    let subject = if template_cert.tbs_certificate.subject != delta_cert.tbs_certificate.subject {
        Some(delta_cert.tbs_certificate.subject.clone())
    }
    else {
        None
    };
    let exts = if template_cert.tbs_certificate.extensions != delta_cert.tbs_certificate.extensions {
        delta_cert.tbs_certificate.extensions.clone()
    }
    else {
        None
    };

    let dcd = DeltaCertificateDescriptor{
        serial: delta_cert.tbs_certificate.serial_number.clone(),
        sig_alg,
        issuer,
        validity,
        subject,
        spki: delta_cert.tbs_certificate.subject_public_key_info.clone(),
        exts,
        sig_value: delta_cert.signature,
    };

    // The certification authority then adds the computed DCD extension to the to-be-signed Base
    // Certificate and signs the Base Certificate.

    // Just doing EC in the base for now: SECP_256_R_1 and ECDSA_WITH_SHA_256
    let mut skids = vec![];
    let mut signing_keys = vec![];
    let mut spki_algs = vec![];
    let mut signing_algs = vec![];
    let mut spkis = vec![];
    generate_keypair(
        SECP_256_R_1,
        ECDSA_WITH_SHA_256,
        &mut skids,
        &mut signing_keys,
        &mut spki_algs,
        &mut signing_algs,
        &mut spkis,
    );

    let public_key = spkis.get(0).unwrap();

    let mut serial = [0u8; 20];
    OsRng.fill_bytes(&mut serial);
    serial[0] = 0x01;
    let serial = SerialNumber::new(&serial[..]).expect("serial can't be more than 20 bytes long");

    let mut exts = template_cert.tbs_certificate.extensions.unwrap();
    exts.push(Extension{
        extn_id: ID_CE_DELTA_CERTIFICATE_DESCRIPTOR,
        critical: true,
        extn_value: OctetString::new(dcd.to_der()?)?,
    });

    let sig_alg = AlgorithmIdentifierOwned{ oid: ECDSA_WITH_SHA_256, parameters: None };
    let tbs_certificate = TbsCertificate {
        version: Version::V3,
        serial_number: serial,
        signature: sig_alg.clone(),
        issuer: ca_cert.tbs_certificate.subject.clone(),
        validity: base_validity,
        subject: template_cert.tbs_certificate.subject,
        subject_public_key_info: SubjectPublicKeyInfoOwned::from_der(public_key)?,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(exts),
    };

    let sig = generate_signature(&ECDSA_WITH_SHA_256, &ca_key_bytes, &tbs_certificate.to_der()?);
    let cert = Certificate{
        tbs_certificate,
        signature_algorithm: sig_alg,
        signature: BitString::new(0, sig)?,
    };

    let der_cert = cert.to_der()?;
    if let Some(output) = &args.base {
        let p = Path::new(output.as_str());
        match fs::write(&p, der_cert) {
            Ok(_) => {}
            Err(e) => {
                println!(
                    "Failed to write base certificate to {output} with error: {:?}",
                    e
                );
            }
        }
    }
    println!("{}", cert.to_pem(LineEnding::LF)?);

    Ok(())
}