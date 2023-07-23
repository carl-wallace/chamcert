use crate::args::ChamCertArgs;
use crate::utils::{generate_signature, get_file_as_byte_vec, get_public_key_alg};
use crate::{Error, Result};
use const_oid::ObjectIdentifier;
use der::asn1::BitString;
use der::{Any, Decode, Encode, EncodePem};
use std::fs;
use std::path::Path;
use std::str::FromStr;

use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfo, SubjectPublicKeyInfoOwned};

use x509_cert::attr::{Attribute, Attributes};
use x509_cert::request::*;
use x509_cert::{ext::Extensions, name::Name, Certificate};

use crate::dcd::{
    DeltaCertificateRequestValue, ID_CE_DELTA_CERTIFICATE_REQUEST,
    ID_CE_DELTA_CERTIFICATE_SIGNATURE,
};
use crate::keygen::generate_keypair;
use const_oid::db::rfc5912::ID_EXTENSION_REQ;
use der::pem::LineEnding;

pub fn generate_request(args: &ChamCertArgs) -> Result<()> {
    let template_cert_bytes = match &args.template_cert {
        Some(template_cert) => get_file_as_byte_vec(Path::new(template_cert)),
        None => return Err(Error::MissingParameter),
    }?;

    let template_cert = Certificate::from_der(&template_cert_bytes)?;

    let mut skids = vec![];
    let mut signing_keys = vec![];
    let mut spki_algs = vec![];
    let mut signing_algs = vec![];
    let mut spkis = vec![];

    let pk_alg = get_public_key_alg(&template_cert)?;

    generate_keypair(
        pk_alg,
        template_cert.signature_algorithm.oid,
        &mut skids,
        &mut signing_keys,
        &mut spki_algs,
        &mut signing_algs,
        &mut spkis,
    );

    if let Some(oidstr) = &args.delta_pk_alg {
        let delta_pk = ObjectIdentifier::from_str(oidstr)?;

        let delta_sig = if let Some(oidstr) = &args.delta_sig_alg {
            ObjectIdentifier::from_str(oidstr)?
        } else {
            delta_pk
        };
        generate_keypair(
            delta_pk,
            delta_sig,
            &mut skids,
            &mut signing_keys,
            &mut spki_algs,
            &mut signing_algs,
            &mut spkis,
        );
    } else {
        generate_keypair(
            pk_alg,
            template_cert.signature_algorithm.oid,
            &mut skids,
            &mut signing_keys,
            &mut spki_algs,
            &mut signing_algs,
            &mut spkis,
        );
    }

    let dcrv = DeltaCertificateRequestValue {
        subject: None,
        spki: SubjectPublicKeyInfoOwned::from_der(spkis.get(1).unwrap())?,
        exts: None,
        sig_alg: None,
    };

    let mut spki_algs_parsed = vec![];
    for spki_alg in spki_algs {
        spki_algs_parsed.push(AlgorithmIdentifierOwned::from_der(&spki_alg)?);
    }

    let csr = generate_csr(
        spkis,
        &template_cert.tbs_certificate.subject,
        &template_cert.tbs_certificate.extensions,
        spki_algs_parsed,
        &signing_keys,
        &template_cert.signature_algorithm,
        &dcrv,
    )?;
    let csr_bytes = csr.to_der()?;

    if let Some(output) = &args.request {
        let p = Path::new(output.as_str());
        match fs::write(p, csr_bytes) {
            Ok(_) => {}
            Err(e) => {
                println!(
                    "Failed to write base certificate to {output} with error: {:?}",
                    e
                );
            }
        }
    }
    println!("{}", csr.to_pem(LineEnding::LF)?);
    Ok(())
}

/// Generate a certificate request containing the given name, public key and extensions
pub fn generate_csr(
    spkibufs: Vec<Vec<u8>>,
    subject: &Name,
    extensions: &Option<Extensions>,
    spki_algs: Vec<AlgorithmIdentifierOwned>,
    signing_key_bytes: &[Vec<u8>],
    signing_alg: &AlgorithmIdentifierOwned,
    dcrv: &DeltaCertificateRequestValue,
) -> Result<CertReq> {
    let spki = SubjectPublicKeyInfo::<Any, BitString>::from_der(spkibufs.get(0).unwrap()).unwrap();

    let mut attributes = Attributes::new();
    let mut er_attr = Attribute {
        oid: ID_EXTENSION_REQ,
        values: Default::default(),
    };
    let er_attr_val = extensions.to_der().unwrap();
    let _r = er_attr
        .values
        .insert(Any::from_der(er_attr_val.as_slice()).unwrap());
    let _r = attributes.insert(er_attr);

    let mut dcrv_attr = Attribute {
        oid: ID_CE_DELTA_CERTIFICATE_REQUEST,
        values: Default::default(),
    };
    let dcrv_attr_val = dcrv.to_der().unwrap();
    dcrv_attr
        .values
        .insert(Any::from_der(dcrv_attr_val.as_slice()).unwrap())?;
    attributes.insert(dcrv_attr)?;

    let info = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject: subject.clone(),
        public_key: spki.clone(),
        attributes: attributes.clone(),
    };

    let tbs_cert = info.to_der()?;

    let spki_alg1 = spki_algs.get(0).unwrap();

    let s2 = generate_signature(
        &spki_alg1.oid,
        signing_key_bytes.get(1).unwrap(),
        tbs_cert.as_slice(),
    );
    let signature2 = BitString::from_bytes(s2.as_slice()).unwrap();
    let signature2_der = signature2.to_der()?;
    let mut sig_attr = Attribute {
        oid: ID_CE_DELTA_CERTIFICATE_SIGNATURE,
        values: Default::default(),
    };
    sig_attr
        .values
        .insert(Any::from_der(signature2_der.as_slice()).unwrap())?;
    attributes.insert(sig_attr)?;

    let info_with_delta = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject: subject.clone(),
        public_key: spki,
        attributes,
    };
    let tbs_cert_with_delta = info_with_delta.to_der()?;

    let s = generate_signature(
        &spki_alg1.oid,
        signing_key_bytes.get(0).unwrap(),
        tbs_cert_with_delta.as_slice(),
    );
    let signature = BitString::from_bytes(s.as_slice()).unwrap();

    Ok(CertReq {
        info: info_with_delta,
        algorithm: signing_alg.clone(),
        signature,
    })
}
