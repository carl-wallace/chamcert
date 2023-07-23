//! Utility functions used by the pbyk utility

use crate::args::ChamCertArgs;
use crate::keygen::*;
use const_oid::ObjectIdentifier;
use log::LevelFilter;
use log4rs::{
    append::console::ConsoleAppender,
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
};
use p256::ecdsa::{signature::Signer, Signature};

#[cfg(feature = "pqc")]
use pqcrypto_dilithium::*;
#[cfg(feature = "pqc")]
use pqcrypto_falcon::{falcon1024, falcon512};
#[cfg(feature = "pqc")]
use pqcrypto_sphincsplus::*;
use pqcrypto_traits::sign::DetachedSignature;
#[cfg(feature = "pqc")]
use pqcrypto_traits::sign::SecretKey;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use der::Decode;
use pqckeys::oak::PrivateKeyInfo;
use subtle_encoding::hex;

/// Configures logging per logging-related elements of the provided [PbYkArgs] instance
pub(crate) fn configure_logging(args: &ChamCertArgs) {
    let mut logging_configured = false;

    if let Some(logging_config) = &args.logging_config {
        if let Err(e) = log4rs::init_file(logging_config, Default::default()) {
            println!(
                "ERROR: failed to configure logging using {} with {:?}. Continuing without logging.",
                logging_config, e
            );
        } else {
            logging_configured = true;
        }
    }

    if !logging_configured && args.log_to_console {
        // if there's no config, prepare one using stdout
        let stdout = ConsoleAppender::builder()
            .encoder(Box::new(PatternEncoder::new("{m}{n}")))
            .build();
        match Config::builder()
            .appender(Appender::builder().build("stdout", Box::new(stdout)))
            .build(Root::builder().appender("stdout").build(LevelFilter::Info))
        {
            Ok(config) => {
                let handle = log4rs::init_config(config);
                if let Err(e) = handle {
                    println!(
                        "ERROR: failed to configure logging for stdout with {:?}. Continuing without logging.",
                        e
                    );
                }
            }
            Err(e) => {
                println!("ERROR: failed to prepare default logging configuration with {:?}. Continuing without logging", e);
            }
        }
    }
}

/// `get_file_as_byte_vec` provides support for reading artifacts from file when PITTv3 is built using
/// the `std_app` feature.
pub fn get_file_as_byte_vec(filename: &Path) -> crate::Result<Vec<u8>> {
    // match File::open(filename) {
    //     Ok(mut f) => match std::fs::metadata(filename) {
    //         Ok(metadata) => {
    //             let mut buffer = vec![0; metadata.len() as usize];
    //             match f.read_exact(&mut buffer) {
    //                 Ok(_) => Ok(buffer),
    //                 Err(_e) => Err(Error::Unrecognized),
    //             }
    //         }
    //         Err(_e) => Err(Error::Unrecognized),
    //     },
    //     Err(e) => Err(Error::Unrecognized),
    // }
    let mut f = File::open(filename)?;
    let metadata = std::fs::metadata(filename)?;
    let mut buffer = vec![0; metadata.len() as usize];
    f.read_exact(&mut buffer)?;
    Ok(buffer)
}

/// Takes a buffer and returns a String containing an ASCII hex representation of the buffer's contents
pub fn buffer_to_hex(buffer: &[u8]) -> String {
    let hex = hex::encode_upper(buffer);
    let r = std::str::from_utf8(hex.as_slice());
    if let Ok(s) = r {
        s.to_string()
    } else {
        "".to_string()
    }
}

pub fn generate_signature(
    spki_algorithm: &ObjectIdentifier,
    private_key_info_bytes: &[u8],
    tbs_cert: &[u8],
) -> Vec<u8> {

    let oak = match PrivateKeyInfo::from_der(&private_key_info_bytes) {
        Ok(oak) => oak,
        Err(_e) => panic!()
    };
    let signing_key_bytes = oak.private_key.as_bytes();

    let s = if is_diluthium2(spki_algorithm) {
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = dilithium2::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_diluthium3(spki_algorithm) {
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = dilithium3::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_diluthium5(spki_algorithm) {
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = dilithium5::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_diluthium2aes(spki_algorithm) {
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = dilithium2aes::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_diluthium3aes(spki_algorithm) {
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = dilithium3aes::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_diluthium5aes(spki_algorithm) {
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = dilithium5aes::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_falcon512(spki_algorithm) {
        // let (pk, sk) = falcon512::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = falcon512::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_falcon1024(spki_algorithm) {
        // let (pk, sk) = falcon1024::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = falcon1024::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_128f_robust(spki_algorithm) {
        // let (pk, sk) = sphincssha256128frobust::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256128frobust::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_128f_simple(spki_algorithm) {
        // let (pk, sk) = sphincssha256128fsimple::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256128fsimple::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_128s_robust(spki_algorithm) {
        // let (pk, sk) = sphincssha256128srobust::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256128srobust::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_128s_simple(spki_algorithm) {
        // let (pk, sk) = sphincssha256128ssimple::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256128ssimple::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_192f_robust(spki_algorithm) {
        // let (pk, sk) = sphincssha256192frobust::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256192frobust::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_192f_simple(spki_algorithm) {
        // let (pk, sk) = sphincssha256192fsimple::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256192fsimple::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_192s_robust(spki_algorithm) {
        // let (pk, sk) = sphincssha256192srobust::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256192srobust::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_192s_simple(spki_algorithm) {
        // let (pk, sk) = sphincssha256192ssimple::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256192ssimple::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_256f_robust(spki_algorithm) {
        // let (pk, sk) = sphincssha256256frobust::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256256frobust::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_256f_simple(spki_algorithm) {
        // let (pk, sk) = sphincssha256256fsimple::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256256fsimple::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_256s_robust(spki_algorithm) {
        // let (pk, sk) = sphincssha256256srobust::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256256srobust::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_sphincsp_sha256_256s_simple(spki_algorithm) {
        // let (pk, sk) = sphincssha256256ssimple::keypair();
        let sk = SecretKey::from_bytes(signing_key_bytes).unwrap();
        let sm = sphincssha256256ssimple::detached_sign(tbs_cert, &sk);
        sm.as_bytes().to_vec()
    } else if is_ecdsa(spki_algorithm) {
        let signing_key = p256::ecdsa::SigningKey::from_bytes(signing_key_bytes.into()).unwrap();

        let ecsignature: Signature = signing_key.sign(tbs_cert);
        let derecsignature = ecsignature.to_der();
        derecsignature.as_bytes().to_vec()
    } else {
        panic!()
    };
    s
}
