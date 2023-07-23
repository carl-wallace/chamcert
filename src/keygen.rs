use rand_core::OsRng;

#[cfg(feature = "pqc")]
use pqcrypto_dilithium::*;
#[cfg(feature = "pqc")]
use pqcrypto_falcon::{falcon1024, falcon512};
#[cfg(feature = "pqc")]
use pqcrypto_sphincsplus::*;
#[cfg(feature = "pqc")]
use pqcrypto_traits::sign::{PublicKey as OtherPublicKey, SecretKey};

use der::asn1::{BitString, OctetString, OctetStringRef};
use der::{Any, Decode, Encode};

use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::PublicKey;

use sha1::{Digest, Sha1};

use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

use certval::{
    PKIXALG_ECDSA_WITH_SHA224, PKIXALG_ECDSA_WITH_SHA256, PKIXALG_ECDSA_WITH_SHA384,
    PKIXALG_ECDSA_WITH_SHA512, PKIXALG_EC_PUBLIC_KEY, PKIXALG_SECP256R1,
};
use const_oid::ObjectIdentifier;
use pqckeys::oak::OneAsymmetricKey;
use pqckeys::pqc_oids::*;

pub fn is_ecdsa(oid: &ObjectIdentifier) -> bool {
    *oid == PKIXALG_ECDSA_WITH_SHA256
        || *oid == PKIXALG_ECDSA_WITH_SHA384
        || *oid == PKIXALG_ECDSA_WITH_SHA224
        || *oid == PKIXALG_ECDSA_WITH_SHA512
        || *oid == PKIXALG_SECP256R1
        || *oid == PKIXALG_EC_PUBLIC_KEY
}

pub fn is_diluthium2(oid: &ObjectIdentifier) -> bool {
    *oid == ENTU_DILITHIUM2 || *oid == OQ_DILITHIUM2
}

pub fn is_diluthium3(oid: &ObjectIdentifier) -> bool {
    *oid == ENTU_DILITHIUM3 || *oid == OQ_DILITHIUM3
}

pub fn is_diluthium5(oid: &ObjectIdentifier) -> bool {
    *oid == ENTU_DILITHIUM5 || *oid == OQ_DILITHIUM5
}
pub fn is_diluthium2aes(oid: &ObjectIdentifier) -> bool {
    *oid == ENTU_DILITHIUM_AES2 || *oid == OQ_DILITHIUM_AES2
}

pub fn is_diluthium3aes(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_DILITHIUM3 || *oid == ENTU_DILITHIUM_AES3 || *oid == OQ_DILITHIUM_AES3
}

pub fn is_diluthium5aes(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_DILITHIUM5 || *oid == ENTU_DILITHIUM_AES5 || *oid == OQ_DILITHIUM_AES5
}

pub fn is_falcon512(oid: &ObjectIdentifier) -> bool {
    *oid == ENTU_FALCON_512 || *oid == OQ_FALCON_512
}

pub fn is_falcon1024(oid: &ObjectIdentifier) -> bool {
    *oid == ENTU_FALCON_1024 || *oid == OQ_FALCON_1024
}

pub fn is_sphincsp_sha256_128f_robust(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_128F_ROBUST || *oid == ENTU_SPHINCSP_SHA256_128F_ROBUST
}

pub fn is_sphincsp_sha256_128f_simple(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_128F_SIMPLE || *oid == ENTU_SPHINCSP_SHA256_128F_SIMPLE
}

pub fn is_sphincsp_sha256_128s_robust(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_128S_ROBUST || *oid == ENTU_SPHINCSP_SHA256_128S_ROBUST
}

pub fn is_sphincsp_sha256_128s_simple(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_128S_SIMPLE || *oid == ENTU_SPHINCSP_SHA256_128S_SIMPLE
}

pub fn is_sphincsp_sha256_192f_robust(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_192F_ROBUST || *oid == ENTU_SPHINCSP_SHA256_192F_ROBUST
}

pub fn is_sphincsp_sha256_192f_simple(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_192F_SIMPLE || *oid == ENTU_SPHINCSP_SHA256_192F_SIMPLE
}

pub fn is_sphincsp_sha256_192s_robust(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_192S_ROBUST || *oid == ENTU_SPHINCSP_SHA256_192S_ROBUST
}

pub fn is_sphincsp_sha256_192s_simple(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_192S_SIMPLE || *oid == ENTU_SPHINCSP_SHA256_192S_SIMPLE
}

pub fn is_sphincsp_sha256_256f_robust(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_256F_ROBUST || *oid == ENTU_SPHINCSP_SHA256_256F_ROBUST
}

pub fn is_sphincsp_sha256_256f_simple(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_256F_SIMPLE || *oid == ENTU_SPHINCSP_SHA256_256F_SIMPLE
}

pub fn is_sphincsp_sha256_256s_robust(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_256S_ROBUST || *oid == ENTU_SPHINCSP_SHA256_256S_ROBUST
}

pub fn is_sphincsp_sha256_256s_simple(oid: &ObjectIdentifier) -> bool {
    *oid == OQ_SPHINCSP_SHA256_256S_SIMPLE || *oid == ENTU_SPHINCSP_SHA256_256S_SIMPLE
}

pub fn generate_keypair(
    pk_alg1: ObjectIdentifier,
    sig_alg1: ObjectIdentifier,
    skids: &mut Vec<Vec<u8>>,
    signing_keys: &mut Vec<Vec<u8>>,
    spki_algs: &mut Vec<Vec<u8>>,
    signing_algs: &mut Vec<Vec<u8>>,
    spkis: &mut Vec<Vec<u8>>,
) {
    let signature_algorithm = AlgorithmIdentifierOwned {
        oid: sig_alg1,
        parameters: None,
    };
    signing_algs.push(signature_algorithm.to_der().unwrap());

    if is_ecdsa(&sig_alg1) {
        let x = pk_alg1.to_der().unwrap();
        let spki_algorithm = AlgorithmIdentifierOwned {
            oid: PKIXALG_EC_PUBLIC_KEY,
            parameters: Some(Any::from_der(x.as_slice()).unwrap()),
        };
        spki_algs.push(spki_algorithm.to_der().unwrap());

        if pk_alg1 == PKIXALG_SECP256R1 {
            let signing_key = SigningKey::random(&mut OsRng); // Serialize with `::to_bytes()`
            let verify_key = VerifyingKey::from(&signing_key); // Serialize with `::to_encoded_point()`
            let pk = PublicKey::from_encoded_point(&verify_key.to_encoded_point(false));
            let spki = pk.unwrap().to_encoded_point(false);
            let spkibuf = spki.as_bytes();
            let enc_skid = calc_skid(spkibuf);
            skids.push(enc_skid);

            let privkey2 = signing_key.to_bytes();

            let oak_leaf = OneAsymmetricKey {
                version: pqckeys::oak::Version::V2,
                private_key_alg: spki_algorithm.clone(),
                private_key: OctetString::new(privkey2.as_slice()).unwrap(),
                attributes: None,
                public_key: None,
            };
            let oak_der = oak_leaf.to_der().unwrap();
            signing_keys.push(oak_der);

            let spki = SubjectPublicKeyInfoOwned {
                algorithm: spki_algorithm,
                subject_public_key: BitString::from_bytes(spkibuf).unwrap(),
            };
            spkis.push(spki.to_der().unwrap());
        }
    } else {
        let spki_algorithm = AlgorithmIdentifierOwned {
            oid: pk_alg1,
            parameters: None,
        };
        spki_algs.push(spki_algorithm.to_der().unwrap());

        #[cfg(feature = "pqc")]
        let (pk, sk) = if is_diluthium2(&pk_alg1) {
            let (pk, sk) = dilithium2::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_diluthium3(&pk_alg1) {
            let (pk, sk) = dilithium3::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_diluthium5(&pk_alg1) {
            let (pk, sk) = dilithium5::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_diluthium2aes(&pk_alg1) {
            let (pk, sk) = dilithium2aes::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_diluthium3aes(&pk_alg1) {
            let (pk, sk) = dilithium3aes::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_diluthium5aes(&pk_alg1) {
            let (pk, sk) = dilithium5aes::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_falcon512(&pk_alg1) {
            let (pk, sk) = falcon512::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_falcon1024(&pk_alg1) {
            let (pk, sk) = falcon1024::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_128f_robust(&pk_alg1) {
            let (pk, sk) = sphincssha256128frobust::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_128f_simple(&pk_alg1) {
            let (pk, sk) = sphincssha256128fsimple::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_128s_robust(&pk_alg1) {
            let (pk, sk) = sphincssha256128srobust::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_128s_simple(&pk_alg1) {
            let (pk, sk) = sphincssha256128ssimple::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_192f_robust(&pk_alg1) {
            let (pk, sk) = sphincssha256192frobust::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_192f_simple(&pk_alg1) {
            let (pk, sk) = sphincssha256192fsimple::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_192s_robust(&pk_alg1) {
            let (pk, sk) = sphincssha256192srobust::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_192s_simple(&pk_alg1) {
            let (pk, sk) = sphincssha256192ssimple::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_256f_robust(&pk_alg1) {
            let (pk, sk) = sphincssha256256frobust::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_256f_simple(&pk_alg1) {
            let (pk, sk) = sphincssha256256fsimple::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_256s_robust(&pk_alg1) {
            let (pk, sk) = sphincssha256256srobust::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else if is_sphincsp_sha256_256s_simple(&pk_alg1) {
            let (pk, sk) = sphincssha256256ssimple::keypair();
            (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
        } else {
            panic!()
        };
        //let vspkibuf = OctetString::new(pk).unwrap().to_vec().unwrap();
        //let spkibuf = vspkibuf.as_slice();
        let spkibuf = pk.as_slice();
        let enc_skid = calc_skid(spkibuf);
        skids.push(enc_skid);
        signing_keys.push(sk);
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: spki_algorithm,
            subject_public_key: BitString::from_bytes(spkibuf).unwrap(),
        };
        spkis.push(spki.to_der().unwrap());
    }
}

pub fn calc_skid(spkibuf: &[u8]) -> Vec<u8> {
    let spki_hash = Sha1::digest(spkibuf).to_vec();
    let skid = OctetStringRef::new(spki_hash.as_slice()).unwrap();
    skid.to_der().unwrap()
}
