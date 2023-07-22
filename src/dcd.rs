use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::BitString;
use der::{Sequence, ValueOrd};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::ext::Extension;
use x509_cert::ext::{AsExtension, Extensions};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

/// id-ce-deltaCertificateDescriptor OBJECT IDENTIFIER ::= {
///    joint-iso-itu-t(2) country(16) us(840) organization(1)
///    entrust(114027) 80 6 1
/// }
pub const ID_CE_DELTA_CERTIFICATE_DESCRIPTOR: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.6.1");

/// DeltaCertificateDescriptor ::= SEQUENCE {
///   serialNumber          CertificateSerialNumber,
///   signature             [0] IMPLICIT AlgorithmIdentifier
///        {SIGNATURE_ALGORITHM, {...}} OPTIONAL,
///   issuer                [1] IMPLICIT Name OPTIONAL,
///   validity              [2] IMPLICIT Validity OPTIONAL,
///   subject               [3] IMPLICIT Name OPTIONAL,
///   subjectPublicKeyInfo  SubjectPublicKeyInfo,
///   extensions            [4] IMPLICIT Extensions{CertExtensions}
///        OPTIONAL,
///   signatureValue        BIT STRING
/// }
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct DeltaCertificateDescriptor {
    pub serial: SerialNumber,

    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub sig_alg: Option<AlgorithmIdentifierOwned>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub issuer: Option<Name>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub validity: Option<Validity>,

    #[asn1(context_specific = "3", tag_mode = "IMPLICIT", optional = "true")]
    pub subject: Option<Name>,

    pub spki: SubjectPublicKeyInfoOwned,

    #[asn1(context_specific = "4", tag_mode = "IMPLICIT", optional = "true")]
    pub exts: Option<Extensions>,

    pub sig_value: BitString,
}

impl AsExtension for DeltaCertificateDescriptor {
    fn critical(&self, _subject: &Name, _extensions: &[Extension]) -> bool {
        true
    }
}
impl AssociatedOid for DeltaCertificateDescriptor {
    const OID: ObjectIdentifier = ID_CE_DELTA_CERTIFICATE_DESCRIPTOR;
}
