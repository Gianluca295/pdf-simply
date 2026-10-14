//! Enveloped signed files (`.p7m`): CAdES-BES with the document inside the signature, the form
//! Italian public administrations and the AgID rules (Determinazione 147/2019) expect.
//!
//! A `.p7m` is a CMS SignedData (RFC 5652) whose encapsulated content is the signed file itself
//! (a PDF, usually). [`sign`] writes one with the signed attributes CAdES-BES needs:
//! content-type, signing-time, message-digest and signing-certificate-v2 (SHA-256).
//! [`open`] reads one back: DER or base64 (PEM-style or bare), and nested envelopes
//! (`file.pdf.p7m.p7m`, a document signed again by a second signer), and checks each signature.
//!
//! What [`open`] does not do: online revocation checks (OCSP/CRL) and the EU Trusted Lists. A
//! signer whose chain doesn't reach a certificate in the caller's [`TrustStore`] is reported as
//! intact but not trusted, never as valid.

use crate::SignError;
use crate::cms::{DATA, SIGNED_DATA, SignedData};
use crate::der::{self, Time, tag};
use crate::keys::{DigestAlg, PrivateKey};
use crate::pdf::TrustStore;
use crate::x509::{Certificate, build_chain};

const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
const SIGNING_CERT_V2: &str = "1.2.840.113549.1.9.16.2.47";

/// Envelopes inside envelopes are followed this deep, no deeper.
const MAX_NESTING: usize = 8;
/// A base64 `.p7m` larger than this is refused rather than decoded.
const MAX_BASE64: usize = 512 * 1024 * 1024;

/// Sign `content` into a `.p7m` (CAdES-BES, content attached). `time` is the signing time the
/// signature states (the signer's clock: a timestamp from an authority is a separate step).
/// `chain` holds the issuers to embed after the signer's certificate.
pub fn sign(key: &PrivateKey, cert: &Certificate, chain: &[Certificate], alg: DigestAlg, content: &[u8], time: Time) -> Result<Vec<u8>, SignError> {
    let cert_hash = DigestAlg::Sha256.digest(&[&cert.raw]);
    let general_names = der::seq(&[&der::explicit(4, &cert.issuer.raw)]);
    let ess = der::seq(&[&der::seq(&[&der::seq(&[&der::octets(&cert_hash), &der::seq(&[&general_names, &der::uint(&cert.serial)])])])]);
    let attrs = [
        attribute(CONTENT_TYPE, &der::oid(DATA)),
        attribute(SIGNING_TIME, &time_value(time)?),
        attribute(MESSAGE_DIGEST, &der::octets(&alg.digest(&[content]))),
        attribute(SIGNING_CERT_V2, &ess),
    ];
    let refs: Vec<&[u8]> = attrs.iter().map(Vec::as_slice).collect();
    let set = der::set_of(&refs);
    let signature = key.sign(alg, &set)?;
    // The attributes are signed as a SET and carried as [0] IMPLICIT: same bytes, other tag.
    let mut signed_attrs = set;
    if let Some(first) = signed_attrs.first_mut() {
        *first = tag::ctx(0);
    }
    let sid = der::seq(&[&cert.issuer.raw, &der::uint(&cert.serial)]);
    let signer = der::seq(&[&der::int(1), &sid, &alg.algorithm(), &signed_attrs, &key.signature_algorithm(alg), &der::octets(&signature)]);
    let mut certs: Vec<&[u8]> = vec![&cert.raw];
    certs.extend(chain.iter().filter(|c| c.raw != cert.raw).map(|c| c.raw.as_slice()));
    let encap = der::seq(&[&der::oid(DATA), &der::explicit(0, &der::octets(content))]);
    let signed_data =
        der::seq(&[&der::int(1), &der::set_of(&[&alg.algorithm()]), &encap, &der::tlv(tag::ctx(0), &certs.concat()), &der::set_of(&[&signer])]);
    Ok(der::seq(&[&der::oid(SIGNED_DATA), &der::explicit(0, &signed_data)]))
}

/// The file name a signed copy gets: `name.pdf` becomes `name.pdf.p7m`.
pub fn signed_file_name(name: &str) -> String {
    format!("{name}.p7m")
}

/// The file name inside an envelope: `name.pdf.p7m` (also `.P7M`, and `name.pdf.p7m.p7m`) is
/// `name.pdf`.
pub fn inner_file_name(name: &str) -> &str {
    let mut n = name;
    while let Some(stem) = n.strip_suffix(".p7m").or_else(|| n.strip_suffix(".P7M")) {
        n = stem;
    }
    n
}

/// One signature of a `.p7m` (the outermost first when envelopes are nested).
#[derive(Clone, Debug)]
pub struct Signer {
    pub certificate: Option<Certificate>,
    /// The digest and the signature value match the content: nothing changed after signing.
    pub intact: bool,
    /// Signed with signing-certificate(-v2): CAdES rather than plain PKCS #7.
    pub cades: bool,
    /// The signing time the signature states (the signer's own clock).
    pub signing_time: Option<Time>,
    /// The certificate was valid at the signing time (or now, without one).
    pub certificate_valid: bool,
    /// The chain reaches a certificate in the trust store.
    pub trusted: bool,
    /// The certificate says it is an EU qualified certificate (qcStatements with QcCompliance,
    /// ETSI EN 319 412-5): the kind a qualified electronic signature (firma digitale) uses. It is
    /// the certificate's own claim; whether its issuer is on the EU Trusted Lists is not checked.
    pub qualified: bool,
    /// Why the signature is not valid or not trusted, in English, for the details.
    pub notes: Vec<String>,
}

impl Signer {
    /// Intact, by a certificate valid then and trusted.
    pub fn valid(&self) -> bool {
        self.intact && self.certificate_valid && self.trusted
    }

    /// The signer's name as the certificate gives it.
    pub fn name(&self) -> String {
        self.certificate.as_ref().map(Certificate::display_name).unwrap_or_default()
    }
}

/// A `.p7m` opened: the signed content (with every envelope removed) and its signatures.
#[derive(Clone, Debug)]
pub struct Envelope {
    pub content: Vec<u8>,
    pub signers: Vec<Signer>,
}

impl Envelope {
    /// Every signature is intact.
    pub fn intact(&self) -> bool {
        !self.signers.is_empty() && self.signers.iter().all(|s| s.intact)
    }

    /// Every signature is intact, by a certificate valid then and trusted.
    pub fn valid(&self) -> bool {
        !self.signers.is_empty() && self.signers.iter().all(Signer::valid)
    }
}

/// Is this a `.p7m` (a CMS SignedData with the content attached), in DER or base64?
pub fn looks_like_p7m(bytes: &[u8]) -> bool {
    der_bytes(bytes).is_ok_and(|der| SignedData::parse(&der).is_ok_and(|sd| sd.content.is_some()))
}

/// Open a `.p7m`: remove every envelope and check each signature against `trust`.
pub fn open(bytes: &[u8], trust: &TrustStore) -> Result<Envelope, SignError> {
    let mut signers = Vec::new();
    let mut current = der_bytes(bytes)?;
    for depth in 0..MAX_NESTING {
        let sd = SignedData::parse(&current)?;
        let content =
            sd.content.clone().ok_or_else(|| SignError::Unsupported("the signature does not contain the document (detached signature)".into()))?;
        signers.push(check(&sd, &content, trust));
        // A document signed again: its content is itself an envelope.
        let inner = der_bytes(&content).ok().filter(|d| SignedData::parse(d).is_ok_and(|s| s.content.is_some()));
        match inner {
            Some(next) if depth + 1 < MAX_NESTING => current = next,
            Some(_) => return Err(SignError::Unsupported("too many nested signatures".into())),
            None => return Ok(Envelope { content, signers }),
        }
    }
    Err(SignError::Unsupported("too many nested signatures".into()))
}

fn check(sd: &SignedData, content: &[u8], trust: &TrustStore) -> Signer {
    let mut notes = Vec::new();
    let s = &sd.signer;
    let digest = s.digest.digest(&[content]);
    let certificate = sd.signer_certificate().cloned();
    let intact = match &certificate {
        None => {
            notes.push("The signer's certificate is not in the file.".to_string());
            false
        }
        Some(cert) => {
            let digest_ok = s.signed_attrs.is_none() || s.message_digest.as_deref() == Some(digest.as_slice());
            if !digest_ok {
                notes.push("The document was changed after it was signed.".to_string());
            }
            let signature_ok = match sd.verify_signature(cert, &digest) {
                Ok(ok) => ok,
                Err(e) => {
                    notes.push(format!("The signature could not be checked: {e}"));
                    false
                }
            };
            if digest_ok && !signature_ok {
                notes.push("The signature value does not match the signer's key.".to_string());
            }
            digest_ok && signature_ok
        }
    };
    if s.signed_attrs.is_some() && s.content_type.as_deref().is_some_and(|ct| ct != DATA) {
        notes.push("The signed attributes name another kind of content.".to_string());
    }
    if !s.signing_certificate {
        notes.push("The signature has no signing-certificate attribute: it is PKCS #7, not CAdES.".to_string());
    }
    let (certificate_valid, trusted) = match &certificate {
        None => (false, false),
        Some(cert) => {
            let at = s.signing_time;
            let in_window = |t: Time| cert.not_before <= t && t <= cert.not_after;
            let certificate_valid = match at {
                Some(t) => in_window(t),
                None => true,
            };
            if !certificate_valid {
                notes.push("The certificate was not valid at the signing time.".to_string());
            }
            if let Some(problem) = cert.signing_problem() {
                notes.push(format!("{problem:?}"));
            }
            let mut pool = sd.certificates.clone();
            pool.extend(trust.certs.iter().cloned());
            let chain = build_chain(cert, &pool, at);
            let trusted = chain.iter().any(|c| trust.certs.iter().any(|t| t.raw == c.raw));
            if !trusted {
                notes.push("The signer's certificate does not chain to a trusted certificate.".to_string());
            }
            (certificate_valid, trusted)
        }
    };
    let qualified = certificate.as_ref().is_some_and(is_qualified);
    Signer { certificate, intact, cades: s.signing_certificate, signing_time: s.signing_time, certificate_valid, trusted, qualified, notes }
}

/// The qcStatements extension (1.3.6.1.5.5.7.1.3) holding the QcCompliance statement
/// (0.4.0.1862.1.1), searched in the certificate's own bytes.
fn is_qualified(cert: &Certificate) -> bool {
    let qc_statements = der::oid("1.3.6.1.5.5.7.1.3");
    let qc_compliance = der::oid("0.4.0.1862.1.1");
    let has = |needle: &[u8]| cert.raw.windows(needle.len()).any(|w| w == needle);
    has(&qc_statements) && has(&qc_compliance)
}

/// DER bytes of a `.p7m` that may be base64 (PEM-style armour or bare).
fn der_bytes(bytes: &[u8]) -> Result<Vec<u8>, SignError> {
    if bytes.first() == Some(&tag::SEQUENCE) {
        return Ok(bytes.to_vec());
    }
    if bytes.len() > MAX_BASE64 {
        return Err(SignError::Unsupported("the file is too large".into()));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| SignError::Malformed("not a signed file".into()))?;
    let compact: String = text.lines().filter(|l| !l.starts_with("-----")).flat_map(str::chars).filter(|c| !c.is_whitespace()).collect();
    use base64::Engine as _;
    let der = base64::engine::general_purpose::STANDARD.decode(compact.as_bytes()).map_err(|_| SignError::Malformed("not a signed file".into()))?;
    if der.first() == Some(&tag::SEQUENCE) { Ok(der) } else { Err(SignError::Malformed("not a signed file".into())) }
}

fn attribute(o: &str, value: &[u8]) -> Vec<u8> {
    der::seq(&[&der::oid(o), &der::set_of(&[value])])
}

/// signing-time: UTCTime up to 2049, GeneralizedTime after (RFC 5652 §11.3).
fn time_value(t: Time) -> Result<Vec<u8>, SignError> {
    if !(1950..=9999).contains(&t.year) || !(1..=12).contains(&t.month) || !(1..=31).contains(&t.day) || t.hour > 23 || t.minute > 59 || t.second > 60
    {
        return Err(SignError::Malformed("the signing time is out of range".into()));
    }
    let rest = format!("{:02}{:02}{:02}{:02}{:02}Z", t.month, t.day, t.hour, t.minute, t.second);
    Ok(if t.year < 2050 {
        der::tlv(tag::UTC_TIME, format!("{:02}{rest}", t.year % 100).as_bytes())
    } else {
        der::tlv(tag::GENERALIZED_TIME, format!("{:04}{rest}", t.year).as_bytes())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::Name;

    fn identity(name: &str) -> (PrivateKey, Certificate) {
        let key = PrivateKey::generate_p256().expect("key");
        let dn = Name::build(name, "", "", "", "IT");
        let cert = Certificate::self_signed(&dn, &key, Time::from_unix(1_700_000_000), 5, &[7, 1]).expect("certificate");
        (key, cert)
    }

    const WHEN: i64 = 1_760_000_000;

    #[test]
    fn signs_and_opens_a_p7m() {
        let (key, cert) = identity("Mario Rossi");
        let pdf = b"%PDF-1.7\nfinto documento\n%%EOF";
        let p7m = sign(&key, &cert, &[], DigestAlg::Sha256, pdf, Time::from_unix(WHEN)).expect("sign");
        assert!(looks_like_p7m(&p7m));

        let trust = TrustStore { certs: vec![cert.clone()] };
        let env = open(&p7m, &trust).expect("open");
        assert_eq!(env.content, pdf);
        let [s] = env.signers.as_slice() else { panic!("one signer") };
        assert!(s.intact && s.cades && s.trusted && s.certificate_valid, "{:?}", s.notes);
        assert_eq!(s.signing_time, Some(Time::from_unix(WHEN)));
        assert_eq!(s.name(), "Mario Rossi");
        assert!(env.valid());
        assert!(!s.qualified, "a self-signed test certificate is not qualified");

        // Without the certificate in the trust store: intact, but not valid.
        let env = open(&p7m, &TrustStore { certs: Vec::new() }).expect("open");
        assert!(env.intact() && !env.valid());
    }

    #[test]
    fn a_changed_document_is_not_intact() {
        let (key, cert) = identity("Mario Rossi");
        let mut p7m = sign(&key, &cert, &[], DigestAlg::Sha256, b"%PDF-1.7 testo originale", Time::from_unix(WHEN)).expect("sign");
        let at = p7m.windows(8).position(|w| w == b"original").expect("content inside");
        p7m[at] = b'O';
        let env = open(&p7m, &TrustStore { certs: vec![cert] }).expect("open");
        assert!(!env.intact());
        assert!(env.signers[0].notes.iter().any(|n| n.contains("changed")));
    }

    #[test]
    fn opens_base64_and_nested_envelopes() {
        let (key1, cert1) = identity("Primo Firmatario");
        let (key2, cert2) = identity("Secondo Firmatario");
        let inner = sign(&key1, &cert1, &[], DigestAlg::Sha256, b"%PDF-1.7 contratto", Time::from_unix(WHEN)).expect("sign");
        let outer = sign(&key2, &cert2, &[], DigestAlg::Sha256, &inner, Time::from_unix(WHEN + 60)).expect("sign");
        use base64::Engine as _;
        let b64 = format!("-----BEGIN PKCS7-----\n{}\n-----END PKCS7-----\n", base64::engine::general_purpose::STANDARD.encode(&outer));

        let env = open(b64.as_bytes(), &TrustStore { certs: vec![cert1, cert2] }).expect("open");
        assert_eq!(env.content, b"%PDF-1.7 contratto");
        let names: Vec<String> = env.signers.iter().map(Signer::name).collect();
        assert_eq!(names, ["Secondo Firmatario", "Primo Firmatario"]);
        assert!(env.valid());
    }

    #[test]
    fn rejects_what_is_not_a_p7m() {
        let trust = TrustStore { certs: Vec::new() };
        assert!(open(b"%PDF-1.7", &trust).is_err());
        assert!(open(b"", &trust).is_err());
        assert!(open(&[0x30, 0x82, 0xff], &trust).is_err());
        assert!(!looks_like_p7m(b"%PDF-1.7"));
    }

    #[test]
    fn file_names() {
        assert_eq!(signed_file_name("fattura.pdf"), "fattura.pdf.p7m");
        assert_eq!(inner_file_name("fattura.pdf.p7m"), "fattura.pdf");
        assert_eq!(inner_file_name("fattura.pdf.P7M.p7m"), "fattura.pdf");
        assert_eq!(inner_file_name("fattura.pdf"), "fattura.pdf");
    }

    #[test]
    fn signing_time_encoding() {
        assert_eq!(time_value(Time::from_unix(WHEN)).expect("time")[0], tag::UTC_TIME);
        let far = Time { year: 2051, month: 1, day: 2, hour: 3, minute: 4, second: 5 };
        assert_eq!(time_value(far).expect("time"), der::tlv(tag::GENERALIZED_TIME, b"20510102030405Z"));
        assert!(time_value(Time { year: 1900, month: 1, day: 1, hour: 0, minute: 0, second: 0 }).is_err());
    }
}
