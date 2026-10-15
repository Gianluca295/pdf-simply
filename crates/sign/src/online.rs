//! The online check of a signer's certificate (PDF Simply's "Check online"): was it revoked or
//! suspended, and is its issuer a qualified certification authority on the Italian trusted
//! list (AgID, the national part of the EU Trusted Lists)?
//!
//! It runs only when the user asks. This module never opens a connection: the caller passes a
//! `fetch` function that does (the desktop app over HTTP/HTTPS), so what goes out stays visible
//! in one place. What is asked: the trusted list from AgID, the issuer's certificate when the
//! file doesn't carry it, and the certificate's status from the addresses written in the
//! certificate itself (OCSP, then the CRL). The signed document is never sent.
//!
//! The answers are checked, not believed: OCSP responses and CRLs must be signed by the issuer
//! (or its delegated OCSP responder), and a downloaded issuer certificate must have signed the
//! signer's certificate. The trusted list's own XML signature is not verified: it is trusted
//! because it comes from AgID's official address over HTTPS.

use crate::der::{self, Time};
use crate::keys::DigestAlg;
use crate::revocation::{CertificateList, OcspResponse, RevocationStatus};
use crate::x509::{Certificate, load_certificates};

/// The Italian trusted list, published by AgID.
pub const ITALIAN_TRUSTED_LIST: &str = "https://eidas.agid.gov.it/TL/TSL-IT.xml";

const SHA1: &str = "1.3.14.3.2.26";
/// A qualified certification authority issuing qualified certificates (ETSI TS 119 612).
const SVC_CA_QC: &str = "Svctype/CA/QC";
/// The service statuses that mean "currently qualified" (EU, and the older national ones).
const ACTIVE_STATUSES: [&str; 4] = ["Svcstatus/granted", "Svcstatus/accredited", "Svcstatus/undersupervision", "Svcstatus/supervisionincessation"];

/// One request the check needs answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    /// Download what is at this address (the trusted list, an issuer certificate, a CRL).
    Get(&'a str),
    /// Post an OCSP request (`application/ocsp-request`) and return the response.
    Ocsp { url: &'a str, body: &'a [u8] },
}

/// What the issuer of the certificate says about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Revocation {
    /// Not revoked or suspended, according to `source` (an OCSP responder or CRL address).
    Good { source: String },
    /// Revoked or suspended since `at`, according to `source`.
    Revoked { at: Time, source: String },
    /// No answer could be obtained or checked.
    Unknown,
}

/// Where the issuer stands on the Italian trusted list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustedList {
    /// A qualified certification authority, currently.
    Active,
    /// It was one, and no longer is (its status was withdrawn).
    Withdrawn,
    /// Not on the list (it may be on another EU country's list).
    Absent,
    /// The list could not be downloaded or read.
    Unreachable,
}

/// The outcome of [`check`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub revocation: Revocation,
    pub trusted_list: TrustedList,
    /// The issuer's name, when its certificate was found.
    pub issuer: Option<String>,
    /// When the check ran.
    pub checked_at: Time,
    /// The certificate had expired by then: certification authorities may stop listing the
    /// revocation of expired certificates, so a "good" answer is weaker.
    pub expired: bool,
    /// What went wrong along the way, in English (fixed phrases, translated by the app).
    pub notes: Vec<String>,
}

/// Check `cert` online. `carried` are the certificates the signature carries; `now` is the
/// current time; `fetch` answers each [`Request`].
pub fn check(cert: &Certificate, carried: &[Certificate], now: Time, fetch: &mut dyn FnMut(Request<'_>) -> Result<Vec<u8>, String>) -> Report {
    let mut notes = Vec::new();
    let listed = match fetch(Request::Get(ITALIAN_TRUSTED_LIST)) {
        Ok(bytes) => {
            let cas = trusted_list_cas(&String::from_utf8_lossy(&bytes));
            if cas.is_empty() {
                notes.push("The Italian trusted list could not be read.".to_string());
                None
            } else {
                Some(cas)
            }
        }
        Err(_) => {
            notes.push("The Italian trusted list could not be downloaded.".to_string());
            None
        }
    };

    let issues = |c: &Certificate| c.subject.raw == cert.issuer.raw && cert.signed_by(&c.public_key);
    let mut issuer = carried.iter().find(|c| issues(c)).cloned();
    if issuer.is_none() {
        issuer = listed.iter().flatten().map(|(c, _)| c).find(|c| issues(c)).cloned();
    }
    if issuer.is_none() {
        for url in cert.ca_issuer_urls.iter().filter(|u| is_http(u)) {
            match fetch(Request::Get(url)).map_err(|e| e.to_string()).and_then(|b| load_certificates(&b).map_err(|e| e.to_string())) {
                Ok(found) => {
                    issuer = found.into_iter().find(|c| issues(c));
                    if issuer.is_some() {
                        break;
                    }
                }
                Err(_) => note(&mut notes, "The issuer's certificate could not be downloaded."),
            }
        }
    }

    let trusted_list = match (&listed, &issuer) {
        (None, _) => TrustedList::Unreachable,
        (Some(_), None) => TrustedList::Absent,
        (Some(cas), Some(iss)) => {
            let same = |c: &Certificate| c.subject.raw == iss.subject.raw && c.public_key.key_bits() == iss.public_key.key_bits();
            if cas.iter().any(|(c, active)| *active && same(c)) {
                TrustedList::Active
            } else if cas.iter().any(|(c, _)| same(c)) {
                TrustedList::Withdrawn
            } else {
                TrustedList::Absent
            }
        }
    };

    let revocation = match &issuer {
        None => {
            notes.push("The issuer's certificate was not found, so the revocation status could not be checked.".to_string());
            Revocation::Unknown
        }
        Some(iss) => revocation(cert, iss, now, fetch, &mut notes),
    };
    Report { revocation, trusted_list, issuer: issuer.map(|c| c.display_name()), checked_at: now, expired: now > cert.not_after, notes }
}

fn revocation(
    cert: &Certificate,
    issuer: &Certificate,
    now: Time,
    fetch: &mut dyn FnMut(Request<'_>) -> Result<Vec<u8>, String>,
    notes: &mut Vec<String>,
) -> Revocation {
    let body = ocsp_request(cert, issuer);
    for url in cert.ocsp_urls.iter().filter(|u| is_http(u)) {
        match fetch(Request::Ocsp { url, body: &body }) {
            Ok(bytes) => match OcspResponse::parse(&bytes) {
                Ok(r) => match r.check(cert, issuer, now) {
                    RevocationStatus::Good => return Revocation::Good { source: url.clone() },
                    RevocationStatus::Revoked { at } => return Revocation::Revoked { at, source: url.clone() },
                    RevocationStatus::Unknown => note(notes, "An OCSP answer did not cover this certificate or was not signed by its issuer."),
                },
                Err(_) => note(notes, "An OCSP answer could not be read."),
            },
            Err(_) => note(notes, "The OCSP service did not answer."),
        }
    }
    for url in cert.crl_urls.iter().filter(|u| is_http(u)) {
        match fetch(Request::Get(url)) {
            Ok(bytes) => match CertificateList::parse(&bytes) {
                Ok(crl) => match crl.check(cert, issuer, now) {
                    RevocationStatus::Good => return Revocation::Good { source: url.clone() },
                    RevocationStatus::Revoked { at } => return Revocation::Revoked { at, source: url.clone() },
                    RevocationStatus::Unknown => note(notes, "A revocation list was out of date or not signed by the issuer."),
                },
                Err(_) => note(notes, "A revocation list could not be read."),
            },
            Err(_) => note(notes, "A revocation list could not be downloaded."),
        }
    }
    Revocation::Unknown
}

/// Add `text` to the notes once (several addresses may fail the same way).
fn note(notes: &mut Vec<String>, text: &str) {
    if !notes.iter().any(|n| n == text) {
        notes.push(text.to_string());
    }
}

fn is_http(url: &str) -> bool {
    let u = url.to_ascii_lowercase();
    u.starts_with("http://") || u.starts_with("https://")
}

/// An OCSP request (RFC 6960 §4.1) for `cert`, with a SHA-1 `CertID` (what every responder
/// accepts).
pub fn ocsp_request(cert: &Certificate, issuer: &Certificate) -> Vec<u8> {
    let name_hash = DigestAlg::Sha1.digest(&[&cert.issuer.raw]);
    let key_hash = DigestAlg::Sha1.digest(&[&issuer.public_key.key_bits()]);
    let cert_id = der::seq(&[&der::algorithm(SHA1, Some(&der::null())), &der::octets(&name_hash), &der::octets(&key_hash), &der::uint(&cert.serial)]);
    let request = der::seq(&[&cert_id]);
    let tbs = der::seq(&[&der::seq(&[&request])]);
    der::seq(&[&tbs])
}

/// The certification authorities issuing qualified certificates on a trusted list (ETSI
/// TS 119 612 XML), each with whether it is currently qualified.
pub fn trusted_list_cas(xml: &str) -> Vec<(Certificate, bool)> {
    let mut out = Vec::new();
    for service in elements(xml, "TSPService") {
        let Some(info) = elements(service, "ServiceInformation").into_iter().next() else { continue };
        let kind = elements(info, "ServiceTypeIdentifier").into_iter().next().unwrap_or_default();
        if !kind.trim().ends_with(SVC_CA_QC) {
            continue;
        }
        let status = elements(info, "ServiceStatus").into_iter().next().unwrap_or_default();
        let active = ACTIVE_STATUSES.iter().any(|s| status.trim().ends_with(s));
        for b64 in elements(info, "X509Certificate") {
            let clean: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
            let Some(raw) = crate::x509::base64(&clean) else { continue };
            if let Ok(c) = Certificate::parse(&raw) {
                out.push((c, active));
            }
        }
    }
    out
}

/// The contents of every element named `local` (any namespace prefix), not nested in itself.
fn elements<'a>(xml: &'a str, local: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(lt) = rest.find('<') {
        rest = &rest[lt + 1..];
        let end = rest.find(['>', ' ', '\t', '\r', '\n', '/']).unwrap_or(rest.len());
        let qname = &rest[..end];
        let name = qname.rsplit(':').next().unwrap_or(qname);
        if name != local || qname.is_empty() {
            continue;
        }
        let Some(gt) = rest.find('>') else { break };
        if rest[..gt].ends_with('/') {
            rest = &rest[gt + 1..];
            continue;
        }
        let body = &rest[gt + 1..];
        let close = format!("</{qname}>");
        let Some(stop) = body.find(&close) else { break };
        out.push(&body[..stop]);
        rest = &body[stop + close.len()..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_elements_with_any_prefix() {
        let xml = "<a:List><a:TSPService><b>1</b></a:TSPService><TSPService x=\"y\">2</TSPService><TSPService/></a:List>";
        assert_eq!(elements(xml, "TSPService"), vec!["<b>1</b>", "2"]);
        assert!(elements(xml, "Missing").is_empty());
    }
}
