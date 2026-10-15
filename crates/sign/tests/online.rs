//! The online check (revocation and the Italian trusted list) against a pretend certification
//! authority: no network, every answer comes from the test.

use base64::Engine;
use pdfcraft_sign::der::{self, Time, Tlv, tag};
use pdfcraft_sign::keys::DigestAlg;
use pdfcraft_sign::online::{self, ITALIAN_TRUSTED_LIST, Request, Revocation, TrustedList};
use pdfcraft_sign::{Certificate, Name, pkcs12};

const OCSP: &str = "http://ocsp.example.it";
const CRL: &str = "http://crl.example.it/ca.crl";
const CA: &str = "http://cert.example.it/ca.crt";

fn ca() -> pkcs12::DigitalId {
    let bytes = std::fs::read(format!("{}/tests/data/ec-p256.p12", env!("CARGO_MANIFEST_DIR"))).unwrap();
    pkcs12::open(&bytes, "test").unwrap()
}

fn time(month: u32, day: u32) -> Time {
    Time { year: 2026, month, day, hour: 12, minute: 0, second: 0 }
}

/// A signer's certificate issued by `ca`, naming the OCSP, CRL and issuer addresses.
fn leaf(ca: &pkcs12::DigitalId, not_after: Time) -> Certificate {
    let ca_tbs = Tlv::parse_all(&ca.certificate.raw).unwrap().children().unwrap()[0].children().unwrap();
    let spki = ca_tbs
        .iter()
        .find(|t| {
            t.tag == tag::SEQUENCE
                && t.children().is_ok_and(|c| c.first().is_some_and(|a| a.tag == tag::SEQUENCE))
                && t.children().unwrap().len() == 2
                && t.children().unwrap()[1].tag == tag::BIT_STRING
        })
        .unwrap()
        .raw
        .to_vec();
    let uri = |u: &str| der::tlv(tag::ctx_prim(6), u.as_bytes());
    let aia = der::seq(&[&der::seq(&[&der::oid("1.3.6.1.5.5.7.48.1"), &uri(OCSP)]), &der::seq(&[&der::oid("1.3.6.1.5.5.7.48.2"), &uri(CA)])]);
    let crl_dp = der::seq(&[&der::seq(&[&der::tlv(tag::ctx(0), &der::tlv(tag::ctx(0), &uri(CRL)))])]);
    let ext = |oid: &str, value: &[u8]| der::seq(&[&der::oid(oid), &der::octets(value)]);
    let extensions = der::seq(&[&ext("1.3.6.1.5.5.7.1.1", &aia), &ext("2.5.29.31", &crl_dp)]);
    let alg = ca.key.signature_algorithm(DigestAlg::Sha256);
    let subject = Name::build("Mario Rossi", "", "", "", "IT");
    let tbs = der::seq(&[
        &der::explicit(0, &der::int(2)),
        &der::uint(&[0x42]),
        &alg,
        &ca.certificate.subject.raw,
        &der::seq(&[&time(1, 1).encode(), &not_after.encode()]),
        &subject.raw,
        &spki,
        &der::explicit(3, &extensions),
    ]);
    let sig = ca.key.sign(DigestAlg::Sha256, &tbs).unwrap();
    Certificate::parse(&der::seq(&[&tbs, &alg, &der::bit_string(&sig)])).unwrap()
}

fn ocsp(ca: &pkcs12::DigitalId, cert: &Certificate, revoked: Option<Time>) -> Vec<u8> {
    let cert_id = der::seq(&[
        &DigestAlg::Sha1.algorithm(),
        &der::octets(&DigestAlg::Sha1.digest(&[&cert.issuer.raw])),
        &der::octets(&DigestAlg::Sha1.digest(&[&ca.certificate.public_key.key_bits()])),
        &der::uint(&cert.serial),
    ]);
    let status = match revoked {
        None => der::tlv(tag::ctx_prim(0), &[]),
        Some(at) => der::tlv(tag::ctx(1), &at.encode()),
    };
    let (this, next) = (time(6, 14), time(6, 20));
    let single = der::seq(&[&cert_id, &status, &this.encode(), &der::tlv(tag::ctx(0), &next.encode())]);
    let tbs = der::seq(&[&der::tlv(tag::ctx(1), &ca.certificate.subject.raw), &this.encode(), &der::seq(&[&single])]);
    let alg = ca.key.signature_algorithm(DigestAlg::Sha256);
    let sig = ca.key.sign(DigestAlg::Sha256, &tbs).unwrap();
    let basic = der::seq(&[&tbs, &alg, &der::bit_string(&sig)]);
    der::seq(&[&der::tlv(0x0A, &[0]), &der::explicit(0, &der::seq(&[&der::oid("1.3.6.1.5.5.7.48.1.1"), &der::octets(&basic)]))])
}

fn crl(ca: &pkcs12::DigitalId, revoked: Option<(&[u8], Time)>) -> Vec<u8> {
    let alg = ca.key.signature_algorithm(DigestAlg::Sha256);
    let mut tbs = vec![der::int(1), alg.clone(), ca.certificate.subject.raw.clone(), time(6, 1).encode(), time(7, 1).encode()];
    if let Some((serial, at)) = revoked {
        tbs.push(der::seq(&[&der::seq(&[&der::uint(serial), &at.encode()])]));
    }
    let refs: Vec<&[u8]> = tbs.iter().map(Vec::as_slice).collect();
    let tbs = der::seq(&refs);
    let sig = ca.key.sign(DigestAlg::Sha256, &tbs).unwrap();
    der::seq(&[&tbs, &alg, &der::bit_string(&sig)])
}

/// A trusted list (ETSI TS 119 612) with `ca` as a qualified CA with the given status.
fn trusted_list(ca: &Certificate, status: &str) -> Vec<u8> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(&ca.raw);
    format!(
        "<?xml version=\"1.0\"?><tsl:TrustServiceStatusList xmlns:tsl=\"http://uri.etsi.org/02231/v2#\"><tsl:TrustServiceProviderList><tsl:TrustServiceProvider><tsl:TSPServices>\
         <tsl:TSPService><tsl:ServiceInformation><tsl:ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</tsl:ServiceTypeIdentifier>\
         <tsl:ServiceDigitalIdentity><tsl:DigitalId><tsl:X509Certificate>\n{b64}\n</tsl:X509Certificate></tsl:DigitalId></tsl:ServiceDigitalIdentity>\
         <tsl:ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/{status}</tsl:ServiceStatus></tsl:ServiceInformation></tsl:TSPService>\
         </tsl:TSPServices></tsl:TrustServiceProvider></tsl:TrustServiceProviderList></tsl:TrustServiceStatusList>"
    )
    .into_bytes()
}

#[test]
fn a_revoked_certificate_is_reported_with_its_date() {
    let ca = ca();
    let cert = leaf(&ca, time(12, 31));
    let revoked_on = time(3, 10);
    let mut asked = Vec::new();
    let report = online::check(&cert, &[cert.clone(), ca.certificate.clone()], time(6, 15), &mut |r| {
        asked.push(format!("{r:?}"));
        match r {
            Request::Get(ITALIAN_TRUSTED_LIST) => Ok(trusted_list(&ca.certificate, "granted")),
            Request::Ocsp { url: OCSP, body } => {
                assert_eq!(body, online::ocsp_request(&cert, &ca.certificate));
                Ok(ocsp(&ca, &cert, Some(revoked_on)))
            }
            other => Err(format!("unexpected {other:?}")),
        }
    });
    assert_eq!(report.revocation, Revocation::Revoked { at: revoked_on, source: OCSP.to_string() });
    assert_eq!(report.trusted_list, TrustedList::Active);
    assert!(!report.expired);
    assert_eq!(asked.len(), 2, "{asked:?}");
}

#[test]
fn the_crl_answers_when_ocsp_does_not_and_the_issuer_is_downloaded() {
    let ca = ca();
    let cert = leaf(&ca, time(12, 31));
    let report = online::check(&cert, std::slice::from_ref(&cert), time(6, 15), &mut |r| match r {
        Request::Get(CA) => Ok(ca.certificate.raw.clone()),
        Request::Get(CRL) => Ok(crl(&ca, Some((&[0x07], time(2, 1))))),
        _ => Err("offline".to_string()),
    });
    assert_eq!(report.revocation, Revocation::Good { source: CRL.to_string() });
    assert_eq!(report.trusted_list, TrustedList::Unreachable);
    assert!(report.issuer.is_some());

    // The same CRL listing this certificate.
    let report = online::check(&cert, std::slice::from_ref(&cert), time(6, 15), &mut |r| match r {
        Request::Get(CA) => Ok(ca.certificate.raw.clone()),
        Request::Get(CRL) => Ok(crl(&ca, Some((&cert.serial, time(2, 1))))),
        _ => Err("offline".to_string()),
    });
    assert_eq!(report.revocation, Revocation::Revoked { at: time(2, 1), source: CRL.to_string() });
}

#[test]
fn the_issuer_comes_from_the_trusted_list_and_its_status_is_read() {
    let ca = ca();
    let cert = leaf(&ca, time(3, 31));
    let report = online::check(&cert, std::slice::from_ref(&cert), time(6, 15), &mut |r| match r {
        Request::Get(ITALIAN_TRUSTED_LIST) => Ok(trusted_list(&ca.certificate, "withdrawn")),
        Request::Ocsp { .. } => Ok(ocsp(&ca, &cert, None)),
        _ => Err("offline".to_string()),
    });
    assert_eq!(report.trusted_list, TrustedList::Withdrawn);
    assert_eq!(report.revocation, Revocation::Good { source: OCSP.to_string() });
    assert!(report.expired);
}

#[test]
fn an_answer_not_signed_by_the_issuer_is_not_believed() {
    let ca = ca();
    let other = pkcs12::open(&std::fs::read(format!("{}/tests/data/ec-p384.p12", env!("CARGO_MANIFEST_DIR"))).unwrap(), "test").unwrap();
    let cert = leaf(&ca, time(12, 31));
    let report = online::check(&cert, &[cert.clone(), ca.certificate.clone()], time(6, 15), &mut |r| match r {
        Request::Ocsp { .. } => Ok(ocsp(&other, &cert, None)),
        Request::Get(CRL) => Ok(crl(&other, None)),
        _ => Err("offline".to_string()),
    });
    assert_eq!(report.revocation, Revocation::Unknown);
    assert!(!report.notes.is_empty());
}
