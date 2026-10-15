//! The connection behind *Check online* on a signed `.p7m` (PDF Simply): it downloads the
//! Italian trusted list, an issuer's certificate or a CRL, and posts OCSP requests. It runs only
//! when the user presses the button; what it asks is decided by `pdfcraft_sign::online`.

use std::time::Duration;

use pdfcraft_engine::sign::online::Request;

/// Large enough for the trusted list and the biggest CRLs.
const MAX_ANSWER: u64 = 64 << 20;

/// Answer one request. OCSP and CRL addresses are usually plain HTTP: their answers are signed
/// by the issuer and checked, so the transport does not need to vouch for them.
pub fn fetch(request: Request<'_>) -> Result<Vec<u8>, String> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .tls_config(ureq::tls::TlsConfig::builder().root_certs(crate::updates::os_roots()?).build())
        .build()
        .new_agent();
    let agent_name = concat!("PDF-Simply/", env!("CARGO_PKG_VERSION"));
    let response = match request {
        Request::Get(url) => agent.get(url).header("User-Agent", agent_name).call(),
        Request::Ocsp { url, body } => agent.post(url).header("User-Agent", agent_name).header("Content-Type", "application/ocsp-request").send(body),
    };
    let mut response = response.map_err(|e| e.to_string())?;
    response.body_mut().with_config().limit(MAX_ANSWER).read_to_vec().map_err(|e| e.to_string())
}
