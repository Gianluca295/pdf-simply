//! PDF Simply: the Italian digital signature. Sign as a `.p7m` (CAdES, the document inside the
//! signature) with a smart-card key through its vendor's PKCS #11 library, a Windows or Keychain
//! store identity, or a digital ID file; and open `.p7m` files, showing the document inside and
//! the result of checking its signatures in a bar above it. *Check online* asks, when the user
//! presses it, whether each signer's certificate was revoked or suspended and whether its issuer
//! is on the Italian trusted list (`sign::online`; the desktop app supplies the connection).

use std::sync::Arc;

use egui::{Align, Color32, Layout};
use pdfcraft_engine::DocId;
use pdfcraft_engine::sign::online::{Report, Request, Revocation, TrustedList};
use pdfcraft_engine::sign::{self, Certificate, DigestAlg, PrivateKey, Time};

use crate::theme::Tokens;
use crate::{PdfCraftApp, widgets};

/// Answers the online check's requests (blocking; it runs on its own thread). The desktop app
/// sets it ([`PdfCraftApp::online_fetch`]); without it there is no *Check online*.
pub type OnlineFetch = Arc<dyn Fn(Request<'_>) -> Result<Vec<u8>, String> + Send + Sync>;

const RED: Color32 = Color32::from_rgb(0xD7, 0x37, 0x3F);
const GREEN: Color32 = Color32::from_rgb(0x2D, 0x9D, 0x78);
const ORANGE: Color32 = Color32::from_rgb(0xE6, 0x86, 0x19);

/// Why `cert` can't make a valid signature now (expired or not yet valid), with its end date.
fn out_of_date(cert: &Certificate, now: Time) -> Option<String> {
    (now < cert.not_before || now > cert.not_after).then(|| {
        let t = cert.not_after;
        crate::i18n::fmt(
            tl!("EXPIRED on {date}: a signature made with this certificate would not be valid."),
            &[("date", &format!("{:02}/{:02}/{:04}", t.day, t.month, t.year))],
        )
    })
}

/// "dd/mm/yyyy hh:mm UTC".
fn when(t: Time) -> String {
    format!("{:02}/{:02}/{:04} {:02}:{:02} UTC", t.day, t.month, t.year, t.hour, t.minute)
}

/// One signature of an opened `.p7m`, ready to show.
#[derive(Clone, Debug, PartialEq)]
pub struct SignerLine {
    pub name: String,
    pub issuer: String,
    /// "dd/mm/yyyy hh:mm UTC", when the signature states a time.
    pub time: Option<String>,
    pub intact: bool,
    pub qualified: bool,
    pub certificate_valid: bool,
    pub trusted: bool,
    pub notes: Vec<String>,
    /// The role the certificate states (its title, such as "Notaio"), when it states one.
    pub role: Option<String>,
    /// The time of a verified timestamp (marca temporale).
    pub timestamp: Option<String>,
    /// When the signature was made: the timestamp's time, else the signer's clock.
    pub signed_at: Option<Time>,
    /// For the online check.
    pub certificate: Option<Certificate>,
    pub carried: Vec<Certificate>,
}

impl SignerLine {
    /// Revoked or suspended since before the signature (or with no signing time to compare).
    fn revoked_before_signing(&self, report: &Report) -> Option<Time> {
        match report.revocation {
            Revocation::Revoked { at, .. } if self.signed_at.is_none_or(|t| at <= t) => Some(at),
            _ => None,
        }
    }
}

/// What opening a `.p7m` found, kept with the document it showed.
#[derive(Clone, Debug, PartialEq)]
pub struct P7mOpened {
    pub file: String,
    pub signers: Vec<SignerLine>,
    pub details_open: bool,
    /// What *Check online* found, one report per signer.
    pub online: Option<Vec<Report>>,
}

impl P7mOpened {
    fn intact(&self) -> bool {
        !self.signers.is_empty() && self.signers.iter().all(|s| s.intact)
    }

    fn valid(&self) -> bool {
        self.intact() && self.signers.iter().all(|s| s.certificate_valid && s.trusted)
    }

    fn qualified(&self) -> bool {
        self.intact() && self.signers.iter().all(|s| s.certificate_valid && s.qualified)
    }
}

/// A way to sign offered by the dialog.
#[derive(Clone, Debug)]
pub enum SignerChoice {
    /// A certificate on a smart card or key, through its PKCS #11 library (asks for the PIN).
    #[cfg(not(target_arch = "wasm32"))]
    Token(Box<sign::pkcs11::TokenIdentity>),
    /// One of the app's digital IDs: a Windows or Keychain store identity (the store asks for
    /// what it needs) or a `.p12`/`.pfx` file (asks for its password).
    Id(crate::sign_ui::DigitalIdEntry),
}

impl SignerChoice {
    fn name(&self) -> String {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            SignerChoice::Token(t) => t.certificate.display_name(),
            SignerChoice::Id(e) => e.name.clone(),
        }
    }

    /// The certificate, when it is known before signing (a key's; a store or file ID shows it
    /// only once opened).
    fn certificate(&self) -> Option<&Certificate> {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            SignerChoice::Token(t) => Some(&t.certificate),
            SignerChoice::Id(_) => None,
        }
    }

    fn detail(&self) -> String {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            SignerChoice::Token(t) => {
                let issuer = t.certificate.issuer.common_name().map(str::to_string).unwrap_or_else(|| t.certificate.issuer.display());
                let kind =
                    if t.certificate.key_usage.is_some_and(|u| u & 0b10 != 0) { tl!("signature") } else { tl!("authentication (not for signing)") };
                crate::i18n::fmt(
                    tl!("Smart card or key \"{token}\" · {kind} · {issuer}"),
                    &[("token", &t.token_label), ("kind", kind), ("issuer", &issuer)],
                )
            }
            SignerChoice::Id(e) if e.path.starts_with("windows:") => {
                crate::i18n::fmt(tl!("Windows certificates · {issuer}"), &[("issuer", &e.issuer)])
            }
            SignerChoice::Id(e) if e.path.starts_with("keychain:") => crate::i18n::fmt(tl!("Keychain · {issuer}"), &[("issuer", &e.issuer)]),
            SignerChoice::Id(e) => crate::i18n::fmt(tl!("Digital ID file · {issuer}"), &[("issuer", &e.issuer)]),
        }
    }

    /// Asks for a PIN (a token) or a password (a file); store identities ask for themselves.
    fn needs_secret(&self) -> bool {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            SignerChoice::Token(_) => true,
            SignerChoice::Id(e) => !(e.path.starts_with("windows:") || e.path.starts_with("keychain:")),
        }
    }

    fn is_token(&self) -> bool {
        #[cfg(not(target_arch = "wasm32"))]
        if matches!(self, SignerChoice::Token(_)) {
            return true;
        }
        false
    }
}

/// The Sign as .p7m dialog's state.
#[derive(Clone, Debug)]
pub struct P7mSignDraft {
    pub doc: DocId,
    pub choices: Vec<SignerChoice>,
    pub selected: Option<usize>,
    pub secret: String,
    pub error: Option<String>,
    /// Wrong PINs typed in this dialog, per choice.
    pub wrong: Vec<u32>,
    /// Where the token's library search looked, for the "no key found" help.
    pub libraries: Vec<String>,
    /// Key libraries found that could not be used, with why (shown when no key is found).
    pub problems: Vec<String>,
}

impl PdfCraftApp {
    /// File ▸ Sign as .p7m: list the keys and identities and show the dialog.
    pub fn start_p7m_signing(&mut self) {
        let Some((_, doc)) = self.active_ids() else { return };
        let mut choices = Vec::new();
        let mut libraries = Vec::new();
        let mut problems = Vec::new();
        #[cfg(not(target_arch = "wasm32"))]
        {
            // The library the user chose by hand comes first.
            let chosen = self.pkcs11_library.as_ref().map(std::path::PathBuf::from).filter(|p| p.is_file());
            let mut all: Vec<std::path::PathBuf> = chosen.into_iter().collect();
            all.extend(sign::pkcs11::libraries().into_iter().filter(|p| !all.contains(p)).collect::<Vec<_>>());
            for library in all {
                libraries.push(library.display().to_string());
                match sign::pkcs11::identities(&library) {
                    Ok(ids) => choices.extend(ids.into_iter().map(|id| SignerChoice::Token(Box::new(id)))),
                    Err(e) => {
                        log::info!("{}: {e}", library.display());
                        if sign::pkcs11::is_32_bit_library(&library) {
                            problems.push(crate::i18n::fmt(
                                tl!("{file} is the 32-bit version of the key's software (Firma4ng, for example, keeps one in its folder), which PDF Simply can't use. Install the key's driver for Windows, which also adds the 64-bit version, then press Search again."),
                                &[("file", &library.display().to_string())],
                            ));
                        } else {
                            problems.push(format!("{}: {e}", library.display()));
                        }
                    }
                }
            }
        }
        // The key's certificate may also be in the Windows store (its driver puts it there):
        // always look, since certificates not meant for signing are greyed and never chosen.
        let store = self.os_key_store_ids;
        self.os_key_store_ids = true;
        self.refresh_signing_ids();
        self.os_key_store_ids = store;
        choices.extend(self.digital_ids.iter().filter(|e| e.unusable.is_none()).cloned().map(SignerChoice::Id));
        // Only a key's certificate in date is chosen in advance; anything else the user picks.
        let now = sign::Time::from_unix(self.session.now_secs());
        let selected = choices.iter().position(|c| c.is_token() && c.certificate().is_some_and(|cert| out_of_date(cert, now).is_none()));
        let wrong = vec![0; choices.len()];
        self.p7m_sign = Some(P7mSignDraft { doc, choices, selected, secret: String::new(), error: None, wrong, libraries, problems });
    }

    /// Sign the document with the chosen identity, then ask where to save the `.p7m`.
    fn finish_p7m_signing(&mut self) -> Result<(), String> {
        if !self.commit_form_typing() {
            return Err(String::new());
        }
        let d = self.p7m_sign.clone().ok_or("nothing to sign")?;
        let index = d.selected.ok_or(tl!("Choose a certificate."))?;
        let choice = d.choices.get(index).cloned().ok_or(tl!("Choose a certificate."))?;
        if choice.needs_secret() && d.secret.is_empty() {
            return Err(if choice.is_token() { tl!("Type the PIN.") } else { tl!("Type the digital ID's password.") }.to_string());
        }
        let now = sign::Time::from_unix(self.session.now_secs());
        // Checked before the PIN is used: an expired certificate never costs an attempt.
        if let Some(why) = choice.certificate().and_then(|c| out_of_date(c, now)) {
            return Err(why);
        }
        let (key, cert, chain) = self.signing_identity(&choice, &d.secret)?;
        if let Some(why) = out_of_date(&cert, now) {
            return Err(why);
        }
        let bytes = self.session.save_bytes(d.doc).map_err(|e| e.to_string())?;
        let p7m = match sign::p7m::sign(&key, &cert, &chain, DigestAlg::Sha256, &bytes, now) {
            Ok(p7m) => p7m,
            Err(sign::SignError::WrongPassword) => {
                let count = {
                    let draft = self.p7m_sign.as_mut().ok_or("nothing to sign")?;
                    draft.secret.clear();
                    let slot = draft.wrong.get_mut(index).ok_or("nothing to sign")?;
                    *slot = slot.saturating_add(1);
                    *slot
                };
                let what = if choice.is_token() { tl!("Wrong PIN") } else { tl!("Wrong password") };
                return Err(crate::i18n::fmt(
                    tl!("{what} ({n} wrong in this session). After a few wrong PINs the key locks."),
                    &[("what", what), ("n", &count.to_string())],
                ));
            }
            Err(e) => return Err(e.to_string()),
        };
        let name = self.session.get(d.doc).map(|doc| doc.name.clone()).unwrap_or_else(|| "document.pdf".into());
        let suggested = sign::p7m::signed_file_name(if name.to_ascii_lowercase().ends_with(".pdf") { &name } else { "document.pdf" });
        let write = move |app: &mut Self, path: std::path::PathBuf| match crate::editing::write_atomically(&path.to_string_lossy(), &p7m) {
            Ok(()) => app.notify_fmt("Signed and saved to {path}", &[("path", &path.display().to_string())]),
            Err(e) => app.notify_fmt("Could not save: {e}", &[("e", &e.to_string())]),
        };
        match self.save_override.clone() {
            Some(p) => write(self, std::path::PathBuf::from(p)),
            #[cfg(not(target_arch = "wasm32"))]
            None => {
                let dialog = rfd::AsyncFileDialog::new().add_filter(tl!("Signed file (.p7m)"), &["p7m"]).set_file_name(suggested);
                if !self.ask_one(crate::pickers::Ask::Save(dialog), Some(d.doc), write) {
                    return Err(String::new());
                }
            }
            #[cfg(target_arch = "wasm32")]
            None => {
                let _ = (suggested, write);
                return Err(tl!("Signing a .p7m is not available in the browser.").to_string());
            }
        }
        Ok(())
    }

    /// The private key, certificate and issuers of a choice.
    fn signing_identity(&self, choice: &SignerChoice, secret: &str) -> Result<(PrivateKey, Certificate, Vec<Certificate>), String> {
        match choice {
            #[cfg(not(target_arch = "wasm32"))]
            SignerChoice::Token(t) => {
                if sign::pkcs11::pin_state(&t.library, t.slot).ok() == Some(sign::pkcs11::PinState::Locked) {
                    return Err(tl!("The PIN is locked: unlock it with the PUK (in the envelope that came with the key).").to_string());
                }
                let key = sign::pkcs11::signing_key(t, secret).map_err(|e| e.to_string())?;
                Ok((key, t.certificate.clone(), Vec::new()))
            }
            SignerChoice::Id(entry) => {
                let id = crate::sign_ui::open_digital_id(entry, secret)?;
                Ok((id.key, id.certificate, id.chain))
            }
        }
    }

    /// Open a `.p7m`: check its signatures, then open the document inside (under its own name,
    /// with no path, so Save asks where: the signed file is never overwritten).
    pub(crate) fn open_p7m(&mut self, name: &str, bytes: &[u8], activate: bool) -> Result<(), String> {
        let trust = sign::TrustStore { certs: self.session.trusted_certificates().to_vec() };
        let envelope = sign::p7m::open(bytes, &trust)
            .map_err(|e| crate::i18n::fmt(tl!("This is not a signed file that can be read: {e}"), &[("e", &e.to_string())]))?;
        let inner = sign::p7m::inner_file_name(name).to_string();
        let opened =
            P7mOpened { file: name.to_string(), signers: envelope.signers.iter().map(signer_line).collect(), details_open: false, online: None };
        let before = self.views.len();
        self.try_open(&inner, None, std::sync::Arc::new(envelope.content), None, activate)?;
        match self.views.get(before).map(|v| v.id) {
            Some(doc) => {
                self.p7m_opened.insert(doc, opened);
            }
            // Asked for a password first: matched by name when it opens.
            None => self.p7m_pending.push((inner, opened)),
        }
        Ok(())
    }

    /// *Check online*: ask, on another thread, about every signer's certificate.
    pub(crate) fn start_online_check(&mut self, doc: DocId) {
        let (Some(fetch), Some(opened)) = (self.online_fetch.clone(), self.p7m_opened.get(&doc)) else { return };
        let jobs: Vec<(Option<Certificate>, Vec<Certificate>)> = opened.signers.iter().map(|s| (s.certificate.clone(), s.carried.clone())).collect();
        #[cfg(not(target_arch = "wasm32"))]
        {
            let (tx, rx) = std::sync::mpsc::channel();
            let ctx = self.ctx.clone();
            std::thread::spawn(move || {
                let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default();
                let now = Time::from_unix(i64::try_from(secs).unwrap_or(i64::MAX));
                let reports = jobs
                    .into_iter()
                    .map(|(cert, carried)| match cert {
                        Some(cert) => sign::online::check(&cert, &carried, now, &mut |r| fetch(r)),
                        None => Report {
                            revocation: Revocation::Unknown,
                            trusted_list: TrustedList::Unreachable,
                            issuer: None,
                            checked_at: now,
                            expired: false,
                            notes: vec!["The signer's certificate is not in the file.".to_string()],
                        },
                    })
                    .collect::<Vec<_>>();
                // The receiver may be gone (the document was closed): nothing to report to then.
                let _ = tx.send(reports);
                if let Some(ctx) = ctx {
                    ctx.request_repaint();
                }
            });
            self.p7m_online.insert(doc, rx);
        }
        #[cfg(target_arch = "wasm32")]
        let _ = (fetch, jobs);
    }

    /// A document opened after a password prompt gets the `.p7m` result waiting for its name.
    pub(crate) fn claim_pending_p7m(&mut self, doc: DocId, name: &str) {
        if let Some(i) = self.p7m_pending.iter().position(|(n, _)| n == name) {
            let (_, opened) = self.p7m_pending.remove(i);
            self.p7m_opened.insert(doc, opened);
        }
    }
}

fn signer_line(s: &sign::p7m::Signer) -> SignerLine {
    let issuer = s.certificate.as_ref().map(|c| c.issuer.common_name().map(str::to_string).unwrap_or_else(|| c.issuer.display())).unwrap_or_default();
    let time = s.signing_time.map(when);
    SignerLine {
        name: s.name(),
        issuer,
        time,
        intact: s.intact,
        qualified: s.qualified,
        certificate_valid: s.certificate_valid,
        trusted: s.trusted,
        notes: s.notes.clone(),
        role: s.certificate.as_ref().and_then(|c| c.subject.get("2.5.4.12")).map(str::to_string),
        timestamp: s.timestamp.map(when),
        signed_at: s.signed_at(),
        certificate: s.certificate.clone(),
        carried: s.carried.clone(),
    }
}

/// Does this file look like a `.p7m` (by name, or by content when it isn't a PDF)?
pub(crate) fn is_p7m(name: &str, bytes: &[u8]) -> bool {
    name.to_ascii_lowercase().ends_with(".p7m") || (!bytes.starts_with(b"%PDF") && sign::p7m::looks_like_p7m(bytes))
}

/// The bar above a document opened from a `.p7m`: the verdict, and Details for each signer.
pub(crate) fn bar(app: &mut PdfCraftApp, doc: DocId, ui: &mut egui::Ui, t: &Tokens) {
    if !app.p7m_opened.contains_key(&doc) && !app.p7m_pending.is_empty() {
        let name = app.session.get(doc).map(|d| d.name.clone()).unwrap_or_default();
        app.claim_pending_p7m(doc, &name);
    }
    if let Some(Ok(reports)) = app.p7m_online.get(&doc).map(std::sync::mpsc::Receiver::try_recv) {
        app.p7m_online.remove(&doc);
        if let Some(opened) = app.p7m_opened.get_mut(&doc) {
            opened.online = Some(reports);
            opened.details_open = true;
        }
    }
    let checking = app.p7m_online.contains_key(&doc);
    let can_check = app.online_fetch.is_some();
    let Some(opened) = app.p7m_opened.get_mut(&doc) else { return };
    let names: Vec<String> = opened.signers.iter().map(|s| s.name.clone()).collect();
    let who = names.join(", ");
    let reports = opened.online.as_deref().unwrap_or_default();
    let revoked_before = opened.signers.iter().zip(reports).find_map(|(s, r)| s.revoked_before_signing(r).map(|at| (s.name.clone(), at)));
    let revoked_after = opened.signers.iter().zip(reports).find_map(|(s, r)| match r.revocation {
        Revocation::Revoked { at, .. } if s.revoked_before_signing(r).is_none() => Some((s.name.clone(), at, s.timestamp.is_some())),
        _ => None,
    });
    let all_good = !reports.is_empty() && reports.iter().all(|r| matches!(r.revocation, Revocation::Good { .. }));
    let (icon, color, mut text) = if let Some((who, at)) = &revoked_before {
        (
            "circle-x",
            RED,
            crate::i18n::fmt(
                tl!("WARNING: the certificate of {who} was REVOKED or SUSPENDED on {date}, before the signature. The signature is NOT valid."),
                &[("who", who), ("date", &when(*at))],
            ),
        )
    } else if let Some((who, at, false)) = &revoked_after {
        (
            "triangle-alert",
            ORANGE,
            crate::i18n::fmt(
                tl!(
                    "Careful: the certificate of {who} was revoked or suspended on {date}. The signature date comes from the signer's computer, so it cannot be proved it came first."
                ),
                &[("who", who), ("date", &when(*at))],
            ),
        )
    } else if let Some(s) = opened.signers.iter().find(|s| s.intact && !s.certificate_valid) {
        (
            "circle-x",
            RED,
            crate::i18n::fmt(
                tl!("Signature NOT valid: the certificate of {who} had expired (or was not yet valid) on the signing date."),
                &[("who", &s.name)],
            ),
        )
    } else if !opened.intact() {
        ("circle-x", RED, tl!("Signature NOT valid: the document was changed after it was signed.").to_string())
    } else if opened.valid() {
        ("circle-check", GREEN, crate::i18n::fmt(tl!("Signed by {who}: the signature is valid."), &[("who", &who)]))
    } else if opened.qualified() {
        ("circle-check", GREEN, crate::i18n::fmt(tl!("Signed by {who} with a qualified certificate: the signature is intact."), &[("who", &who)]))
    } else {
        (
            "triangle-alert",
            ORANGE,
            crate::i18n::fmt(tl!("Signed by {who}: the signature is intact, but the certificate could not be confirmed."), &[("who", &who)]),
        )
    };
    let in_date = opened.signers.iter().all(|s| s.certificate_valid);
    if revoked_before.is_none() && revoked_after.is_none() && all_good && opened.intact() && in_date {
        text.push(' ');
        text.push_str(tl!("Checked online: the certificate is not revoked."));
    }
    let mut toggle = false;
    let mut check = false;
    crate::canvas::notice_bar(ui, t, icon, color, text, |ui| {
        if widgets::pill_button(ui, if opened.details_open { tl!("Hide details") } else { tl!("Details") }, false).clicked() {
            toggle = true;
        }
        if checking {
            ui.add(egui::Spinner::new());
            ui.label(tl!("Checking online…"));
        } else if can_check && widgets::pill_button(ui, tl!("Check online"), false).on_hover_text(tl!("Ask the certificate's issuer whether it was revoked or suspended, and check the AgID list of qualified issuers. The document is not sent.")).clicked() {
            check = true;
        }
    });
    if toggle {
        opened.details_open = !opened.details_open;
    }
    if check {
        app.start_online_check(doc);
        return;
    }
    if !opened.details_open {
        return;
    }
    egui::Frame::NONE.fill(t.card).inner_margin(egui::Margin::symmetric(18, 10)).show(ui, |ui| {
        ui.label(egui::RichText::new(crate::i18n::fmt(tl!("Signed file: {file}"), &[("file", &opened.file)])).color(t.text_muted));
        for (i, s) in opened.signers.iter().enumerate() {
            ui.add_space(4.0);
            let title = if opened.signers.len() > 1 { format!("{}. {}", i + 1, s.name) } else { s.name.clone() };
            ui.label(egui::RichText::new(title).strong());
            let yes_no = |b: bool| if b { tl!("yes") } else { tl!("no") };
            if let Some(role) = &s.role {
                ui.label(crate::i18n::fmt(tl!("Role stated in the certificate: {role}"), &[("role", role)]));
            }
            ui.label(crate::i18n::fmt(tl!("Certificate issued by: {issuer}"), &[("issuer", &s.issuer)]));
            if let Some(time) = &s.time {
                ui.label(crate::i18n::fmt(tl!("Signed on: {time} (the signer's computer clock)"), &[("time", time)]));
            }
            if let Some(stamp) = &s.timestamp {
                ui.label(crate::i18n::fmt(tl!("Timestamp (marca temporale) from an authority: {time}"), &[("time", stamp)]));
            }
            ui.label(crate::i18n::fmt(tl!("Document unchanged since signing: {v}"), &[("v", yes_no(s.intact))]));
            ui.label(crate::i18n::fmt(tl!("Qualified certificate (legally valid digital signature): {v}"), &[("v", yes_no(s.qualified))]));
            if let Some(c) = &s.certificate {
                let day = |t: Time| format!("{:02}/{:02}/{:04}", t.day, t.month, t.year);
                ui.label(crate::i18n::fmt(tl!("Certificate valid from {from} to {to}"), &[("from", &day(c.not_before)), ("to", &day(c.not_after))]));
            }
            let valid = egui::RichText::new(crate::i18n::fmt(tl!("Certificate valid on the signing date: {v}"), &[("v", yes_no(s.certificate_valid))]));
            ui.label(if s.certificate_valid { valid } else { valid.color(RED).strong() });
            // A qualified certificate already says who vouches for it: the missing trust-store
            // anchor would only confuse.
            for note in s.notes.iter().filter(|n| !(s.qualified && n.contains("does not chain to a trusted"))) {
                ui.label(egui::RichText::new(format!("• {}", tl!(note))).small().color(t.text_muted));
            }
            if let Some(report) = reports.get(i) {
                online_lines(ui, t, s, report);
            }
        }
        ui.add_space(6.0);
        let footnote = if can_check {
            tl!(
                "Check online asks the certificate's issuer whether it was revoked or suspended, and checks the AgID list of qualified issuers. Only the certificate is checked: the document is not sent anywhere."
            )
        } else {
            tl!(
                "PDF Simply checks the signature and the certificate, not whether the certificate was revoked. For an official check, use an AgID-compliant verifier (ArubaSign, Firma4NG, or the online verifiers)."
            )
        };
        ui.label(egui::RichText::new(footnote).small().color(t.text_muted));
    });
}

/// What *Check online* found for one signer, in the details.
fn online_lines(ui: &mut egui::Ui, t: &Tokens, s: &SignerLine, r: &Report) {
    ui.add_space(2.0);
    ui.label(egui::RichText::new(crate::i18n::fmt(tl!("Online check of {date}:"), &[("date", &when(r.checked_at))])).strong());
    let (color, line) = match &r.revocation {
        Revocation::Good { .. } => (GREEN, tl!("the certificate is not revoked or suspended.").to_string()),
        Revocation::Revoked { at, .. } if s.revoked_before_signing(r).is_some() => (
            RED,
            crate::i18n::fmt(
                tl!("the certificate was REVOKED or SUSPENDED on {date}, before the signature: the signature is NOT valid."),
                &[("date", &when(*at))],
            ),
        ),
        Revocation::Revoked { at, .. } if s.timestamp.is_some() => (
            ORANGE,
            crate::i18n::fmt(
                tl!("the certificate was revoked or suspended on {date}, after the signature (the timestamp proves the signature came first)."),
                &[("date", &when(*at))],
            ),
        ),
        Revocation::Revoked { at, .. } => (
            ORANGE,
            crate::i18n::fmt(
                tl!(
                    "the certificate was revoked or suspended on {date}. The signature date comes from the signer's computer: it cannot be proved the signature came first."
                ),
                &[("date", &when(*at))],
            ),
        ),
        Revocation::Unknown => {
            (ORANGE, tl!("the revocation could not be checked (no answer from the issuer, or no internet connection).").to_string())
        }
    };
    ui.label(egui::RichText::new(format!("• {line}")).color(color));
    let list = match r.trusted_list {
        TrustedList::Active => tl!("The issuer is a qualified certification authority on the AgID list."),
        TrustedList::Withdrawn => tl!("The issuer is on the AgID list, but it is no longer a qualified certification authority."),
        TrustedList::Absent => tl!("The issuer is not on the Italian AgID list (it may be on another EU country's list)."),
        TrustedList::Unreachable => tl!("The AgID list could not be checked."),
    };
    ui.label(format!("• {list}"));
    if r.expired && matches!(r.revocation, Revocation::Good { .. }) {
        ui.label(
            egui::RichText::new(format!(
                "• {}",
                tl!("The certificate has expired: issuers may stop publishing revocations of expired certificates, so this answer is less certain.")
            ))
            .small()
            .color(t.text_muted),
        );
    }
    for note in &r.notes {
        ui.label(egui::RichText::new(format!("• {}", tl!(note))).small().color(t.text_muted));
    }
}

/// The Sign as .p7m dialog. Returns when it is done (closed or signed).
pub(crate) fn dialog(app: &mut PdfCraftApp, ctx: &egui::Context) {
    let Some(mut d) = app.p7m_sign.take() else { return };
    let mut close = false;
    let mut go = false;
    let mut pick = false;
    let t = Tokens::get(ctx);
    let now = Time::from_unix(app.session.now_secs());
    let modal = widgets::show_modal(ctx, "p7m-sign", |ui| {
        ui.set_width(520.0);
        ui.horizontal(|ui| {
            ui.add(crate::icons::image("signature", 22.0, t.accent));
            ui.label(egui::RichText::new(tl!("Sign as a .p7m file (Italian digital signature)")).font(crate::theme::semibold(17.0)));
        });
        ui.add_space(6.0);
        ui.label(tl!(
                "The document is signed in CAdES format and saved as a new .p7m file, the format public administrations and the Agenzia delle Entrate accept. The document you have open does not change."
            ));
        ui.add_space(8.0);
        if d.choices.is_empty() {
            ui.label(egui::RichText::new(tl!("No certificate found. Plug in the key, wait a few seconds and press Search again.")).strong());
            if d.libraries.is_empty() {
                ui.label(
                        egui::RichText::new(tl!(
                            "The key's software was not found either: install the software that came with the key (for Aruba and InfoCamere keys, the Bit4id driver), or look for it on the key itself."
                        ))
                        .small()
                        .color(t.text_muted),
                    );
            }
            for p in &d.problems {
                ui.label(
                    egui::RichText::new(crate::i18n::fmt(tl!("The key's software was found but could not be used: {problem}"), &[("problem", p)]))
                        .small()
                        .color(Color32::from_rgb(0xD7, 0x37, 0x3F)),
                );
            }
            #[cfg(not(target_arch = "wasm32"))]
            if widgets::pill_button(ui, tl!("Choose the key's file…"), false)
                .on_hover_text(tl!("The key's software file (.dll), for example bit4xpki.dll in C:\\Windows\\System32 or in the folder where the key's software was installed."))
                .clicked()
            {
                pick = true;
            }
        }
        for (i, choice) in d.choices.iter().enumerate() {
            let selected = d.selected == Some(i);
            let resp = ui.add(widgets::radio(selected, &choice.name()));
            ui.label(egui::RichText::new(choice.detail()).small().color(t.text_muted));
            if let Some(why) = choice.certificate().and_then(|c| out_of_date(c, now)) {
                ui.label(egui::RichText::new(why).small().strong().color(RED));
            }
            if resp.clicked() && !selected {
                d.selected = Some(i);
                d.secret.clear();
                d.error = None;
            }
            ui.add_space(2.0);
        }
        if let Some(choice) = d.selected.and_then(|i| d.choices.get(i)) {
            ui.add_space(8.0);
            if choice.needs_secret() {
                #[cfg(not(target_arch = "wasm32"))]
                if let SignerChoice::Token(token) = choice {
                    let warning = match sign::pkcs11::pin_state(&token.library, token.slot) {
                        Ok(sign::pkcs11::PinState::FinalTry) => {
                            Some(tl!("WARNING: this is the last attempt. If the PIN is wrong again, it locks and you will need the PUK."))
                        }
                        Ok(sign::pkcs11::PinState::CountLow) => Some(tl!("Careful: the key says only a few attempts are left before the PIN locks.")),
                        Ok(sign::pkcs11::PinState::Locked) => {
                            Some(tl!("The PIN is locked: unlock it with the PUK (in the envelope that came with the key)."))
                        }
                        _ => None,
                    };
                    if let Some(w) = warning {
                        ui.label(egui::RichText::new(w).color(Color32::from_rgb(0xD7, 0x5A, 0x1F)).strong());
                    }
                }
                ui.label(if choice.is_token() { tl!("Signature PIN") } else { tl!("Digital ID password") });
                let r = ui.add(widgets::line(&mut d.secret).password(true).desired_width(220.0));
                if (r.has_focus() || r.lost_focus()) && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    go = true;
                }
            } else {
                ui.label(egui::RichText::new(tl!("The certificate store will ask for the PIN, if needed.")).small().color(t.text_muted));
            }
        }
        if let Some(e) = d.error.as_ref().filter(|e| !e.is_empty()) {
            ui.add_space(6.0);
            ui.label(egui::RichText::new(e).color(Color32::from_rgb(0xD7, 0x37, 0x3F)));
        }
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if widgets::pill_button(ui, tl!("Search again"), false).clicked() {
                close = true;
                go = false;
                d.error = Some("search".into());
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if widgets::pill_button(ui, tl!("Sign…"), true).clicked() && d.selected.is_some() {
                    go = true;
                }
                if widgets::pill_button(ui, tl!("Cancel"), false).clicked() {
                    close = true;
                }
            });
        });
    });
    if modal.should_close() {
        close = true;
    }
    #[cfg(not(target_arch = "wasm32"))]
    if pick {
        app.p7m_sign = Some(d);
        let dialog =
            rfd::AsyncFileDialog::new().set_title(tl!("Choose the key's file…")).add_filter(tl!("Key software (.dll)"), &["dll", "so", "dylib"]);
        app.ask_one(crate::pickers::Ask::File(dialog), None, |app, path| {
            app.pkcs11_library = Some(path.display().to_string());
            app.start_p7m_signing();
        });
        return;
    }
    if close {
        // Search again: list the keys afresh, keeping the dialog open.
        if d.error.as_deref() == Some("search") {
            app.start_p7m_signing();
        }
        return;
    }
    app.p7m_sign = Some(d);
    if go {
        match app.finish_p7m_signing() {
            Ok(()) => app.p7m_sign = None,
            Err(e) => {
                if let Some(d) = app.p7m_sign.as_mut() {
                    d.error = Some(e);
                }
            }
        }
    }
}
