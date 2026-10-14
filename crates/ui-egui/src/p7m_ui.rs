//! PDF Simply: the Italian digital signature. Sign as a `.p7m` (CAdES, the document inside the
//! signature) with a smart-card key through its vendor's PKCS #11 library, a Windows or Keychain
//! store identity, or a digital ID file; and open `.p7m` files, showing the document inside and
//! the result of checking its signatures in a bar above it.

use egui::{Align, Color32, Layout};
use pdfcraft_engine::DocId;
use pdfcraft_engine::sign::{self, Certificate, DigestAlg, PrivateKey};

use crate::theme::Tokens;
use crate::{PdfCraftApp, widgets};

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
}

/// What opening a `.p7m` found, kept with the document it showed.
#[derive(Clone, Debug, PartialEq)]
pub struct P7mOpened {
    pub file: String,
    pub signers: Vec<SignerLine>,
    pub details_open: bool,
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
}

impl PdfCraftApp {
    /// File ▸ Sign as .p7m: list the keys and identities and show the dialog.
    pub fn start_p7m_signing(&mut self) {
        let Some((_, doc)) = self.active_ids() else { return };
        let mut choices = Vec::new();
        let mut libraries = Vec::new();
        #[cfg(not(target_arch = "wasm32"))]
        for library in sign::pkcs11::libraries() {
            libraries.push(library.display().to_string());
            match sign::pkcs11::identities(&library) {
                Ok(ids) => choices.extend(ids.into_iter().map(|id| SignerChoice::Token(Box::new(id)))),
                Err(e) => log::info!("{}: {e}", library.display()),
            }
        }
        self.refresh_signing_ids();
        choices.extend(self.digital_ids.iter().filter(|e| e.unusable.is_none()).cloned().map(SignerChoice::Id));
        // A signing certificate first (the first token one, which sorts signing keys first).
        let selected = (!choices.is_empty()).then_some(0);
        let wrong = vec![0; choices.len()];
        self.p7m_sign = Some(P7mSignDraft { doc, choices, selected, secret: String::new(), error: None, wrong, libraries });
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
        let (key, cert, chain) = self.signing_identity(&choice, &d.secret)?;
        let bytes = self.session.save_bytes(d.doc).map_err(|e| e.to_string())?;
        let now = sign::Time::from_unix(self.session.now_secs());
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
        let opened = P7mOpened { file: name.to_string(), signers: envelope.signers.iter().map(signer_line).collect(), details_open: false };
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
    let time = s.signing_time.map(|t| format!("{:02}/{:02}/{:04} {:02}:{:02} UTC", t.day, t.month, t.year, t.hour, t.minute));
    SignerLine {
        name: s.name(),
        issuer,
        time,
        intact: s.intact,
        qualified: s.qualified,
        certificate_valid: s.certificate_valid,
        trusted: s.trusted,
        notes: s.notes.clone(),
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
    let Some(opened) = app.p7m_opened.get_mut(&doc) else { return };
    let names: Vec<String> = opened.signers.iter().map(|s| s.name.clone()).collect();
    let who = names.join(", ");
    let (icon, color, text) = if !opened.intact() {
        ("circle-x", Color32::from_rgb(0xD7, 0x37, 0x3F), tl!("Signature NOT valid: the document was changed after it was signed.").to_string())
    } else if opened.valid() {
        ("circle-check", Color32::from_rgb(0x2D, 0x9D, 0x78), crate::i18n::fmt(tl!("Signed by {who}: the signature is valid."), &[("who", &who)]))
    } else if opened.qualified() {
        (
            "circle-check",
            Color32::from_rgb(0x2D, 0x9D, 0x78),
            crate::i18n::fmt(tl!("Signed by {who} with a qualified certificate: the signature is intact."), &[("who", &who)]),
        )
    } else {
        (
            "triangle-alert",
            Color32::from_rgb(0xE6, 0x86, 0x19),
            crate::i18n::fmt(tl!("Signed by {who}: the signature is intact, but the certificate could not be confirmed."), &[("who", &who)]),
        )
    };
    let mut toggle = false;
    crate::canvas::notice_bar(ui, t, icon, color, text, |ui| {
        if widgets::pill_button(ui, if opened.details_open { tl!("Hide details") } else { tl!("Details") }, false).clicked() {
            toggle = true;
        }
    });
    if toggle {
        opened.details_open = !opened.details_open;
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
            ui.label(crate::i18n::fmt(tl!("Certificate issued by: {issuer}"), &[("issuer", &s.issuer)]));
            if let Some(time) = &s.time {
                ui.label(crate::i18n::fmt(tl!("Signed on: {time} (the signer's computer clock)"), &[("time", time)]));
            }
            ui.label(crate::i18n::fmt(tl!("Document unchanged since signing: {v}"), &[("v", yes_no(s.intact))]));
            ui.label(crate::i18n::fmt(tl!("Qualified certificate (legally valid digital signature): {v}"), &[("v", yes_no(s.qualified))]));
            ui.label(crate::i18n::fmt(tl!("Certificate valid on the signing date: {v}"), &[("v", yes_no(s.certificate_valid))]));
            // A qualified certificate already says who vouches for it: the missing trust-store
            // anchor would only confuse.
            for note in s.notes.iter().filter(|n| !(s.qualified && n.contains("does not chain to a trusted"))) {
                ui.label(egui::RichText::new(format!("• {}", tl!(note))).small().color(t.text_muted));
            }
        }
        ui.add_space(6.0);
        ui.label(
            egui::RichText::new(tl!(
                "PDF Simply checks the signature and the certificate, not whether the certificate was revoked. For an official check, use an AgID-compliant verifier (ArubaSign, Firma4NG, or the online verifiers)."
            ))
            .small()
            .color(t.text_muted),
        );
    });
}

/// The Sign as .p7m dialog. Returns when it is done (closed or signed).
pub(crate) fn dialog(app: &mut PdfCraftApp, ctx: &egui::Context) {
    let Some(mut d) = app.p7m_sign.take() else { return };
    let mut close = false;
    let mut go = false;
    let t = Tokens::get(ctx);
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
        }
        for (i, choice) in d.choices.iter().enumerate() {
            let selected = d.selected == Some(i);
            let resp = ui.add(widgets::radio(selected, &choice.name()));
            ui.label(egui::RichText::new(choice.detail()).small().color(t.text_muted));
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
