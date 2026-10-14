//! PDF Simply: opening a signed `.p7m` shows the document inside and the signature check above
//! it; a document changed after signing is reported as not valid.

use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use pdfcraft_engine::sign::{self, Certificate, DigestAlg, Name, PrivateKey, Time};
use pdfcraft_ui_egui::PdfCraftApp;

const PDF: &[u8] = b"%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF";

fn signed(content: &[u8]) -> Vec<u8> {
    let key = PrivateKey::generate_p256().expect("key");
    let cert = Certificate::self_signed(&Name::build("Mario Rossi", "", "", "", "IT"), &key, Time::from_unix(1_700_000_000), 5, &[3]).expect("cert");
    sign::p7m::sign(&key, &cert, &[], DigestAlg::Sha256, content, Time::from_unix(1_760_000_000)).expect("sign")
}

fn harness(name: &'static str, bytes: Vec<u8>) -> Harness<'static, PdfCraftApp> {
    let mut h = Harness::builder().with_size(egui::vec2(1400.0, 900.0)).build_eframe(move |_cc| {
        let mut app = PdfCraftApp::new();
        app.set_option("language", "en").unwrap();
        app.open_bytes(name, None, bytes).unwrap();
        app
    });
    h.run_steps(4);
    h
}

#[test]
fn a_p7m_opens_its_document_with_the_signature_check() {
    let mut h = harness("fattura.pdf.p7m", signed(PDF));
    assert_eq!(h.state().views.len(), 1, "the document inside opened");
    h.get_by_label_contains("Signed by Mario Rossi");
    // The bar's own Details button (the first: the one above the document).
    h.get_all_by_label("Details").next().expect("Details button").click();
    h.run_steps(2);
    h.get_by_label_contains("Document unchanged since signing: yes");
    h.get_by_label("Signed file: fattura.pdf.p7m");
}

#[test]
fn a_changed_p7m_is_reported_as_not_valid() {
    let mut p7m = signed(PDF);
    // A different page size: still a readable PDF, but not the one that was signed.
    let at = p7m.windows(7).position(|w| w == b"200 200").expect("content inside");
    p7m[at + 2] = b'1';
    let h = harness("fattura.pdf.p7m", p7m);
    h.get_by_label_contains("Signature NOT valid");
}

#[test]
fn what_is_not_a_p7m_is_refused_with_a_reason() {
    let mut h = Harness::builder().build_eframe(|_cc| PdfCraftApp::new());
    h.run_steps(1);
    let err = h.state_mut().open_bytes("finto.pdf.p7m", None, b"not a signature".to_vec()).expect_err("refused");
    assert!(!err.is_empty());
}
