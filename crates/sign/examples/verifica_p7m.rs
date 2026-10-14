//! Prova a mano: apre un .p7m e stampa firmatari ed esito (non fa parte del prodotto).
fn main() {
    let path = std::env::args().nth(1).unwrap_or_default();
    if path == "firma" {
        let a: Vec<String> = std::env::args().collect();
        firma_di_prova(&a[2], &a[3]);
        return;
    }
    let out = std::env::args().nth(2);
    let bytes = std::fs::read(&path).unwrap_or_default();
    match pdfcraft_sign::p7m::open(&bytes, &pdfcraft_sign::TrustStore { certs: Vec::new() }) {
        Ok(env) => {
            println!("contenuto: {} byte, inizia con {:?}", env.content.len(), String::from_utf8_lossy(env.content.get(..8).unwrap_or_default()));
            for s in &env.signers {
                println!(
                    "firmatario: {} | integra: {} | CAdES: {} | data: {:?} | certificato valido: {} | qualificato: {} | note: {:?}",
                    s.name(),
                    s.intact,
                    s.cades,
                    s.signing_time,
                    s.certificate_valid,
                    s.qualified,
                    s.notes
                );
                if let Some(c) = &s.certificate {
                    println!("  emesso da: {}", c.issuer.display());
                }
            }
            if let Some(o) = out {
                std::fs::write(o, &env.content).ok();
            }
        }
        Err(e) => println!("errore: {e}"),
    }
}

/// Prova a mano: `firma <file> <uscita.p7m>` firma con una chiave di prova appena creata.
#[allow(dead_code)]
fn firma_di_prova(input: &str, output: &str) {
    use pdfcraft_sign::{Certificate, Name, PrivateKey, Time};
    let key = PrivateKey::generate_rsa(2048).expect("chiave");
    let cert = Certificate::self_signed(&Name::build("Prova PDF Simply", "", "", "", "IT"), &key, Time::from_unix(1_700_000_000), 5, &[9])
        .expect("certificato");
    let data = std::fs::read(input).expect("file");
    let p7m = pdfcraft_sign::p7m::sign(&key, &cert, &[], pdfcraft_sign::DigestAlg::Sha256, &data, Time::from_unix(1_760_000_000)).expect("firma");
    std::fs::write(output, p7m).expect("scrittura");
}
