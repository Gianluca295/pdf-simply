//! Signing with a PKCS #11 token or smart card through its vendor's library (Aruba and
//! InfoCamere keys use Bit4id's `bit4xpki`), without the operating system's key store.
//!
//! [`libraries`] finds the usual vendor libraries; [`identities`] lists the certificates on the
//! tokens a library sees (no PIN needed); [`signing_key`] returns a [`PrivateKey`] that logs in
//! with the PIN and signs on the token. The private key never leaves the token.
//!
//! References are strings, so the app can remember them like digital ID files:
//! `pkcs11:<library path>|<slot id>|<key id, hex>`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, CertificateType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use crate::SignError;
use crate::der;
use crate::keys::{DigestAlg, ExternalKey, PrivateKey, PublicKey};
use crate::x509::Certificate;

/// The prefix of a token identity's reference.
pub const PREFIX: &str = "pkcs11:";

/// Library file names of common Italian and European tokens, in the order they are tried.
const KNOWN: &[&str] = &[
    // Bit4id (Aruba, InfoCamere and many qualified-signature keys).
    "bit4xpki",
    "bit4ipki",
    "bit4opki",
    "bit4npki",
    "bit4cpki",
    // Incard, Athena/ASE, Oberthur and the OpenSC generic driver.
    "incryptoki2",
    "asepkcs",
    "OcsCryptoki",
    "opensc-pkcs11",
    // Thales/Gemalto IDPrime, SafeNet eToken, IDEMIA/Oberthur and Charismathics middleware,
    // which some Italian qualified-signature cards and keys use.
    "IDPrimePKCS1164",
    "eTPKCS11",
    "aetpkss1",
    "cmP11",
];

/// A certificate on a token, with what is needed to find its key again.
#[derive(Clone, Debug)]
pub struct TokenIdentity {
    pub certificate: Certificate,
    pub library: PathBuf,
    pub slot: u64,
    pub key_id: Vec<u8>,
    /// The token's label (e.g. the card's name), for display.
    pub token_label: String,
}

impl TokenIdentity {
    pub fn reference(&self) -> String {
        reference(&self.library, self.slot, &self.key_id)
    }
}

pub fn reference(library: &Path, slot: u64, key_id: &[u8]) -> String {
    let hex: String = key_id.iter().map(|b| format!("{b:02x}")).collect();
    format!("{PREFIX}{}|{slot}|{hex}", library.display())
}

/// The parts of a reference: library, slot id and key id.
pub fn parse_reference(reference: &str) -> Option<(PathBuf, u64, Vec<u8>)> {
    let rest = reference.strip_prefix(PREFIX)?;
    let mut parts = rest.rsplitn(3, '|');
    let hex = parts.next()?;
    let slot = parts.next()?.parse().ok()?;
    let library = PathBuf::from(parts.next()?);
    if hex.len() % 2 != 0 {
        return None;
    }
    let key_id = (0..hex.len()).step_by(2).map(|i| hex.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok())).collect::<Option<Vec<u8>>>()?;
    Some((library, slot, key_id))
}

/// Vendor libraries present on this computer: `PDFSIMPLY_PKCS11_LIB` when set, the system
/// folders, then removable drives
/// (some Aruba keys carry their software on the key itself).
pub fn libraries() -> Vec<PathBuf> {
    let mut found = Vec::new();
    // A library named by hand (an unusual token, or a test token) comes first.
    if let Some(chosen) = std::env::var_os("PDFSIMPLY_PKCS11_LIB").map(PathBuf::from).filter(|p| p.is_file()) {
        found.push(chosen);
    }
    for dir in system_dirs() {
        for name in KNOWN {
            let path = dir.join(library_file(name));
            if path.is_file() && !found.contains(&path) {
                found.push(path);
            }
        }
    }
    // Vendor installers that keep the library in their own folder under Program Files.
    let names: Vec<String> = KNOWN.iter().map(|n| library_file(n).to_ascii_lowercase()).collect();
    for dir in program_dirs() {
        let mut in_dir = Vec::new();
        search_depth(&dir, &names, 0, 3, &mut in_dir);
        found.extend(in_dir.into_iter().filter(|p| !found.contains(p)).collect::<Vec<_>>());
    }
    found.extend(on_removable_drives().into_iter().filter(|p| !found.contains(p)).collect::<Vec<_>>());
    found
}

/// Windows: the Program Files folders (64-bit first).
fn program_dirs() -> Vec<PathBuf> {
    if !cfg!(target_os = "windows") {
        return Vec::new();
    }
    ["ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"].iter().filter_map(std::env::var_os).map(PathBuf::from).fold(Vec::new(), |mut dirs, d| {
        if !dirs.contains(&d) {
            dirs.push(d);
        }
        dirs
    })
}

/// The certificates on every token `library` sees, each with its key's id. Certificates
/// without a matching private key are left out (they can't sign).
pub fn identities(library: &Path) -> Result<Vec<TokenIdentity>, SignError> {
    let ctx = open(library)?;
    let mut out = Vec::new();
    for slot in ctx.get_slots_with_token().map_err(ck)? {
        let Ok(info) = ctx.get_token_info(slot) else { continue };
        if !info.token_initialized() {
            continue;
        }
        let Ok(session) = ctx.open_ro_session(slot) else { continue };
        let certs =
            session.find_objects(&[Attribute::Class(ObjectClass::CERTIFICATE), Attribute::CertificateType(CertificateType::X_509)]).map_err(ck)?;
        for handle in certs {
            let attrs = session.get_attributes(handle, &[AttributeType::Value, AttributeType::Id]).map_err(ck)?;
            let mut value = None;
            let mut id = None;
            for a in attrs {
                match a {
                    Attribute::Value(v) => value = Some(v),
                    Attribute::Id(i) => id = Some(i),
                    _ => {}
                }
            }
            let (Some(value), Some(id)) = (value, id) else { continue };
            let Ok(certificate) = Certificate::parse(&value) else { continue };
            // Many tokens list the private key only after login; a key id shared with the
            // certificate is how the key is found at signing time.
            out.push(TokenIdentity {
                certificate,
                library: library.to_path_buf(),
                slot: slot.id(),
                key_id: id,
                token_label: info.label().trim().to_string(),
            });
        }
    }
    // Signing certificates first (non-repudiation), then the rest (authentication, CNS).
    out.sort_by_key(|t| !t.certificate.key_usage.is_some_and(|u| u & 0b10 != 0));
    Ok(out)
}

/// What the token says about its PIN before signing (no attempt is used).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinState {
    Normal,
    /// An earlier attempt failed: only a few are left.
    CountLow,
    /// One more wrong PIN locks it.
    FinalTry,
    Locked,
}

pub fn pin_state(library: &Path, slot: u64) -> Result<PinState, SignError> {
    let ctx = open(library)?;
    let slot = find_slot(&ctx, slot)?;
    let info = ctx.get_token_info(slot).map_err(ck)?;
    Ok(if info.user_pin_locked() {
        PinState::Locked
    } else if info.user_pin_final_try() {
        PinState::FinalTry
    } else if info.user_pin_count_low() {
        PinState::CountLow
    } else {
        PinState::Normal
    })
}

/// A key on the token that signs after logging in with `pin`. The PIN is checked at the first
/// signature: a wrong one returns [`SignError::WrongPassword`].
pub fn signing_key(identity: &TokenIdentity, pin: &str) -> Result<PrivateKey, SignError> {
    let public = identity.certificate.public_key.clone();
    let key = TokenKey {
        library: identity.library.clone(),
        slot: identity.slot,
        key_id: identity.key_id.clone(),
        pin: pin.to_string(),
        public: public.clone(),
    };
    Ok(PrivateKey::external(public, Arc::new(key)))
}

/// Find the identity a reference names (the token must be plugged in).
pub fn find(reference: &str) -> Result<TokenIdentity, SignError> {
    let (library, slot, key_id) = parse_reference(reference).ok_or_else(|| SignError::Malformed(format!("{reference}: not a token reference")))?;
    identities(&library)?
        .into_iter()
        .find(|t| t.slot == slot && t.key_id == key_id)
        .ok_or_else(|| SignError::Crypto("The key is not plugged in, or its certificate is no longer on it.".into()))
}

struct TokenKey {
    library: PathBuf,
    slot: u64,
    key_id: Vec<u8>,
    pin: String,
    public: PublicKey,
}

impl ExternalKey for TokenKey {
    fn sign(&self, alg: DigestAlg, msg: &[u8]) -> Result<Vec<u8>, SignError> {
        let ctx = open(&self.library)?;
        let slot = find_slot(&ctx, self.slot)?;
        let session = ctx.open_ro_session(slot).map_err(ck)?;
        session.login(UserType::User, Some(&AuthPin::new(self.pin.clone()))).map_err(ck)?;
        let result = (|| {
            let keys = session.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Id(self.key_id.clone())]).map_err(ck)?;
            let key = *keys.first().ok_or_else(|| SignError::Crypto("The key's private part is not on the token.".into()))?;
            let digest = alg.digest(&[msg]);
            match &self.public {
                PublicKey::Rsa { .. } => {
                    // PKCS #1 v1.5 over a DigestInfo the token pads and signs: every RSA token
                    // supports CKM_RSA_PKCS, not all the hash-and-sign mechanisms.
                    let digest_info = der::seq(&[&der::algorithm(alg.oid(), Some(&[0x05, 0x00])), &der::octets(&digest)]);
                    session.sign(&Mechanism::RsaPkcs, key, &digest_info).map_err(ck)
                }
                PublicKey::P256(_) | PublicKey::P384(_) => {
                    let raw = session.sign(&Mechanism::Ecdsa, key, &digest).map_err(ck)?;
                    self.public.store_signature_der(&raw)
                }
                other => Err(SignError::Unsupported(format!("signing with {} keys on a token", other.describe()))),
            }
        })();
        let _ = session.logout();
        result
    }
}

fn open(library: &Path) -> Result<Pkcs11, SignError> {
    let ctx = Pkcs11::new(library).map_err(|e| SignError::Crypto(format!("{}: the key's library could not be loaded: {e}", library.display())))?;
    match ctx.initialize(CInitializeArgs::OsThreads) {
        Ok(()) | Err(CkError::AlreadyInitialized) => Ok(ctx),
        Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => Ok(ctx),
        Err(e) => Err(ck(e)),
    }
}

fn find_slot(ctx: &Pkcs11, id: u64) -> Result<Slot, SignError> {
    ctx.get_slots_with_token().map_err(ck)?.into_iter().find(|s| s.id() == id).ok_or_else(|| SignError::Crypto("The key is not plugged in.".into()))
}

/// Token errors in words; a wrong PIN is [`SignError::WrongPassword`].
fn ck(e: CkError) -> SignError {
    match e {
        CkError::Pkcs11(RvError::PinIncorrect | RvError::PinLenRange, _) => SignError::WrongPassword,
        CkError::Pkcs11(RvError::PinLocked, _) => {
            SignError::Crypto("The PIN is locked: unlock it with the PUK (in the envelope that came with the key).".into())
        }
        CkError::Pkcs11(RvError::TokenNotPresent | RvError::DeviceRemoved, _) => SignError::Crypto("The key is not plugged in.".into()),
        other => SignError::Crypto(format!("The key reported an error: {other}")),
    }
}

fn library_file(name: &str) -> String {
    if cfg!(target_os = "windows") {
        format!("{name}.dll")
    } else if cfg!(target_os = "macos") {
        format!("lib{name}.dylib")
    } else {
        format!("lib{name}.so")
    }
}

fn system_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if cfg!(target_os = "windows") {
        if let Some(root) = std::env::var_os("SystemRoot") {
            let root = PathBuf::from(root);
            dirs.push(root.join("System32"));
            dirs.push(root.join("SysWOW64"));
        }
    } else if cfg!(target_os = "macos") {
        dirs.extend(["/usr/local/lib", "/Library/bit4id/pkcs11", "/usr/lib"].map(PathBuf::from));
    } else {
        dirs.extend(
            ["/usr/lib", "/usr/local/lib", "/usr/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu/pkcs11", "/usr/lib64", "/opt/bit4id"]
                .map(PathBuf::from),
        );
    }
    dirs
}

/// Vendor libraries on removable drives (Windows: drive letters D: to Z:), at most four folders deep.
fn on_removable_drives() -> Vec<PathBuf> {
    let mut found = Vec::new();
    if !cfg!(target_os = "windows") {
        return found;
    }
    let names: Vec<String> = KNOWN.iter().map(|n| library_file(n).to_ascii_lowercase()).collect();
    for letter in b'D'..=b'Z' {
        let root = PathBuf::from(format!("{}:\\", letter as char));
        if root.is_dir() {
            search(&root, &names, 0, &mut found);
        }
    }
    found
}

fn search(dir: &Path, names: &[String], depth: usize, found: &mut Vec<PathBuf>) {
    search_depth(dir, names, depth, 4, found);
}

fn search_depth(dir: &Path, names: &[String], depth: usize, max_depth: usize, found: &mut Vec<PathBuf>) {
    const MAX_ENTRIES: usize = 4096;
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten().take(MAX_ENTRIES) {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else { continue };
        if kind.is_dir() && depth < max_depth {
            search_depth(&path, names, depth + 1, max_depth, found);
        } else if kind.is_file() && path.file_name().is_some_and(|n| names.contains(&n.to_string_lossy().to_ascii_lowercase())) {
            found.push(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_round_trip() {
        let r = reference(Path::new("C:\\Windows\\System32\\bit4xpki.dll"), 3, &[0x01, 0xab]);
        assert_eq!(r, "pkcs11:C:\\Windows\\System32\\bit4xpki.dll|3|01ab");
        assert_eq!(parse_reference(&r), Some((PathBuf::from("C:\\Windows\\System32\\bit4xpki.dll"), 3, vec![0x01, 0xab])));
        // A path with the separator in it still parses: the fields are taken from the right.
        assert_eq!(parse_reference("pkcs11:/a|b/lib.so|0|ff"), Some((PathBuf::from("/a|b/lib.so"), 0, vec![0xff])));
        for bad in ["windows:abc", "pkcs11:lib|x|00", "pkcs11:lib|1|0", "pkcs11:lib|1|zz", "pkcs11:"] {
            assert_eq!(parse_reference(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_missing_library_is_an_error_not_a_crash() {
        assert!(identities(Path::new("/nessuna/libreria.so")).is_err());
    }

    /// With SoftHSM (a software token) set up as in `tests/softhsm-setup.sh` of PdfFacile:
    /// `PDFSIMPLY_PKCS11_LIB` and `PDFSIMPLY_PKCS11_PIN` point to it. Skipped otherwise.
    #[test]
    fn signs_a_p7m_on_a_software_token() {
        let (Some(lib), Some(pin)) = (std::env::var_os("PDFSIMPLY_PKCS11_LIB"), std::env::var_os("PDFSIMPLY_PKCS11_PIN")) else { return };
        let pin = pin.to_string_lossy().into_owned();
        let ids = identities(Path::new(&lib)).expect("token");
        let id = ids.first().expect("a certificate on the token");
        assert_eq!(pin_state(&id.library, id.slot).expect("pin state"), PinState::Normal);
        let found = find(&id.reference()).expect("found by reference");
        assert_eq!(found.certificate.raw, id.certificate.raw);

        // A wrong PIN is reported as such, and the right one signs.
        let wrong = signing_key(id, "00000000").expect("key");
        assert!(matches!(wrong.sign(DigestAlg::Sha256, b"x"), Err(SignError::WrongPassword)));
        let key = signing_key(id, &pin).expect("key");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
        let p7m = crate::p7m::sign(&key, &id.certificate, &[], DigestAlg::Sha256, b"%PDF-1.7 firmato", crate::Time::from_unix(now)).expect("sign");
        let env = crate::p7m::open(&p7m, &crate::TrustStore { certs: vec![id.certificate.clone()] }).expect("open");
        assert!(env.valid(), "{:?}", env.signers[0].notes);
    }
}
