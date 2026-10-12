//! TLS certificate checks for the sites the user watches, and the check that
//! HTTPS isn't being intercepted. Handshakes use rustls with the bundled
//! Mozilla roots (webpki-roots), so the answer doesn't depend on the macOS
//! keychain, where a proxy or security product may have added its own CA.
//! NetWatch only ever connects to the hosts the user chose and to a few big
//! public sites for the interception check; nothing is sent beyond the handshake.

use crate::alerts::{AlertDraft, Severity};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

const DAY_MS: u64 = 86_400_000;
/// Certificates expiring within this long raise a Medium alert…
pub const EXPIRY_WARN_MS: u64 = 14 * DAY_MS;
/// …and within this long (or already expired), a High one.
pub const EXPIRY_CRITICAL_MS: u64 = 3 * DAY_MS;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(6);
const IO_TIMEOUT: Duration = Duration::from_secs(8);
/// Big public sites that every browser reaches over HTTPS, for the interception check.
pub const INTERCEPT_HOSTS: [&str; 3] = ["www.apple.com", "www.cloudflare.com", "www.google.com"];

// ------------------------------------------------------------ certificate facts

/// What NetWatch remembers about a server's leaf certificate. Times are ms.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct CertInfo {
    pub subject: String,
    /// "Let's Encrypt (R11)": who issued it, for people.
    pub issuer: String,
    /// What "same issuer" means: the issuer's organisation, or its name when
    /// there is none. Let's Encrypt and big CAs rotate between intermediates
    /// (R10, R11, E5…) on ordinary renewals, so comparing whole names would
    /// cry wolf.
    pub issuer_org: String,
    pub not_before: u64,
    pub not_after: u64,
    /// SHA-256 of the DER certificate, lowercase hex.
    pub fingerprint: String,
}

fn name_part<'a>(mut it: impl Iterator<Item = &'a x509_parser::x509::AttributeTypeAndValue<'a>>) -> Option<String> {
    it.find_map(|a| a.as_str().ok()).map(str::to_string).filter(|s| !s.is_empty())
}

/// Reads subject, issuer, validity and fingerprint from a DER certificate.
pub fn parse_leaf(der: &[u8]) -> Result<CertInfo, String> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| format!("unreadable certificate: {e}"))?;
    let ms = |t: ASN1Time| (t.timestamp().max(0) as u64) * 1000;
    let issuer = cert.issuer();
    let (org, cn) = (name_part(issuer.iter_organization()), name_part(issuer.iter_common_name()));
    let issuer_label = match (&org, &cn) {
        (Some(o), Some(c)) if o != c => format!("{o} ({c})"),
        (Some(o), _) => o.clone(),
        (None, Some(c)) => c.clone(),
        (None, None) => issuer.to_string(),
    };
    let subject = cert.subject();
    let subject_label = name_part(subject.iter_common_name())
        .or_else(|| name_part(subject.iter_organization()))
        .unwrap_or_else(|| subject.to_string());
    let fingerprint = Sha256::digest(der).iter().map(|b| format!("{b:02x}")).collect();
    Ok(CertInfo {
        subject: subject_label,
        issuer: issuer_label,
        issuer_org: org.or(cn).unwrap_or_else(|| issuer.to_string()),
        not_before: ms(cert.validity().not_before),
        not_after: ms(cert.validity().not_after),
        fingerprint,
    })
}

// ------------------------------------------------------------ pure rules

/// Whole days left (rounded down); negative once expired.
pub fn days_left(not_after: u64, now: u64) -> i64 {
    (not_after as i64 - now as i64).div_euclid(DAY_MS as i64)
}

fn fmt_day(ms: u64) -> String {
    chrono::DateTime::from_timestamp_millis(ms as i64)
        .map(|t| t.format("%-d %b %Y").to_string())
        .unwrap_or_default()
}

/// Why a certificate chain didn't verify.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub enum TrustFailure {
    Expired,
    NotYetValid,
    /// Not issued by any root NetWatch ships with.
    UnknownIssuer,
    NameMismatch,
    Other(String),
}

impl TrustFailure {
    fn from_error(e: &TlsError) -> Self {
        match e {
            TlsError::InvalidCertificate(c) => match c {
                CertificateError::Expired | CertificateError::ExpiredContext { .. } => Self::Expired,
                CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => Self::NotYetValid,
                CertificateError::UnknownIssuer => Self::UnknownIssuer,
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => Self::NameMismatch,
                other => Self::Other(format!("{other:?}")),
            },
            other => Self::Other(other.to_string()),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Expired => "the certificate has expired".into(),
            Self::NotYetValid => "the certificate isn't valid yet (is this computer's clock right?)".into(),
            Self::UnknownIssuer => "it wasn't issued by a certificate authority NetWatch trusts".into(),
            Self::NameMismatch => "the certificate is for a different site name".into(),
            Self::Other(d) => format!("the certificate chain didn't verify ({d})"),
        }
    }
}

/// A problem found with one site's certificate. `tier` keeps the alert key
/// stable until the situation changes (14 days → 3 days → expired).
#[derive(Debug, PartialEq)]
pub struct CertFinding {
    pub tier: String,
    pub draft: AlertDraft,
}

/// The rules for one watched site's latest certificate.
///
/// * expiring within 14 days: Medium; within 3 days or expired: High
/// * the fingerprint changed and the issuer is different: Medium (the same
///   issuer is an ordinary renewal, which callers just record)
/// * the chain doesn't verify: High (an expired chain is reported as expiry)
pub fn cert_findings(target: &str, prev: Option<&CertInfo>, cur: &CertInfo, failure: Option<&TrustFailure>, now: u64) -> Vec<CertFinding> {
    let mut out = Vec::new();
    let fp = cur.fingerprint.get(..8).unwrap_or(&cur.fingerprint);
    let mut push = |tier: &str, severity: Severity, title: String, detail: String| {
        out.push(CertFinding {
            tier: tier.to_string(),
            draft: AlertDraft {
                severity,
                kind: "cert",
                key: format!("{target}:{fp}:{tier}"),
                title,
                detail,
            },
        });
    };
    let remaining = cur.not_after as i64 - now as i64;
    let expired = remaining <= 0 || failure == Some(&TrustFailure::Expired);
    if expired {
        let ago = (-days_left(cur.not_after, now)).max(0);
        push(
            "expired",
            Severity::High,
            format!("The certificate for {target} has expired"),
            format!(
                "{target}'s HTTPS certificate expired on {}{}. Browsers will warn visitors, and apps may refuse to connect. If it's your own site, renew the certificate now.",
                fmt_day(cur.not_after),
                if ago > 0 { format!(" ({ago} day{} ago)", if ago == 1 { "" } else { "s" }) } else { String::new() }
            ),
        );
    } else if remaining <= EXPIRY_WARN_MS as i64 {
        let critical = remaining <= EXPIRY_CRITICAL_MS as i64;
        let days = days_left(cur.not_after, now);
        push(
            if critical { "3d" } else { "14d" },
            if critical { Severity::High } else { Severity::Medium },
            format!(
                "The certificate for {target} expires {}",
                if days < 1 { "within a day".to_string() } else { format!("in {days} day{}", if days == 1 { "" } else { "s" }) }
            ),
            format!(
                "{target}'s HTTPS certificate (issued by {}) is valid until {}. Sites normally renew automatically well before this; if it's yours and it hasn't, renew it before visitors see warnings.",
                cur.issuer,
                fmt_day(cur.not_after)
            ),
        );
    }
    if let Some(p) = prev {
        if p.fingerprint != cur.fingerprint && p.issuer_org != cur.issuer_org {
            push(
                &format!("issuer-{}", p.fingerprint.get(..8).unwrap_or("")),
                Severity::Medium,
                format!("{target} now uses a certificate from a different issuer"),
                format!(
                    "The certificate for {target} was issued by {} last time and by {} now. Sites do change providers, but an unexpected change can also mean something is intercepting your connection to it. If you're on a public or shared network, be careful what you sign in to.",
                    p.issuer, cur.issuer
                ),
            );
        }
    }
    if let Some(f) = failure.filter(|f| **f != TrustFailure::Expired) {
        push(
            "verify",
            Severity::High,
            format!("The certificate for {target} can't be verified"),
            format!(
                "NetWatch couldn't verify {target}'s HTTPS certificate: {}. That can mean something between you and the site is intercepting the connection. If {target} is a device or server of your own using a self-signed certificate, this is expected: stop watching it in the Connection page to silence it.",
                f.describe()
            ),
        );
    }
    out
}

/// One test site in the HTTPS-interception check.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct Probe {
    pub host: String,
    /// A TCP connection to port 443 was possible.
    pub reachable: bool,
    /// The chain verified against the bundled roots.
    pub verified: bool,
    /// The chain failed with an unknown-issuer error.
    pub unknown_issuer: bool,
    pub error: Option<String>,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Ok,
    Intercepted,
    /// Mixed results (one site failed, others fine): not enough to say.
    Inconclusive,
    /// No test site could be reached at all.
    Offline,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Intercepted => "intercepted",
            Self::Inconclusive => "inconclusive",
            Self::Offline => "offline",
        }
    }
}

/// HTTPS looks intercepted when every test site we could reach failed with an
/// unknown-issuer error: real sites chain to the public roots, so a different
/// issuer for all of them means something is re-signing the traffic. Mixed
/// results are inconclusive (a captive portal, one site's trouble).
pub fn intercept_verdict(probes: &[Probe]) -> Verdict {
    let reachable: Vec<&Probe> = probes.iter().filter(|p| p.reachable).collect();
    if reachable.is_empty() {
        Verdict::Offline
    } else if reachable.iter().all(|p| p.verified) {
        Verdict::Ok
    } else if reachable.iter().all(|p| p.unknown_issuer) {
        Verdict::Intercepted
    } else {
        Verdict::Inconclusive
    }
}

pub fn intercept_alert(day: &str, probes: &[Probe]) -> AlertDraft {
    let hosts: Vec<&str> = probes.iter().filter(|p| p.reachable).map(|p| p.host.as_str()).collect();
    AlertDraft {
        severity: Severity::High,
        kind: "tls_intercept",
        key: day.to_string(),
        title: "HTTPS may be intercepted by a proxy or security software".into(),
        detail: format!(
            "{} presented certificates that don't chain to any public certificate authority. Real sites always do, so something on this computer or network is re-signing HTTPS traffic. Antivirus, a company or school proxy, parental controls and a Wi-Fi sign-in page (hotel, café) can all do this; if none of those applies, treat the network as untrusted and avoid signing in to anything sensitive.",
            hosts.join(", ")
        ),
    }
}

// ------------------------------------------------------------ handshakes

/// How a TLS handshake with a server went.
#[derive(Debug, Clone)]
pub enum Handshake {
    /// The chain verified against the roots.
    Trusted(CertInfo),
    /// A certificate arrived but the chain didn't verify.
    Untrusted { info: CertInfo, failure: TrustFailure },
    /// TCP connected but there was no usable TLS (not a TLS port, or silence).
    NoTls(String),
    /// Couldn't connect (name lookup or TCP).
    Unreachable(String),
}

/// The Mozilla root programme, as shipped in the webpki-roots crate.
pub fn bundled_roots() -> Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    ROOTS
        .get_or_init(|| {
            Arc::new(RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
        })
        .clone()
}

/// Verifies like the normal verifier, but keeps the leaf certificate and the
/// first error, so a failed or expired chain can still be reported in detail.
#[derive(Debug)]
struct Recorder {
    inner: Arc<WebPkiServerVerifier>,
    leaf: Mutex<Option<Vec<u8>>>,
    failure: Mutex<Option<TlsError>>,
}

impl Recorder {
    fn note<T>(&self, r: Result<T, TlsError>) -> Result<T, TlsError> {
        if let Err(e) = &r {
            self.failure.lock().unwrap().get_or_insert_with(|| e.clone());
        }
        r
    }
}

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        *self.leaf.lock().unwrap() = Some(end_entity.to_vec());
        let r = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now);
        self.note(r)
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TlsError> {
        self.note(self.inner.verify_tls12_signature(message, cert, dss))
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TlsError> {
        self.note(self.inner.verify_tls13_signature(message, cert, dss))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// A client configuration that checks against `roots` and records what it saw.
/// The provider is passed explicitly: nothing here relies on a process-wide
/// default, which would panic if no provider had been installed.
fn client_config(roots: Arc<RootCertStore>) -> Result<(Arc<ClientConfig>, Arc<Recorder>), String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let inner = WebPkiServerVerifier::builder_with_provider(roots, provider.clone())
        .build()
        .map_err(|e| e.to_string())?;
    let recorder = Arc::new(Recorder {
        inner,
        leaf: Mutex::new(None),
        failure: Mutex::new(None),
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(recorder.clone())
        .with_no_client_auth();
    Ok((Arc::new(config), recorder))
}

/// Resolves `host` and TCP-connects to the first address that answers.
fn connect(host: &str, port: u16) -> Result<(TcpStream, SocketAddr), String> {
    let mut addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|_| format!("couldn't look up {host}"))?
        .collect();
    addrs.sort_by_key(|a| a.is_ipv6());
    let mut last = format!("couldn't look up {host}");
    for addr in addrs.into_iter().take(3) {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(s) => return Ok((s, addr)),
            Err(e) => last = format!("couldn't connect to {host}: {e}"),
        }
    }
    Err(last)
}

/// Runs a handshake over `sock` for `name` and classifies the outcome.
fn handshake_over(mut sock: TcpStream, name: &str, roots: Arc<RootCertStore>) -> Handshake {
    let Ok(server_name) = ServerName::try_from(name.to_string()) else {
        return Handshake::NoTls("not a valid host name".into());
    };
    let (config, recorder) = match client_config(roots) {
        Ok(c) => c,
        Err(e) => return Handshake::NoTls(e),
    };
    let mut conn = match ClientConnection::new(config, server_name) {
        Ok(c) => c,
        Err(e) => return Handshake::NoTls(e.to_string()),
    };
    let _ = sock.set_read_timeout(Some(IO_TIMEOUT));
    let _ = sock.set_write_timeout(Some(IO_TIMEOUT));
    let result = (|| {
        while conn.is_handshaking() {
            conn.complete_io(&mut sock)?;
        }
        Ok::<(), std::io::Error>(())
    })();
    let leaf = recorder.leaf.lock().unwrap().take();
    let failure = recorder.failure.lock().unwrap().take();
    let Some(der) = leaf else {
        let why = result.err().map_or_else(|| "no certificate".to_string(), |e| e.to_string());
        return Handshake::NoTls(format!("no TLS handshake ({why})"));
    };
    let info = match parse_leaf(&der) {
        Ok(i) => i,
        Err(e) => return Handshake::NoTls(e),
    };
    match (failure, result) {
        (Some(f), _) => Handshake::Untrusted { info, failure: TrustFailure::from_error(&f) },
        (None, Ok(())) => Handshake::Trusted(info),
        // Verified but the handshake didn't finish: don't claim it's fine.
        (None, Err(e)) => Handshake::Untrusted { info, failure: TrustFailure::Other(e.to_string()) },
    }
}

/// A TLS handshake with `host:port`, verified against the bundled roots.
pub fn handshake(host: &str, port: u16) -> Handshake {
    handshake_with(host, port, bundled_roots())
}

fn handshake_with(host: &str, port: u16, roots: Arc<RootCertStore>) -> Handshake {
    match connect(host, port) {
        Ok((sock, _)) => handshake_over(sock, host, roots),
        Err(e) => Handshake::Unreachable(e),
    }
}

/// Checks one interception test site.
pub fn probe(host: &str) -> Probe {
    let mut p = Probe {
        host: host.to_string(),
        ..Default::default()
    };
    match handshake(host, 443) {
        Handshake::Trusted(_) => {
            p.reachable = true;
            p.verified = true;
        }
        Handshake::Untrusted { failure, .. } => {
            p.reachable = true;
            p.unknown_issuer = failure == TrustFailure::UnknownIssuer;
            p.error = Some(failure.describe());
        }
        Handshake::NoTls(e) => {
            p.reachable = true;
            p.error = Some(e);
        }
        Handshake::Unreachable(e) => p.error = Some(e),
    }
    p
}

/// Splits a watch-list entry into host and port (443 unless given). `None`
/// for IP addresses: a certificate check is about site names.
pub fn cert_target(entry: &str) -> Option<(String, u16)> {
    let (host, port) = match entry.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()?),
        None => (entry, 443),
    };
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    Some((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// A throwaway self-signed P-256 certificate for CN=localhost, O=NetWatch
    /// Test CA, valid 2026-10-03 to 2126-09-09, made with `openssl req -x509`.
    /// The key is only used by the loopback test below.
    const CERT_B64: &str = "MIIBojCCAUigAwIBAgIJAKY2S308ckJCMAoGCCqGSM49BAMCMC8xEjAQBgNVBAMMCWxvY2FsaG9zdDEZMBcGA1UECgwQTmV0V2F0Y2ggVGVzdCBDQTAgFw0yNjEwMDMxMzA4MjNaGA8yMTI2MDkwOTEzMDgyM1owLzESMBAGA1UEAwwJbG9jYWxob3N0MRkwFwYDVQQKDBBOZXRXYXRjaCBUZXN0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1SjqQS9w18Gf2T31jDNgtKNdx5AI727f/TQGabenUHrRKrHLxP5aPy7lljOvOvu99fovazoRQ2U3xHt3cJrnnqNLMEkwFAYDVR0RBA0wC4IJbG9jYWxob3N0MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAoGCCqGSM49BAMCA0gAMEUCIQCUWlUNLgICB5K2VL0G1LDA8ymwszR50oUm6atMFezGuQIgbw9zVvvxNaW5+xZjODeexSdMaQmeUmdOxqtl8G5MJPw=";

    fn sample() -> CertInfo {
        CertInfo {
            subject: "example.com".into(),
            issuer: "Let's Encrypt (R11)".into(),
            issuer_org: "Let's Encrypt".into(),
            not_before: 0,
            not_after: 100 * DAY_MS,
            fingerprint: "aabbccdd11223344".into(),
        }
    }

    fn kinds(f: &[CertFinding]) -> Vec<(&str, Severity)> {
        f.iter().map(|f| (f.tier.as_str(), f.draft.severity)).collect()
    }

    #[test]
    fn expiry_tiers() {
        let c = sample(); // expires at day 100
        assert!(cert_findings("example.com", None, &c, None, 50 * DAY_MS).is_empty());
        // 15 days left: nothing yet; 14 days left: Medium
        assert!(cert_findings("example.com", None, &c, None, 85 * DAY_MS).is_empty());
        let f = cert_findings("example.com", None, &c, None, 86 * DAY_MS);
        assert_eq!(kinds(&f), vec![("14d", Severity::Medium)]);
        assert!(f[0].draft.title.contains("in 14 days"));
        // within 3 days: High; a different tier so it alerts again
        let f = cert_findings("example.com", None, &c, None, 97 * DAY_MS);
        assert_eq!(kinds(&f), vec![("3d", Severity::High)]);
        assert_ne!(f[0].draft.key, cert_findings("example.com", None, &c, None, 86 * DAY_MS)[0].draft.key);
        // under a day left
        let f = cert_findings("example.com", None, &c, None, 100 * DAY_MS - 3_600_000);
        assert!(f[0].draft.title.contains("within a day"));
        // expired
        let f = cert_findings("example.com", None, &c, None, 103 * DAY_MS);
        assert_eq!(kinds(&f), vec![("expired", Severity::High)]);
        assert!(f[0].draft.detail.contains("3 days ago"));
        assert_eq!(f[0].draft.kind, "cert");
    }

    #[test]
    fn expired_chain_is_reported_once_as_expiry() {
        let c = sample();
        // The verifier says "expired" while our clock still thinks it's valid
        // (clock skew): still one expiry alert, not a second "can't verify".
        let f = cert_findings("example.com", None, &c, Some(&TrustFailure::Expired), 50 * DAY_MS);
        assert_eq!(kinds(&f), vec![("expired", Severity::High)]);
    }

    #[test]
    fn renewal_with_the_same_issuer_is_quiet_but_a_new_issuer_is_not() {
        let old = sample();
        let mut renewed = sample();
        renewed.fingerprint = "99887766aabbccdd".into();
        renewed.issuer = "Let's Encrypt (E5)".into(); // another intermediate, same organisation
        renewed.not_after = 190 * DAY_MS;
        assert!(cert_findings("example.com", Some(&old), &renewed, None, 100 * DAY_MS).is_empty());

        let mut swapped = renewed.clone();
        swapped.issuer = "Acme Proxy CA".into();
        swapped.issuer_org = "Acme Proxy CA".into();
        let f = cert_findings("example.com", Some(&old), &swapped, None, 100 * DAY_MS);
        assert_eq!(kinds(&f), vec![("issuer-aabbccdd", Severity::Medium)]);
        assert!(f[0].draft.detail.contains("Let's Encrypt (R11)") && f[0].draft.detail.contains("Acme Proxy CA"));

        // Same certificate again: nothing.
        assert!(cert_findings("example.com", Some(&old), &old, None, 50 * DAY_MS).is_empty());
        // First sight of a site is a baseline, not a change.
        assert!(cert_findings("example.com", None, &swapped, None, 50 * DAY_MS).is_empty());
    }

    #[test]
    fn unverifiable_chain_is_high() {
        let f = cert_findings("example.com", None, &sample(), Some(&TrustFailure::UnknownIssuer), 50 * DAY_MS);
        assert_eq!(kinds(&f), vec![("verify", Severity::High)]);
        assert!(f[0].draft.detail.contains("self-signed"));
        let f = cert_findings("example.com", None, &sample(), Some(&TrustFailure::NameMismatch), 50 * DAY_MS);
        assert_eq!(kinds(&f), vec![("verify", Severity::High)]);
    }

    #[test]
    fn classifies_verifier_errors() {
        use TrustFailure::*;
        let ic = |c| TlsError::InvalidCertificate(c);
        assert_eq!(TrustFailure::from_error(&ic(CertificateError::UnknownIssuer)), UnknownIssuer);
        assert_eq!(TrustFailure::from_error(&ic(CertificateError::Expired)), Expired);
        assert_eq!(TrustFailure::from_error(&ic(CertificateError::NotValidYet)), NotYetValid);
        assert_eq!(TrustFailure::from_error(&ic(CertificateError::NotValidForName)), NameMismatch);
        assert!(matches!(TrustFailure::from_error(&ic(CertificateError::BadSignature)), Other(_)));
        assert!(matches!(TrustFailure::from_error(&TlsError::HandshakeNotComplete), Other(_)));
    }

    fn p(host: &str, reachable: bool, verified: bool, unknown: bool) -> Probe {
        Probe { host: host.into(), reachable, verified, unknown_issuer: unknown, error: None }
    }

    #[test]
    fn interception_verdicts() {
        let ok = [p("a", true, true, false), p("b", true, true, false), p("c", true, true, false)];
        assert_eq!(intercept_verdict(&ok), Verdict::Ok);
        let all_bad = [p("a", true, false, true), p("b", true, false, true), p("c", true, false, true)];
        assert_eq!(intercept_verdict(&all_bad), Verdict::Intercepted);
        // One site unreachable doesn't hide interception on the others.
        let partial = [p("a", false, false, false), p("b", true, false, true), p("c", true, false, true)];
        assert_eq!(intercept_verdict(&partial), Verdict::Intercepted);
        // Mixed: one fails, others verify. Not enough.
        let mixed = [p("a", true, true, false), p("b", true, false, true), p("c", true, true, false)];
        assert_eq!(intercept_verdict(&mixed), Verdict::Inconclusive);
        // TCP fine but the failure isn't an unknown issuer (clock, name…): not interception.
        let other = [p("a", true, false, false), p("b", true, false, true)];
        assert_eq!(intercept_verdict(&other), Verdict::Inconclusive);
        // No connectivity: can't say anything.
        let off = [p("a", false, false, false), p("b", false, false, false)];
        assert_eq!(intercept_verdict(&off), Verdict::Offline);
        assert_eq!(intercept_verdict(&[]), Verdict::Offline);
        let a = intercept_alert("2026-10-03", &all_bad);
        assert_eq!((a.severity, a.kind), (Severity::High, "tls_intercept"));
        assert!(a.title.contains("intercepted") && a.detail.contains("a, b, c"));
    }

    #[test]
    fn watch_entries_become_cert_targets() {
        assert_eq!(cert_target("example.com"), Some(("example.com".into(), 443)));
        assert_eq!(cert_target("example.com:8443"), Some(("example.com".into(), 8443)));
        assert_eq!(cert_target("10.0.0.5"), None);
        assert_eq!(cert_target("10.0.0.5:443"), None);
        assert_eq!(cert_target("example.com:nope"), None);
    }

    #[test]
    fn reads_a_certificate() {
        let der = base64::engine::general_purpose::STANDARD.decode(CERT_B64).unwrap();
        let c = parse_leaf(&der).unwrap();
        assert_eq!(c.subject, "localhost");
        assert_eq!(c.issuer, "NetWatch Test CA (localhost)");
        assert_eq!(c.issuer_org, "NetWatch Test CA");
        assert_eq!(c.not_before, 1_791_032_903_000);
        assert_eq!(c.not_after, 4_944_632_903_000);
        // openssl x509 -fingerprint -sha256
        assert_eq!(c.fingerprint, "04ea8aa3aa6de9196b677fefdc286cd5d06aa3e3f326fd51758e194b0c6bb017");
        assert!(parse_leaf(b"not a certificate").is_err());
    }

    #[test]
    fn tls_config_builds_without_a_default_provider() {
        let (_config, recorder) = client_config(bundled_roots()).unwrap();
        assert!(recorder.leaf.lock().unwrap().is_none());
        assert!(bundled_roots().roots.len() > 100);
    }

    /// A one-shot TLS server on loopback, using the test certificate.
    fn serve_once(key_b64: &str) -> u16 {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::{ServerConfig, ServerConnection};
        let b64 = base64::engine::general_purpose::STANDARD;
        let cert = CertificateDer::from(b64.decode(CERT_B64).unwrap());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(b64.decode(key_b64).unwrap()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
                let mut conn = ServerConnection::new(Arc::new(config)).unwrap();
                while conn.is_handshaking() {
                    if conn.complete_io(&mut sock).is_err() {
                        break;
                    }
                }
            }
        });
        port
    }

    const KEY_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgDFmdVcMNegh6i1B/mDfmVHrmzisNBlXr7ZCoiYrJovShRANCAATVKOpBL3DXwZ/ZPfWMM2C0o13HkAjvbt/9NAZpt6dQetEqscvE/lo/LuWWM686+731+i9rOhFDZTfEe3dwmuee";

    #[test]
    fn loopback_handshakes_trusted_and_untrusted() {
        let b64 = base64::engine::general_purpose::STANDARD;
        let der = b64.decode(CERT_B64).unwrap();

        // Against the public roots the self-signed certificate is an unknown
        // issuer, and we still get its details.
        let port = serve_once(KEY_B64);
        let sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        match handshake_over(sock, "localhost", bundled_roots()) {
            Handshake::Untrusted { info, failure } => {
                assert_eq!(failure, TrustFailure::UnknownIssuer);
                assert_eq!(info.fingerprint, parse_leaf(&der).unwrap().fingerprint);
            }
            other => panic!("expected Untrusted, got {other:?}"),
        }

        // With that certificate as the trust anchor, the same server verifies.
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(der.clone())).unwrap();
        let port = serve_once(KEY_B64);
        let sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        match handshake_over(sock, "localhost", Arc::new(roots)) {
            Handshake::Trusted(info) => assert_eq!(info.issuer_org, "NetWatch Test CA"),
            other => panic!("expected Trusted, got {other:?}"),
        }

        // A name the certificate isn't for fails as a name mismatch.
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(der)).unwrap();
        let port = serve_once(KEY_B64);
        let sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        match handshake_over(sock, "example.com", Arc::new(roots)) {
            Handshake::Untrusted { failure, .. } => assert_eq!(failure, TrustFailure::NameMismatch),
            other => panic!("expected Untrusted, got {other:?}"),
        }
    }

    #[test]
    fn a_non_tls_port_is_not_a_certificate_problem() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::Write;
            if let Ok((mut s, _)) = listener.accept() {
                let _ = s.write_all(b"SSH-2.0-OpenSSH_9.0\r\n");
                std::thread::sleep(Duration::from_millis(300));
            }
        });
        let sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        assert!(matches!(handshake_over(sock, "localhost", bundled_roots()), Handshake::NoTls(_)));
        // And a closed port is simply unreachable.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        assert!(matches!(handshake_with("127.0.0.1", closed, bundled_roots()), Handshake::Unreachable(_)));
    }

    /// Needs the internet: `cargo test live_ -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_handshakes() {
        for host in INTERCEPT_HOSTS {
            println!("{host}: {:?}", probe(host));
        }
        println!("{:?}", handshake("expired.badssl.com", 443));
        println!("{:?}", handshake("self-signed.badssl.com", 443));
    }
}
