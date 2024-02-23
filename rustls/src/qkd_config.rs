//! Initial configuration for QKD (KME address and SAE ID)


/// Initial configuration for a QKD client (KME config and SAE IDs)
pub struct QkdClientConfig<'a> {
    pub(crate) kme_addr: &'a str,
    pub(crate) client_auth_certificate_path: &'a str,
    pub(crate) client_auth_certificate_password: &'a str,
    pub(crate) target_sae_id: i64,
    pub(crate) danger_accept_invalid_kme_cert: bool
}

impl<'a> QkdClientConfig<'a> {
    /// Create a new QKD configuration
    pub fn new(kme_addr: &'a str, client_auth_certificate_path: &'a str, client_auth_certificate_password: &'a str, target_sae_id: i64, danger_accept_invalid_kme_cert: bool) -> QkdClientConfig<'a> {
        Self {
            kme_addr,
            client_auth_certificate_path,
            client_auth_certificate_password,
            target_sae_id,
            danger_accept_invalid_kme_cert
        }
    }
}

/// Initial configuration for a QKD server (KME address and SAE ID)
pub struct QkdInitialServerConfig<'a> {
    pub(crate) kme_addr: &'a str,
    pub(crate) client_auth_certificate_path: &'a str,
    pub(crate) client_auth_certificate_password: &'a str,
    pub(crate) danger_accept_invalid_kme_cert: bool
}

impl<'a> QkdInitialServerConfig<'a> {
    /// Create a new QKD configuration
    pub fn new(kme_addr: &'a str, client_auth_certificate_path: &'a str, client_auth_certificate_password: &'a str, danger_accept_invalid_kme_cert: bool) -> QkdInitialServerConfig<'a> {
        Self {
            kme_addr,
            client_auth_certificate_path,
            client_auth_certificate_password,
            danger_accept_invalid_kme_cert,
        }
    }
}