//! Initial configuration for QKD (KME address and SAE ID)


/// Initial configuration for a QKD client (KME config and SAE IDs)
pub struct QkdClientConfig<'a> {
    pub(crate) kme_addr: &'a str,
    pub(crate) client_auth_certificate_path: &'a str,
    pub(crate) client_auth_certificate_password: &'a str,
    pub(crate) origin_sae_id: i64,
    pub(crate) target_sae_id: i64
}

impl<'a> QkdClientConfig<'a> {
    /// Create a new QKD configuration
    pub fn new(kme_addr: &'a str, client_auth_certificate_path: &'a str, client_auth_certificate_password: &'a str, origin_sae_id: i64, target_sae_id: i64) -> QkdClientConfig<'a> {
        Self {
            kme_addr,
            client_auth_certificate_path,
            client_auth_certificate_password,
            origin_sae_id,
            target_sae_id
        }
    }
}

/// Initial configuration for a QKD server (KME address and SAE ID)
pub struct QkdServerConfig<'a> {
    pub(crate) kme_addr: &'a str,
    pub(crate) client_auth_certificate_path: &'a str,
    pub(crate) client_auth_certificate_password: &'a str,
    pub(crate) sae_id: i64
}

impl<'a> QkdServerConfig<'a> {
    /// Create a new QKD configuration
    pub fn new(kme_addr: &'a str, client_auth_certificate_path: &'a str, client_auth_certificate_password: &'a str, sae_id: i64) -> QkdServerConfig<'a> {
        Self {
            kme_addr,
            client_auth_certificate_path,
            client_auth_certificate_password,
            sae_id
        }
    }
}