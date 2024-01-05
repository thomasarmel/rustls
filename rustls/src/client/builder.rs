use crate::builder::{ConfigBuilder, WantsVerifier};
use crate::client::handy;
use crate::client::{ClientConfig, ResolvesClientCert};
use crate::crypto::CryptoProvider;
use crate::error::Error;
use crate::key_log::NoKeyLog;
use crate::msgs::handshake::CertificateChain;
use crate::webpki::{self, WebPkiServerVerifier};
use crate::{verify, versions};

use super::client_conn::Resumption;

use pki_types::{CertificateDer, PrivateKeyDer};

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;
use std::format;
use std::fs::File;
use std::io::Read;
use std::prelude::rust_2021::ToString;
use crate::qkd::ResponseQkdSAEInfo;
use crate::qkd_config::QkdClientConfig;

impl ConfigBuilder<ClientConfig, WantsVerifier> {
    /// Choose how to verify server certificates.
    ///
    /// Using this function does not configure revocation.  If you wish to
    /// configure revocation, instead use:
    ///
    /// ```diff
    /// - .with_root_certificates(root_store)
    /// + .with_webpki_verifier(
    /// +   WebPkiServerVerifier::builder_with_provider(root_store, crypto_provider)
    /// +   .with_crls(...)
    /// +   .build()?
    /// + )
    /// ```
    pub fn with_root_certificates(
        self,
        root_store: impl Into<Arc<webpki::RootCertStore>>,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        let algorithms = self
            .state
            .provider
            .signature_verification_algorithms;
        self.with_webpki_verifier(
            WebPkiServerVerifier::new_without_revocation(root_store, algorithms).into(),
        )
    }

    /// Choose how to verify server certificates using a webpki verifier.
    ///
    /// See [`webpki::WebPkiServerVerifier::builder`] and
    /// [`webpki::WebPkiServerVerifier::builder_with_provider`] for more information.
    pub fn with_webpki_verifier(
        self,
        verifier: Arc<WebPkiServerVerifier>,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        ConfigBuilder {
            state: WantsClientCert {
                provider: self.state.provider,
                versions: self.state.versions,
                verifier,
            },
            side: PhantomData,
        }
    }

    /// Access configuration options whose use is dangerous and requires
    /// extra care.
    pub fn dangerous(self) -> danger::DangerousClientConfigBuilder {
        danger::DangerousClientConfigBuilder { cfg: self }
    }
}

/// Container for unsafe APIs
pub(super) mod danger {
    use alloc::sync::Arc;
    use core::marker::PhantomData;

    use crate::client::WantsClientCert;
    use crate::{verify, ClientConfig, ConfigBuilder, WantsVerifier};

    /// Accessor for dangerous configuration options.
    #[derive(Debug)]
    pub struct DangerousClientConfigBuilder {
        /// The underlying ClientConfigBuilder
        pub cfg: ConfigBuilder<ClientConfig, WantsVerifier>,
    }

    impl DangerousClientConfigBuilder {
        /// Set a custom certificate verifier.
        pub fn with_custom_certificate_verifier(
            self,
            verifier: Arc<dyn verify::ServerCertVerifier>,
        ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
            ConfigBuilder {
                state: WantsClientCert {
                    provider: self.cfg.state.provider,
                    versions: self.cfg.state.versions,
                    verifier,
                },
                side: PhantomData,
            }
        }
    }
}

/// A config builder state where the caller needs to supply whether and how to provide a client
/// certificate.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone)]
pub struct WantsClientCert {
    provider: Arc<CryptoProvider>,
    versions: versions::EnabledVersions,
    verifier: Arc<dyn verify::ServerCertVerifier>,
}

impl ConfigBuilder<ClientConfig, WantsClientCert> {
    /// Sets a single certificate chain and matching private key for use
    /// in client authentication.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded private key as PKCS#1, PKCS#8, or SEC1. The
    /// `aws-lc-rs` and `ring` [`CryptoProvider`]s support all three encodings,
    /// but other `CryptoProviders` may not.
    ///
    /// This function fails if `key_der` is invalid.
    pub fn with_client_auth_cert(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<ClientConfig, Error> {
        let private_key = self
            .state
            .provider
            .key_provider
            .load_private_key(key_der)?;
        let resolver =
            handy::AlwaysResolvesClientCert::new(private_key, CertificateChain(cert_chain))?;
        Ok(self.with_client_cert_resolver(Arc::new(resolver)))
    }

    /// Do not support client auth.
    pub fn with_no_client_auth(self) -> ClientConfig {
        self.with_client_cert_resolver(Arc::new(handy::FailResolveClientCert {}))
    }

    /// Sets a custom [`ResolvesClientCert`].
    pub fn with_client_cert_resolver(
        self,
        client_auth_cert_resolver: Arc<dyn ResolvesClientCert>,
    ) -> ClientConfig {
        ClientConfig {
            provider: self.state.provider,
            alpn_protocols: Vec::new(),
            resumption: Resumption::default(),
            max_fragment_size: None,
            client_auth_cert_resolver,
            versions: self.state.versions,
            enable_sni: true,
            verifier: self.state.verifier,
            key_log: Arc::new(NoKeyLog {}),
            enable_secret_extraction: false,
            enable_early_data: false,
            accept_qkd: false,
            origin_sae_id: None,
            target_sae_id: None,
            kme_client: None,
            kme_host: None,
        }
    }

    /// Accepts QKD
    pub fn with_qkd(self, qkd_config: &QkdClientConfig) -> Result<ClientConfig, ()> {

        let mut buf = Vec::new();
        File::open(qkd_config.client_auth_certificate_path).unwrap().read_to_end(&mut buf).map_err(|_| ())?; // TODO: Error handling
        let client_cert_id = reqwest::Identity::from_pkcs12_der(&buf, qkd_config.client_auth_certificate_password).map_err(|_| ())?;
        let kme_client = Some(reqwest::blocking::Client::builder()
            .identity(client_cert_id)
            //.danger_accept_invalid_certs(true)
            .build().map_err(|_| ())?);

        // Retrieve current SAE ID
        let this_sae_info_response = kme_client.as_ref().unwrap()
            .get(&format!("https://{}/api/v1/sae/info/me", qkd_config.kme_addr))
            .send()
            .map_err(|_| ())?
            .text().map_err(|_| ())?;
        let this_sae_info_obj: ResponseQkdSAEInfo = serde_json::from_str(&this_sae_info_response).map_err(|_| ())?;

        Ok(ClientConfig {
            provider: self.state.provider,
            alpn_protocols: Vec::new(),
            resumption: Resumption::default(),
            max_fragment_size: None,
            client_auth_cert_resolver: Arc::new(handy::FailResolveClientCert {}),
            versions: self.state.versions,
            enable_sni: true,
            verifier: self.state.verifier,
            key_log: Arc::new(NoKeyLog {}),
            enable_secret_extraction: false,
            enable_early_data: false,
            accept_qkd: true,
            origin_sae_id: Some(this_sae_info_obj.SAE_ID),
            target_sae_id: Some(qkd_config.target_sae_id),
            kme_host: Some(qkd_config.kme_addr.to_string()),
            kme_client,
        })
    }
}
