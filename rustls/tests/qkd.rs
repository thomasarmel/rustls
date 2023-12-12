use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::client::ClientConnection;
use rustls::{RootCertStore, ServerConfig};
use rustls::server::Acceptor;

#[test]
fn connect_to_unice() {
    // run simple_server() in another thread
    /*std::thread::spawn(|| {
        simple_server();
    });*/
    const HOST: &'static str = "localhost";
    std::thread::sleep(std::time::Duration::from_millis(20));
    let mut root_store = RootCertStore::empty();
    root_store.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
    );
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store).with_qkd();

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    let server_name = HOST.try_into().unwrap();
    let mut conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect(format!("{}:4443", HOST)).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    let bytes_written = concat!(
        "GET / HTTP/1.1\r\n",
        "Host: localhost\r\n",
        "Connection: close\r\n",
        "Accept-Encoding: identity\r\n",
        "\r\n"
    )
        .as_bytes();
    let result = tls.write_all(bytes_written);
    result.unwrap();

    /*let ciphersuite = tls
        .conn
        .negotiated_cipher_suite()
        .unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    ).unwrap();*/
    println!("[client] Written");
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    println!("[client] Read {:?}", plaintext);
    tls.read_to_end(&mut plaintext).unwrap();
    println!("[client] Read {:?}", plaintext);
    conn.send_close_notify();
    conn.complete_io(&mut sock).unwrap();
    assert!(plaintext.starts_with(b"HTTP/1.1 200 OK"));
}

#[test]
fn simple_server() {
    let server_config = TestPki::new().server_config();

    let listener = std::net::TcpListener::bind(format!("[::]:{}", 4443)).unwrap();
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut acceptor = Acceptor::default();

        let accepted = loop {
            acceptor.read_tls(&mut stream).unwrap();
            if let Some(accepted) = acceptor.accept().unwrap() {
                break accepted;
            }
        };

        match accepted.into_connection(server_config.clone()) {
            Ok(mut conn) => {
                let msg = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Connection: Closed\r\n",
                "Content-Type: text/html\r\n",
                "\r\n",
                "<h1>Hello World!</h1>\r\n"
                )
                    .as_bytes();
                //conn.reader().read_to_end(&mut Vec::new()).unwrap();
                // Note: do not use `unwrap()` on IO in real programs!
                conn.writer().write_all(msg).unwrap();
                conn.write_tls(&mut stream).unwrap();
                if conn.wants_write() || conn.wants_read() {
                    conn.complete_io(&mut stream).unwrap();
                }

                conn.writer().write_all(msg).unwrap();
                conn.write_tls(&mut stream).unwrap();
                conn.complete_io(&mut stream).unwrap();

                let mut buf = [0u8; 1];
                let mut read_vec = Vec::new();
                while let Ok(size_read) = conn.reader().read(&mut buf) {
                    if size_read == 0 {
                        break;
                    }
                    read_vec.push(buf[0]);
                }
                println!("{:02X?}", read_vec);

                conn.send_close_notify();
                conn.write_tls(&mut stream).unwrap();
                conn.complete_io(&mut stream).unwrap();
                println!("{}", conn.wants_read());
            }
            Err(e) => {
                eprintln!("{}", e);
            }
        }
    }
}


struct TestPki {
    server_cert_der: CertificateDer<'static>,
    server_key_der: PrivateKeyDer<'static>,
}

impl TestPki {
    fn new() -> Self {
        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let mut ca_params = rcgen::CertificateParams::new(Vec::new());
        ca_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Provider Server Example");
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Example CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        ca_params.alg = alg;
        let ca_cert = rcgen::Certificate::from_params(ca_params).unwrap();

        // Create a server end entity cert issued by the CA.
        let mut server_ee_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]);
        server_ee_params.is_ca = rcgen::IsCa::NoCa;
        server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        server_ee_params.alg = alg;
        let server_cert = rcgen::Certificate::from_params(server_ee_params).unwrap();
        let server_cert_der = CertificateDer::from(
            server_cert
                .serialize_der_with_signer(&ca_cert)
                .unwrap(),
        );
        let server_key_der =
            PrivatePkcs8KeyDer::from(server_cert.serialize_private_key_der()).into();
        Self {
            server_cert_der,
            server_key_der,
        }
    }

    fn server_config(self) -> Arc<ServerConfig> {
        let mut server_config = ServerConfig::builder().with_no_client_auth().with_qkd_and_single_cert(
            vec![self.server_cert_der],
            self.server_key_der).unwrap();

        server_config.key_log = Arc::new(rustls::KeyLogFile::new());

        Arc::new(server_config)
    }
}