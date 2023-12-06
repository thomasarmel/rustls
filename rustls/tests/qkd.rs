use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use rustls::client::ClientConnection;
use rustls::{RootCertStore};

#[test]
fn connect_to_unice() {
    println!("hello world");
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

    let server_name = "unice.fr".try_into().unwrap();
    let mut conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect("unice:443").unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(
        concat!(
        "GET / HTTP/1.1\r\n",
        "Host: unice.fr\r\n",
        "Connection: close\r\n",
        "Accept-Encoding: identity\r\n",
        "\r\n"
        )
            .as_bytes(),
    )
        .unwrap();

    /*let ciphersuite = tls
        .conn
        .negotiated_cipher_suite()
        .unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    ).unwrap();*/
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    assert!(plaintext.starts_with(b"HTTP/1.1 200 OK"));
    println!("hello world");
}