//! Minimal rustls TLS server for the testbed.
//! usage: rustls-server PORT CERT KEY MODE
//!   MODE = enforce   : X25519MLKEM768 only, TLS 1.3 only
//!          prefer    : X25519MLKEM768 then X25519/P-256 (rustls default order), TLS 1.2 and 1.3
use std::{fs::File, io::{BufReader, Read, Write}, net::TcpListener, sync::Arc};
use rustls::crypto::aws_lc_rs as provider;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (port, cert, key, mode) = (&a[1], &a[2], &a[3], a[4].as_str());
    let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(cert).unwrap())).map(|c| c.unwrap()).collect::<Vec<_>>();
    let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(key).unwrap())).unwrap().unwrap();
    let mut prov = provider::default_provider();
    let versions: Vec<&'static rustls::SupportedProtocolVersion> = match mode {
        "enforce" => {
            prov.kx_groups = vec![provider::kx_group::X25519MLKEM768];
            vec![&rustls::version::TLS13]
        }
        _ => {
            prov.kx_groups = vec![provider::kx_group::X25519MLKEM768, provider::kx_group::X25519, provider::kx_group::SECP256R1];
            vec![&rustls::version::TLS13, &rustls::version::TLS12]
        }
    };
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(prov))
        .with_protocol_versions(&versions).unwrap()
        .with_no_client_auth().with_single_cert(certs, key).unwrap();
    let cfg = Arc::new(cfg);
    let l = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
    for s in l.incoming() {
        let mut s = match s { Ok(s) => s, Err(_) => continue };
        let mut conn = rustls::ServerConnection::new(cfg.clone()).unwrap();
        let mut tls = rustls::Stream::new(&mut conn, &mut s);
        let mut buf = [0u8; 1024];
        if tls.read(&mut buf).is_ok() {
            let _ = tls.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
            let _ = tls.flush();
        }
    }
}
