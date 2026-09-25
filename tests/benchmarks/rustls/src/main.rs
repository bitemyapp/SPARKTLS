//! Single-client comparison adapter, not a general-purpose HTTP server.
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{RootCertStore, ServerConfig, ServerConnection, Stream};
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let result = rustls_pemfile::certs(&mut BufReader::new(File::open(path)?))
        .collect::<io::Result<Vec<_>>>()?;
    if result.is_empty() {
        return Err("empty certificate file".into());
    }
    Ok(result)
}

fn serve_connection(
    mut socket: TcpStream,
    config: Arc<ServerConfig>,
    payload: Option<&[u8]>,
) -> Result<()> {
    socket.set_nodelay(true)?;
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut tls = ServerConnection::new(config)?;
    tls.complete_io(&mut socket)?;
    if let Some(body) = payload {
        // Read only the small HTTP request; cap it to keep mistakes bounded.
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        let mut stream = Stream::new(&mut tls, &mut socket);
        while !request.windows(4).any(|s| s == b"\r\n\r\n")
            && !request.windows(2).any(|s| s == b"\n\n")
        {
            let n = stream.read(&mut buffer)?;
            if n == 0 {
                return Ok(());
            }
            request.extend_from_slice(&buffer[..n]);
            if request.len() > 8192 {
                return Err("HTTP request too long".into());
            }
        }
        if !request.starts_with(b"GET /payload.bin HTTP/1.") {
            return Err("unexpected benchmark request".into());
        }
        write!(stream, "HTTP/1.0 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n", body.len())?;
        // Bounded records avoid buffering another full copy of the cached file.
        for chunk in body.chunks(16 * 1024) {
            stream.write_all(chunk)?;
        }
        stream.flush()?;
    }
    tls.send_close_notify();
    while tls.wants_write() {
        tls.write_tls(&mut socket)?;
    }
    Ok(())
}

fn serve(args: &[String]) -> Result<()> {
    if !(args.len() == 4 || args.len() == 5) {
        return Err("serve CERT KEY PORT SUITE [PAYLOAD]".into());
    }
    let mut provider = aws_lc_rs::default_provider();
    let suite = match args[3].as_str() {
        "TLS_AES_128_GCM_SHA256" => rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        "TLS_AES_256_GCM_SHA384" => rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
        "TLS_CHACHA20_POLY1305_SHA256" => rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        _ => return Err("unsupported cipher suite".into()),
    };
    provider.cipher_suites.retain(|s| s.suite() == suite);
    provider.kx_groups = vec![aws_lc_rs::kx_group::X25519];
    let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(&args[1])?))?
        .ok_or("missing private key")?;
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs(&args[0])?, key)?;
    // Stateless tickets permit repeated reuse of s_time's initial session,
    // matching the other servers' ticket-based TLS 1.3 resumption.
    config.ticketer = aws_lc_rs::Ticketer::new()?;
    let config = Arc::new(config);
    let payload = args.get(4).map(fs::read).transpose()?;
    let listener = TcpListener::bind(("127.0.0.1", args[2].parse::<u16>()?))?;
    for socket in listener.incoming() {
        if let Err(error) = serve_connection(socket?, config.clone(), payload.as_deref()) {
            // Readiness checks and s_time close connections without a TLS
            // close_notify. All measured clients are independently checked.
            if let Some(error) = error.downcast_ref::<io::Error>() {
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                ) {
                    continue;
                }
            }
            eprintln!("connection failed: {error}");
        }
    }
    Ok(())
}

fn verify(args: &[String]) -> Result<()> {
    if args.len() != 4 {
        return Err("verify LEAF CA HOSTNAME ITERATIONS".into());
    }
    let mut roots = RootCertStore::empty();
    for cert in certs(&args[1])? {
        roots.add(cert)?;
    }
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(aws_lc_rs::default_provider()),
    )
    .build()?;
    let name = ServerName::try_from(args[2].as_str())?;
    let iterations = args[3].parse::<usize>()?;
    if iterations == 0 {
        return Err("iterations must be positive".into());
    }
    let now = UnixTime::now();
    for _ in 0..iterations {
        // Like x509_validate and openssl verify, reread and decode the PEM
        // leaf each time, retaining the trust store across validations.
        let chain = certs(&args[0])?;
        verifier.verify_server_cert(&chain[0], &chain[1..], &name, &[], now)?;
    }
    println!("{iterations} validations OK");
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => serve(&args[1..]),
        Some("verify") => verify(&args[1..]),
        Some("--version") => {
            println!("sparktls-rustls-bench {}; rustls 0.23.45; provider aws-lc-rs; see Cargo.lock for backend versions", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => Err("expected serve, verify or --version".into()),
    }
}
