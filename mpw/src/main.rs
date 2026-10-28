use actix_web::{web as aw_web, App, HttpServer};
use anyhow::{bail, Context, Result};
use clap::Parser;
use log::{debug, info, LevelFilter};
use rpassword::prompt_password;

#[cfg(feature = "tls")]
use rustls::ServerConfig;
#[cfg(feature = "tls")]
use rustls_pki_types::pem::PemObject;
#[cfg(feature = "tls")]
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use simple_logger::SimpleLogger;

use masterpassword_rs::generate_password;
use mpw::{api_generate, index};

#[derive(Parser)]
#[command(name = "masterpassword")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Opt {
    /// template to use: x-extra,l-long,m-medium,s-short,n-name,P-passphrase,p-pin,b-basic
    #[arg(short = 't', long = "template", default_value = "x")]
    template: char,

    /// password counter (increment to rotate the password for a site; minimum 1)
    #[arg(short = 'c', long = "count", default_value = "1")]
    count: u32,

    /// a=Authentication, i=Login, r=Recovery
    #[arg(short = 'k', long = "kind", default_value = "a")]
    usage: char,

    /// optional context
    #[arg(short = 'x', long = "context", default_value = "")]
    context: String,

    #[arg(short = 'u', long = "user", default_value_t = String::new())]
    user: String,

    #[arg(short = 's', long = "site", default_value_t = String::new())]
    site: String,

    /// start HTTP server
    #[arg(long = "serve")]
    serve: bool,

    /// bind address for HTTP server (plaintext is only allowed on loopback addresses)
    #[arg(long = "bind", default_value = "127.0.0.1")]
    bind: String,

    /// port for HTTP server
    #[arg(long = "port", default_value_t = 8080)]
    port: u16,

    /// TLS certificate file (PEM). If provided together with --tls-key, server will use HTTPS.
    #[arg(long = "tls-cert", default_value_t = String::new())]
    tls_cert: String,

    /// TLS private key file (PEM). If provided together with --tls-cert, server will use HTTPS.
    #[arg(long = "tls-key", default_value_t = String::new())]
    tls_key: String,
}

/// True for "localhost" and loopback IP addresses (127.0.0.0/8, ::1).
fn is_loopback(bind: &str) -> bool {
    bind == "localhost"
        || bind.ends_with(".localhost")
        || bind
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn main() -> Result<()> {
    SimpleLogger::new()
        .with_level(LevelFilter::Info)
        .init()
        .context("logger init failed")?;

    let opt = Opt::parse();

    if opt.serve {
        let bind_addr = format!("{}:{}", opt.bind, opt.port);
        let tls_requested = !opt.tls_cert.is_empty() && !opt.tls_key.is_empty();

        if !tls_requested && !is_loopback(&opt.bind) {
            // The API accepts master passwords; sending them over plaintext
            // HTTP to a routable interface would expose them to the network.
            bail!(
                "refusing to serve plaintext HTTP on non-loopback address '{}'; \
                 bind to 127.0.0.1 or provide --tls-cert and --tls-key \
                 (requires building with '--features tls')",
                opt.bind
            );
        }

        if tls_requested {
            #[cfg(feature = "tls")]
            {
                info!("starting HTTPS server at https://{}", bind_addr);
                // Load certificates using rustls-pki-types (keep DER wrappers).
                let certs_iter =
                    CertificateDer::pem_file_iter(&opt.tls_cert).context("reading tls certs")?;
                let mut cert_chain: Vec<CertificateDer<'static>> = Vec::new();
                for cert_res in certs_iter {
                    let cert = cert_res.context("parsing tls cert")?;
                    cert_chain.push(cert.to_owned());
                }

                // Load private key as a PrivateKeyDer (handles PKCS8 / PKCS1 / SEC1).
                let key_der =
                    PrivateKeyDer::from_pem_file(&opt.tls_key).context("reading tls key")?;

                let config = ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(cert_chain, key_der)
                    .context("creating rustls ServerConfig failed")?;

                let server = HttpServer::new(|| {
                    App::new()
                        .route("/", aw_web::get().to(index))
                        .route("/api/generate", aw_web::post().to(api_generate))
                })
                .bind_rustls_0_23(bind_addr.as_str(), config)?
                .run();

                actix_web::rt::System::new()
                    .block_on(server)
                    .context("server failed")?;
            }
            #[cfg(not(feature = "tls"))]
            {
                bail!("TLS support not compiled in; rebuild with '--features tls'");
            }
        } else {
            info!("starting HTTP server at http://{}", bind_addr);
            let server = HttpServer::new(|| {
                App::new()
                    .route("/", aw_web::get().to(index))
                    .route("/api/generate", aw_web::post().to(api_generate))
            })
            .bind(bind_addr.as_str())?
            .run();

            actix_web::rt::System::new()
                .block_on(server)
                .context("server failed")?;
        }
    } else {
        debug!("template class {:?} {:?}", &opt.template, &opt.user);

        let user = if opt.user.is_empty() {
            prompt_password("user: ").context("reading user")?
        } else {
            opt.user
        };

        // Use env var or prompt for master password. It is deliberately not
        // a command-line flag: argv is visible to other processes via `ps`.
        let master_password = match std::env::var("MPW_MASTER_PASSWORD") {
            Ok(pw) => pw,
            Err(_) => prompt_password("password: ").context("reading password")?,
        };

        let site_name = if opt.site.is_empty() {
            prompt_password("site: ").context("reading site")?
        } else {
            opt.site
        };

        let counter = opt.count;

        let pw = generate_password(
            &master_password,
            &user,
            &site_name,
            counter,
            &opt.context,
            opt.usage,
            opt.template,
            None,
        )?;

        println!(
            "password for user {} and site {} is {}",
            user, site_name, pw
        );
    }
    Ok(())
}
