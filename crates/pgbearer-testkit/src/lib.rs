//! Throwaway PostgreSQL clusters for pgbearer integration tests.
//!
//! [`PgCluster::start`] creates a temporary directory, generates a TLS PKI
//! (CA, server certificate for `localhost` / `127.0.0.1`, client
//! certificates on demand), runs `initdb`, writes `postgresql.conf`,
//! `pg_hba.conf` and `pg_ident.conf`, and starts the server with `pg_ctl`
//! on a free port of `127.0.0.1` plus a private unix socket. Dropping the
//! cluster stops the server (`pg_ctl stop -m immediate`, best effort) and
//! removes the directory.
//!
//! This crate is a dev-dependency only (`publish = false`).
//!
//! # Binaries
//!
//! The server binaries (`initdb`, `pg_ctl`, `postgres`) are looked up in
//! `$PGBEARER_TEST_PG_BIN`, then in the highest `/usr/lib/postgresql/<n>/bin`
//! (or the one named by [`PgOptions::version`]), then on `PATH`. Tests call
//! [`pg_available`] (or the [`require_pg!`] macro) first and skip with a
//! message on stderr when there are none. When `$PGBEARER_TEST_PG_BIN` is
//! set, PostgreSQL always counts as available: a wrong value (or a missing
//! `postgres` OS user when running as root) fails the tests instead of
//! skipping them.
//!
//! PostgreSQL refuses to run as root. When the tests run as root (as in some
//! containers) the temporary directory is handed to the `postgres` OS user
//! and `initdb` / `pg_ctl` run through `runuser -u postgres --`.
//!
//! # Authentication
//!
//! `pg_hba.conf`, in order:
//!
//! ```text
//! <PgOptions::hba lines>
//! local   all all                          trust
//! hostssl all +pgbearer_login 127.0.0.1/32 cert map=pgbearer
//! hostssl all all             127.0.0.1/32 scram-sha-256
//! host    all all             127.0.0.1/32 scram-sha-256
//! ```
//!
//! and `pg_ident.conf` maps the certificate CN `pgbearer` ([`CERT_USER`])
//! to every member of `pgbearer_login` ([`LOGIN_GROUP`], created NOLOGIN at
//! start). The bootstrap superuser is `postgres` ([`ADMIN_USER`]), reachable
//! without a password over the unix socket ([`PgCluster::admin`]).
//!
//! # Example
//!
//! ```no_run
//! use pgbearer_testkit::{PgCluster, PgOptions, create_role_graph, pg_available};
//!
//! # async fn example() -> Result<(), pgbearer_testkit::TestkitError> {
//! if !pg_available() {
//!     eprintln!("skipping: PostgreSQL not available");
//!     return Ok(());
//! }
//! let cluster = PgCluster::start(PgOptions::new().conf("work_mem = '8MB'")).await?;
//! create_role_graph(&cluster.admin().await?).await?;
//! let client = cluster
//!     .connect_tls(&cluster.tcp_config("plain"), Some(pgbearer_testkit::CERT_USER))
//!     .await?;
//! client.simple_query("SELECT 1").await?;
//! cluster.stop().await?;
//! # Ok(())
//! # }
//! ```

use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::RootCertStore;
use tempfile::TempDir;
use tokio_postgres::config::SslMode;
use tokio_postgres::{Client, Config, NoTls};
use tokio_postgres_rustls::MakeRustlsConnect;

mod pki;
pub mod role_graph;

pub use role_graph::create_role_graph;

use pki::Pki;

/// Environment variable naming the directory with `initdb` and `pg_ctl`.
pub const PG_BIN_ENV: &str = "PGBEARER_TEST_PG_BIN";
/// When this environment variable is set (non-empty), the temporary
/// directory of every cluster is kept after drop, for debugging.
pub const KEEP_ENV: &str = "PGBEARER_TESTKIT_KEEP";
/// The bootstrap superuser created by `initdb`.
pub const ADMIN_USER: &str = "postgres";
/// NOLOGIN group role whose members may log in with a client certificate.
pub const LOGIN_GROUP: &str = "pgbearer_login";
/// Client certificate common name that `pg_ident.conf` maps to every member
/// of [`LOGIN_GROUP`] (map name `pgbearer`).
pub const CERT_USER: &str = "pgbearer";
/// The address the server listens on.
pub const HOST: &str = "127.0.0.1";

/// OS user the server runs as when the tests run as root.
const POSTGRES_OS_USER: &str = "postgres";
/// Debian/Ubuntu layout: `/usr/lib/postgresql/<major>/bin`.
const DEBIAN_PG_LIB: &str = "/usr/lib/postgresql";
/// Attempts to start the server when the chosen port turns out to be taken.
const START_ATTEMPTS: u32 = 5;
/// Connect timeout for every client connection made by this crate.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Errors from the test kit.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TestkitError {
    /// No PostgreSQL server binaries were found.
    #[error(
        "PostgreSQL server binaries (initdb, pg_ctl) not found; set {PG_BIN_ENV} \
         or install PostgreSQL under /usr/lib/postgresql/<version>/bin"
    )]
    BinariesNotFound,
    /// `$PGBEARER_TEST_PG_BIN` is set but does not contain the binaries.
    #[error("{PG_BIN_ENV}={0} does not contain initdb and pg_ctl")]
    BadBinDir(PathBuf),
    /// Running as root, but there is no `postgres` OS user to run the
    /// server as.
    #[error("running as root but there is no `postgres` OS user to run PostgreSQL as")]
    NoPostgresUser,
    /// A file system or process operation failed.
    #[error("{context}: {source}")]
    Io {
        /// What was being done.
        context: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A command (`initdb`, `pg_ctl`) exited unsuccessfully.
    #[error("`{command}` failed ({status})\n{output}")]
    Command {
        /// The command line.
        command: String,
        /// The exit status.
        status: String,
        /// Its stdout and stderr, and for `pg_ctl start` the server log.
        output: String,
    },
    /// A PostgreSQL client operation failed. The message includes the
    /// server's error (tokio-postgres' own message is only e.g. `db error`).
    #[error("postgres: {}", error_chain(.0))]
    Postgres(#[from] tokio_postgres::Error),
    /// Certificate generation failed.
    #[error("certificate generation failed: {0}")]
    Certificate(#[from] rcgen::Error),
    /// Building a rustls configuration failed.
    #[error("tls configuration failed: {0}")]
    Tls(#[from] rustls::Error),
}

impl TestkitError {
    fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        TestkitError::Io {
            context: context.into(),
            source,
        }
    }
}

/// Options for [`PgCluster::start`]. All empty by default.
#[derive(Debug, Clone, Default)]
pub struct PgOptions {
    /// Preferred major version, used when `$PGBEARER_TEST_PG_BIN` is not
    /// set and `/usr/lib/postgresql/<version>/bin` exists; otherwise the
    /// normal lookup applies. Check [`PgCluster::version_num`] when a test
    /// needs a particular version.
    pub version: Option<u32>,
    /// Lines appended to `postgresql.conf` after the test kit's own settings
    /// (so they override them; do not change `port`, `listen_addresses` or
    /// `unix_socket_directories`).
    pub extra_conf: Vec<String>,
    /// Lines placed at the top of `pg_hba.conf`, before the default rules.
    pub extra_hba: Vec<String>,
    /// SQL run as the superuser after start, one `batch_execute` per entry
    /// in order (so `CREATE DATABASE` needs an entry of its own).
    pub extra_sql: Vec<String>,
}

impl PgOptions {
    /// Default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Prefer this major version (see [`PgOptions::version`]).
    pub fn version(mut self, major: u32) -> Self {
        self.version = Some(major);
        self
    }

    /// Append a `postgresql.conf` line.
    pub fn conf(mut self, line: impl Into<String>) -> Self {
        self.extra_conf.push(line.into());
        self
    }

    /// Add a `pg_hba.conf` line before the defaults.
    pub fn hba(mut self, line: impl Into<String>) -> Self {
        self.extra_hba.push(line.into());
        self
    }

    /// Run this SQL as the superuser after start.
    pub fn sql(mut self, sql: impl Into<String>) -> Self {
        self.extra_sql.push(sql.into());
        self
    }
}

/// True when a PostgreSQL server can be started: the binaries exist and,
/// when running as root, there is a `postgres` OS user. Always true when
/// `$PGBEARER_TEST_PG_BIN` is set, so that a misconfigured CI job fails
/// (in [`PgCluster::start`]) instead of silently skipping. Tests return
/// early with a message on stderr when it is false; see [`require_pg!`].
pub fn pg_available() -> bool {
    if std::env::var_os(PG_BIN_ENV).is_some_and(|v| !v.is_empty()) {
        return true;
    }
    find_bin_dir(None).is_ok() && (!running_as_root() || postgres_os_ids().is_some())
}

/// The directory with the PostgreSQL server binaries that
/// [`PgCluster::start`] would use without a version preference.
pub fn pg_bin_dir() -> Option<PathBuf> {
    find_bin_dir(None).ok()
}

/// Return early from the calling test (a function returning `()`) with a
/// skip message on stderr when [`pg_available`] is false.
#[macro_export]
macro_rules! require_pg {
    () => {
        if !$crate::pg_available() {
            ::std::eprintln!(
                "skipping {}: PostgreSQL server binaries not available (set {})",
                ::std::module_path!(),
                $crate::PG_BIN_ENV,
            );
            return;
        }
    };
}

/// A running throwaway PostgreSQL cluster. See the [crate documentation](crate).
pub struct PgCluster {
    /// `None` only after drop decided to keep the directory.
    tmp: Option<TempDir>,
    root: PathBuf,
    data_dir: PathBuf,
    socket_dir: PathBuf,
    log_path: PathBuf,
    bin_dir: PathBuf,
    /// Run `initdb` / `pg_ctl` through `runuser -u postgres`.
    as_postgres: bool,
    port: u16,
    version_num: u32,
    pki: Pki,
    /// `pg_ctl start` was attempted, so drop must try to stop the server.
    started: bool,
    /// [`PgCluster::stop`] succeeded.
    stopped: bool,
}

impl std::fmt::Debug for PgCluster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgCluster")
            .field("root", &self.root)
            .field("port", &self.port)
            .field("version_num", &self.version_num)
            .field("bin_dir", &self.bin_dir)
            .field("as_postgres", &self.as_postgres)
            .finish_non_exhaustive()
    }
}

impl PgCluster {
    /// Create, configure and start a cluster, then create [`LOGIN_GROUP`]
    /// and run [`PgOptions::extra_sql`].
    pub async fn start(options: PgOptions) -> Result<PgCluster, TestkitError> {
        let bin_dir = find_bin_dir(options.version)?;
        let as_postgres = running_as_root();
        let owner = if as_postgres {
            Some(postgres_os_ids().ok_or(TestkitError::NoPostgresUser)?)
        } else {
            None
        };

        let tmp = tempfile::Builder::new()
            .prefix("pgbtk-")
            .tempdir_in(temp_base(as_postgres))
            .map_err(|e| TestkitError::io("create temporary directory", e))?;
        let root = tmp.path().to_path_buf();
        let socket_dir = root.join("sock");
        let tls_dir = root.join("tls");
        for dir in [&socket_dir, &tls_dir, &tls_dir.join("clients")] {
            std::fs::create_dir(dir)
                .map_err(|e| TestkitError::io(format!("create {}", dir.display()), e))?;
        }
        let pki = Pki::generate(&tls_dir)?;
        if let Some((uid, gid)) = owner {
            chown_recursive(&root, uid, gid)?;
        }

        let mut cluster = PgCluster {
            tmp: Some(tmp),
            data_dir: root.join("data"),
            log_path: root.join("postgres.log"),
            socket_dir,
            root,
            bin_dir,
            as_postgres,
            port: 0,
            version_num: 0,
            pki,
            started: false,
            stopped: false,
        };
        // From here on, an error drops `cluster`, which stops the server (if
        // it got that far) and removes the directory.
        cluster.init(&options).await?;
        cluster.start_server(&options).await?;

        let admin = cluster.admin().await?;
        admin
            .batch_execute(&format!("CREATE ROLE {LOGIN_GROUP} NOLOGIN"))
            .await?;
        for sql in &options.extra_sql {
            admin.batch_execute(sql).await?;
        }
        let row = admin
            .query_one("SELECT current_setting('server_version_num')::int4", &[])
            .await?;
        let version: i32 = row.try_get(0)?;
        cluster.version_num = u32::try_from(version).unwrap_or(0);
        Ok(cluster)
    }

    /// Run `initdb` and write `pg_hba.conf` / `pg_ident.conf`.
    async fn init(&self, options: &PgOptions) -> Result<(), TestkitError> {
        let mut args: Vec<OsString> = vec!["-D".into(), self.data_dir.clone().into_os_string()];
        args.extend(
            [
                "--username",
                ADMIN_USER,
                "--auth-local=trust",
                "--auth-host=scram-sha-256",
                "--encoding=UTF8",
                "--no-locale",
                "--no-sync",
                "--no-instructions",
            ]
            .map(OsString::from),
        );
        self.run_pg("initdb", &args).await?;

        let mut hba = String::from("# pgbearer-testkit\n");
        for line in &options.extra_hba {
            hba.push_str(line);
            hba.push('\n');
        }
        hba.push_str(&format!(
            "local   all all                          trust\n\
             hostssl all +{LOGIN_GROUP} 127.0.0.1/32 cert map=pgbearer\n\
             hostssl all all             127.0.0.1/32 scram-sha-256\n\
             host    all all             127.0.0.1/32 scram-sha-256\n"
        ));
        // Overwrite in place so the files keep their owner.
        write_existing(&self.data_dir.join("pg_hba.conf"), &hba)?;
        write_existing(
            &self.data_dir.join("pg_ident.conf"),
            &format!("# pgbearer-testkit\npgbearer {CERT_USER} +{LOGIN_GROUP}\n"),
        )?;
        Ok(())
    }

    /// Write `postgresql.conf` with a free port and start the server,
    /// retrying with another port when the chosen one was taken meanwhile.
    async fn start_server(&mut self, options: &PgOptions) -> Result<(), TestkitError> {
        let conf_path = self.data_dir.join("postgresql.conf");
        let base_conf = std::fs::read_to_string(&conf_path)
            .map_err(|e| TestkitError::io(format!("read {}", conf_path.display()), e))?;
        let mut attempt = 1;
        loop {
            self.port = free_port()?;
            let mut conf = base_conf.clone();
            conf.push_str(&self.testkit_conf());
            for line in &options.extra_conf {
                conf.push_str(line);
                conf.push('\n');
            }
            write_existing(&conf_path, &conf)?;

            self.started = true;
            let args: Vec<OsString> = vec![
                "-D".into(),
                self.data_dir.clone().into_os_string(),
                "-l".into(),
                self.log_path.clone().into_os_string(),
                "-w".into(),
                "-t".into(),
                "60".into(),
                "-s".into(),
                "start".into(),
            ];
            match self.run_pg("pg_ctl", &args).await {
                Ok(_) => return Ok(()),
                Err(TestkitError::Command {
                    command,
                    status,
                    output,
                }) => {
                    let log = self.log_contents();
                    let port_taken = log.contains("could not create any TCP/IP sockets")
                        || log.contains("Address already in use");
                    if port_taken && attempt < START_ATTEMPTS {
                        attempt += 1;
                        continue;
                    }
                    return Err(TestkitError::Command {
                        command,
                        status,
                        output: format!("{output}\n--- server log ---\n{}", tail(&log, 40)),
                    });
                }
                Err(other) => return Err(other),
            }
        }
    }

    /// The test kit's `postgresql.conf` settings for the current port.
    fn testkit_conf(&self) -> String {
        format!(
            "\n# --- pgbearer-testkit ---\n\
             listen_addresses = '{HOST}'\n\
             port = {port}\n\
             unix_socket_directories = '{sock}'\n\
             ssl = on\n\
             ssl_cert_file = '{cert}'\n\
             ssl_key_file = '{key}'\n\
             ssl_ca_file = '{ca}'\n\
             password_encryption = 'scram-sha-256'\n\
             logging_collector = off\n\
             log_connections = on\n\
             log_line_prefix = '%m [%p] %q%u@%d '\n\
             shared_buffers = '32MB'\n\
             fsync = off\n\
             synchronous_commit = off\n\
             full_page_writes = off\n",
            port = self.port,
            sock = conf_quote(&self.socket_dir),
            cert = conf_quote(self.pki.server_cert_path()),
            key = conf_quote(self.pki.server_key_path()),
            ca = conf_quote(self.pki.ca_cert_path()),
        )
    }

    /// Stop the server cleanly (`pg_ctl stop -m fast`) and remove the
    /// temporary directory.
    pub async fn stop(mut self) -> Result<(), TestkitError> {
        let args: Vec<OsString> = vec![
            "-D".into(),
            self.data_dir.clone().into_os_string(),
            "-m".into(),
            "fast".into(),
            "-w".into(),
            "-t".into(),
            "60".into(),
            "-s".into(),
            "stop".into(),
        ];
        self.run_pg("pg_ctl", &args).await?;
        self.stopped = true;
        Ok(())
    }

    /// Connection settings for the bootstrap superuser over the unix socket
    /// (database `postgres`).
    pub fn admin_config(&self) -> Config {
        let mut config = Config::new();
        config
            .host_path(&self.socket_dir)
            .port(self.port)
            .user(ADMIN_USER)
            .dbname("postgres")
            .application_name("pgbearer-testkit")
            .connect_timeout(CONNECT_TIMEOUT);
        config
    }

    /// A new superuser connection over the unix socket. The connection task
    /// is spawned on the current tokio runtime.
    pub async fn admin(&self) -> Result<Client, TestkitError> {
        let (client, connection) = self.admin_config().connect(NoTls).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(client)
    }

    /// Run `sql` (one or more statements) as the superuser on a fresh
    /// connection.
    pub async fn exec(&self, sql: &str) -> Result<(), TestkitError> {
        self.admin().await?.batch_execute(sql).await?;
        Ok(())
    }

    /// TCP connection settings for `user` to `127.0.0.1:<port>`, database
    /// `postgres`. Add a password or change the database as needed, then
    /// pass it to [`PgCluster::connect_tls`] or [`PgCluster::connect_plain`].
    /// (Do not call `host` on it: tokio-postgres would add a second host; use
    /// [`PgCluster::tcp_config_with_host`] instead.)
    pub fn tcp_config(&self, user: &str) -> Config {
        self.tcp_config_with_host(user, HOST)
    }

    /// Like [`PgCluster::tcp_config`], but with `host` as the host name
    /// (the name the server certificate is verified against, e.g.
    /// `"localhost"`) while still connecting to 127.0.0.1 (`hostaddr`).
    pub fn tcp_config_with_host(&self, user: &str, host: &str) -> Config {
        let mut config = Config::new();
        config
            .host(host)
            .hostaddr(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .port(self.port)
            .user(user)
            .dbname("postgres")
            .application_name("pgbearer-testkit")
            .connect_timeout(CONNECT_TIMEOUT);
        config
    }

    /// A rustls client configuration that verifies the server against the
    /// cluster's CA (including the host name, like `sslmode=verify-full`),
    /// presenting a freshly minted client certificate with CN `client_cn`
    /// when given.
    pub fn client_tls_config(
        &self,
        client_cn: Option<&str>,
    ) -> Result<rustls::ClientConfig, TestkitError> {
        let mut roots = RootCertStore::empty();
        roots.add(self.pki.ca_cert_der().clone())?;
        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots);
        Ok(match client_cn {
            Some(cn) => {
                let client = self.pki.mint_client(cn)?;
                builder.with_client_auth_cert(vec![client.cert_der], client.key_der)?
            }
            None => builder.with_no_client_auth(),
        })
    }

    /// Connect with TLS required and verified against the cluster's CA
    /// (see [`PgCluster::client_tls_config`]). The connection task is
    /// spawned on the current tokio runtime.
    pub async fn connect_tls(
        &self,
        config: &Config,
        client_cn: Option<&str>,
    ) -> Result<Client, TestkitError> {
        let tls = MakeRustlsConnect::new(self.client_tls_config(client_cn)?);
        let mut config = config.clone();
        config.ssl_mode(SslMode::Require);
        let (client, connection) = config.connect(tls).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(client)
    }

    /// Connect without TLS. The connection task is spawned on the current
    /// tokio runtime.
    pub async fn connect_plain(&self, config: &Config) -> Result<Client, TestkitError> {
        let mut config = config.clone();
        config.ssl_mode(SslMode::Disable);
        let (client, connection) = config.connect(NoTls).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(client)
    }

    /// The TCP port (on [`HOST`]).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The TCP listen address, `"127.0.0.1"`.
    pub fn host(&self) -> &'static str {
        HOST
    }

    /// The TCP listen address and port.
    pub fn addr(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port)
    }

    /// The directory holding the unix socket (`.s.PGSQL.<port>`).
    pub fn socket_dir(&self) -> &Path {
        &self.socket_dir
    }

    /// The data directory.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// The directory with the binaries in use.
    pub fn bin_dir(&self) -> &Path {
        &self.bin_dir
    }

    /// `server_version_num`, e.g. `160004`.
    pub fn version_num(&self) -> u32 {
        self.version_num
    }

    /// The CA certificate (PEM) that signed the server and client
    /// certificates.
    pub fn ca_cert_path(&self) -> &Path {
        self.pki.ca_cert_path()
    }

    /// The CA certificate in PEM format.
    pub fn ca_cert_pem(&self) -> String {
        self.pki.ca_cert_pem()
    }

    /// The CA certificate in DER format.
    pub fn ca_cert_der(&self) -> rustls::pki_types::CertificateDer<'static> {
        self.pki.ca_cert_der().clone()
    }

    /// The server certificate (PEM; SANs `localhost` and `127.0.0.1`).
    pub fn server_cert_path(&self) -> &Path {
        self.pki.server_cert_path()
    }

    /// The server private key (PEM, PKCS#8).
    pub fn server_key_path(&self) -> &Path {
        self.pki.server_key_path()
    }

    /// Mint a client certificate with common name `cn`, signed by the
    /// cluster's CA, and return the paths of the certificate and its key
    /// (PEM, mode 0600).
    pub fn client_cert(&self, cn: &str) -> Result<(PathBuf, PathBuf), TestkitError> {
        let client = self.pki.mint_client(cn)?;
        Ok((client.cert_path, client.key_path))
    }

    /// The server log so far (empty when it cannot be read).
    pub fn log_contents(&self) -> String {
        std::fs::read(&self.log_path)
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default()
    }

    /// The path of the server log.
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// A command for a PostgreSQL binary, as the `postgres` OS user when
    /// running as root.
    fn pg_command(&self, program: &str) -> Command {
        let exe = self.bin_dir.join(program);
        let mut cmd = if self.as_postgres {
            let mut cmd = Command::new(runuser_path());
            cmd.args(["-u", POSTGRES_OS_USER, "--"]).arg(exe);
            cmd
        } else {
            Command::new(exe)
        };
        cmd.current_dir(&self.root).stdin(Stdio::null());
        for var in [
            "PGDATA",
            "PGHOST",
            "PGHOSTADDR",
            "PGPORT",
            "PGUSER",
            "PGDATABASE",
            "PGOPTIONS",
            "PGSERVICE",
            "PGSSLMODE",
            "PGPASSWORD",
            "PGPASSFILE",
        ] {
            cmd.env_remove(var);
        }
        cmd
    }

    /// Run a PostgreSQL binary to completion; a non-zero exit is an error.
    async fn run_pg(&self, program: &str, args: &[OsString]) -> Result<Output, TestkitError> {
        let mut cmd = self.pg_command(program);
        cmd.args(args);
        let command = describe(&cmd);
        let output = tokio::process::Command::from(cmd)
            .output()
            .await
            .map_err(|e| TestkitError::io(format!("run `{command}`"), e))?;
        if output.status.success() {
            Ok(output)
        } else {
            Err(TestkitError::Command {
                command,
                status: output.status.to_string(),
                output: format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ),
            })
        }
    }
}

impl Drop for PgCluster {
    fn drop(&mut self) {
        if self.started && !self.stopped {
            let mut cmd = self.pg_command("pg_ctl");
            cmd.arg("-D")
                .arg(&self.data_dir)
                .args(["-m", "immediate", "-w", "-t", "30", "-s", "stop"])
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            // Best effort: the server may already be gone.
            let _ = cmd.status();
        }
        let keep = std::env::var_os(KEEP_ENV).is_some_and(|v| !v.is_empty());
        if let Some(tmp) = self.tmp.take() {
            if keep {
                let path = tmp.keep();
                eprintln!("pgbearer-testkit: kept {}", path.display());
            } else if std::thread::panicking() {
                eprintln!(
                    "pgbearer-testkit: removing {} (set {KEEP_ENV}=1 to keep it)",
                    self.root.display()
                );
            }
        }
    }
}

/// Locate the server binaries: `$PGBEARER_TEST_PG_BIN`, then
/// `/usr/lib/postgresql/<version>/bin` for the preferred version, then the
/// highest `/usr/lib/postgresql/<n>/bin`, then `PATH`.
fn find_bin_dir(version: Option<u32>) -> Result<PathBuf, TestkitError> {
    if let Some(dir) = std::env::var_os(PG_BIN_ENV).filter(|v| !v.is_empty()) {
        let dir = PathBuf::from(dir);
        return if has_server_binaries(&dir) {
            Ok(dir)
        } else {
            Err(TestkitError::BadBinDir(dir))
        };
    }
    let installed = installed_versions(Path::new(DEBIAN_PG_LIB));
    if let Some(wanted) = version
        && let Some((_, dir)) = installed.iter().find(|(major, _)| *major == wanted)
    {
        return Ok(dir.clone());
    }
    if let Some((_, dir)) = installed.first() {
        return Ok(dir.clone());
    }
    std::env::var_os("PATH")
        .and_then(|path| std::env::split_paths(&path).find(|dir| has_server_binaries(dir)))
        .ok_or(TestkitError::BinariesNotFound)
}

/// `<base>/<major>/bin` directories with server binaries, highest first.
fn installed_versions(base: &Path) -> Vec<(u32, PathBuf)> {
    let mut found: Vec<(u32, PathBuf)> = std::fs::read_dir(base)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let major = entry.file_name().to_str()?.parse::<u32>().ok()?;
            let bin = entry.path().join("bin");
            has_server_binaries(&bin).then_some((major, bin))
        })
        .collect();
    found.sort_by_key(|(major, _)| std::cmp::Reverse(*major));
    found
}

fn has_server_binaries(dir: &Path) -> bool {
    ["initdb", "pg_ctl", "postgres"]
        .iter()
        .all(|name| dir.join(name).is_file())
}

/// Whether this process runs as root, judged by the owner of a file it
/// creates (no `unsafe` `geteuid` call needed).
fn running_as_root() -> bool {
    static ROOT: OnceLock<bool> = OnceLock::new();
    *ROOT.get_or_init(|| {
        tempfile::tempfile()
            .and_then(|file| file.metadata())
            .is_ok_and(|meta| meta.uid() == 0)
    })
}

/// uid and gid of the `postgres` OS user, if it exists.
fn postgres_os_ids() -> Option<(u32, u32)> {
    static IDS: OnceLock<Option<(u32, u32)>> = OnceLock::new();
    *IDS.get_or_init(|| {
        let id = |flag: &str| -> Option<u32> {
            let out = Command::new("id")
                .args([flag, POSTGRES_OS_USER])
                .stderr(Stdio::null())
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            String::from_utf8_lossy(&out.stdout).trim().parse().ok()
        };
        Some((id("-u")?, id("-g")?))
    })
}

fn runuser_path() -> PathBuf {
    ["/usr/sbin/runuser", "/sbin/runuser", "/usr/bin/runuser"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .unwrap_or_else(|| PathBuf::from("runuser"))
}

/// Where to create the temporary directory. The unix socket path must stay
/// short (about 100 bytes), and when the server runs as `postgres` the
/// directory must be reachable by that user, so use `/tmp` in those cases.
fn temp_base(as_postgres: bool) -> PathBuf {
    let default = std::env::temp_dir();
    if as_postgres || default.as_os_str().len() > 60 {
        PathBuf::from("/tmp")
    } else {
        default
    }
}

fn chown_recursive(path: &Path, uid: u32, gid: u32) -> Result<(), TestkitError> {
    std::os::unix::fs::lchown(path, Some(uid), Some(gid))
        .map_err(|e| TestkitError::io(format!("chown {}", path.display()), e))?;
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| TestkitError::io(format!("stat {}", path.display()), e))?;
    if meta.is_dir() {
        let entries = std::fs::read_dir(path)
            .map_err(|e| TestkitError::io(format!("read {}", path.display()), e))?;
        for entry in entries {
            let entry =
                entry.map_err(|e| TestkitError::io(format!("read {}", path.display()), e))?;
            chown_recursive(&entry.path(), uid, gid)?;
        }
    }
    Ok(())
}

/// A free TCP port on 127.0.0.1 (racy by nature; start retries).
fn free_port() -> Result<u16, TestkitError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| TestkitError::io("bind 127.0.0.1:0", e))?;
    let port = listener
        .local_addr()
        .map_err(|e| TestkitError::io("local address", e))?
        .port();
    Ok(port)
}

/// Truncate and rewrite an existing file (keeping its owner and mode).
fn write_existing(path: &Path, contents: &str) -> Result<(), TestkitError> {
    std::fs::write(path, contents)
        .map_err(|e| TestkitError::io(format!("write {}", path.display()), e))
}

/// A path as a single-quoted `postgresql.conf` value body.
fn conf_quote(path: &Path) -> String {
    path.display().to_string().replace('\'', "''")
}

fn describe(cmd: &Command) -> String {
    std::iter::once(cmd.get_program())
        .chain(cmd.get_args())
        .map(|s| s.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `error: source: source of source ...`.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// The last `lines` lines of `text`.
fn tail(text: &str, lines: usize) -> String {
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn file_stem_is_safe() {
        assert_eq!(pki::file_stem("pgbearer"), "pgbearer");
        assert_eq!(pki::file_stem("a b/../c"), "a_b____c");
        assert_eq!(pki::file_stem(""), "client");
        assert_eq!(pki::file_stem(&"x".repeat(100)).len(), 64);
    }

    #[test]
    fn tail_keeps_last_lines() {
        assert_eq!(tail("a\nb\nc\n", 2), "b\nc");
        assert_eq!(tail("a", 5), "a");
        assert_eq!(tail("", 5), "");
    }

    #[test]
    fn shareable_across_tasks() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<PgCluster>();
        assert_send_sync::<TestkitError>();
    }

    #[test]
    fn postgres_errors_show_their_cause() {
        let err = "port=not-a-port".parse::<Config>().unwrap_err();
        let text = TestkitError::from(err).to_string();
        assert!(
            text.starts_with("postgres: invalid connection string: "),
            "{text}"
        );
        assert!(text.contains("port"), "{text}");
    }

    #[test]
    fn conf_quote_doubles_quotes() {
        assert_eq!(conf_quote(Path::new("/tmp/it's")), "/tmp/it''s");
    }

    #[test]
    fn installed_versions_sorted_highest_first() {
        let base = tempfile::tempdir().unwrap();
        for major in ["9", "16", "17", "not-a-version"] {
            let bin = base.path().join(major).join("bin");
            std::fs::create_dir_all(&bin).unwrap();
            for name in ["initdb", "pg_ctl", "postgres"] {
                std::fs::write(bin.join(name), "").unwrap();
            }
        }
        // A version without binaries is ignored.
        std::fs::create_dir_all(base.path().join("18").join("bin")).unwrap();
        let found: Vec<u32> = installed_versions(base.path())
            .into_iter()
            .map(|(v, _)| v)
            .collect();
        assert_eq!(found, vec![17, 16, 9]);
    }

    #[test]
    fn options_builder() {
        let o = PgOptions::new()
            .version(17)
            .conf("a = 1")
            .hba("local all x trust")
            .sql("SELECT 1");
        assert_eq!(o.version, Some(17));
        assert_eq!(o.extra_conf, ["a = 1"]);
        assert_eq!(o.extra_hba, ["local all x trust"]);
        assert_eq!(o.extra_sql, ["SELECT 1"]);
    }
}
