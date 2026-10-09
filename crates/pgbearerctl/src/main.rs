//! `pgbearerctl`: operator and user tooling for pgbearer.
//!
//! Commands:
//! * `validate --config FILE`: parse and validate a config; print problems.
//! * `explain --config FILE (--token JWT | --claims JSON --provider NAME)
//!   [--user U] [--database D] [--sni HOST] [--listener L] [--client-ip IP]`:
//!   show the identity extracted from the token (signature NOT verified unless
//!   `--verify`, which fetches the provider's JWKS), matching deny rules,
//!   entitlements, the route, and the final decision with its reason.
//! * `token --issuer URL --client-id ID [--scope S]`: OAuth 2.0 Device
//!   Authorization Grant (RFC 8628) against the issuer's discovery document;
//!   prints the access token to stdout (instructions go to stderr), so it can
//!   be used as `PGPASSWORD=$(pgbearerctl token …) psql …`.

use std::process::ExitCode;

use clap::Parser;

/// pgbearer tooling.
#[derive(Parser, Debug)]
#[command(name = "pgbearerctl", version, about)]
struct Cli {}

fn main() -> ExitCode {
    let _cli = Cli::parse();
    eprintln!("pgbearerctl: not implemented yet");
    ExitCode::FAILURE
}
