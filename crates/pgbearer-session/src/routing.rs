//! Routing of client connections to backends.
//!
//! Routes are evaluated in config order; the first route whose match
//! conditions all hold wins:
//! * `listeners`: the listener name is in the list (empty = any);
//! * `sni`: exact, case-insensitive host match; `*.example.com` matches exactly
//!   one additional leading label (`a.example.com`, not `a.b.example.com` or
//!   `example.com`); when the route has `sni` set but the client sent none,
//!   the route does not match;
//! * `databases`: the database is in the list or the list contains `*`
//!   (empty = any).
//!
//! When no routes are configured and exactly one backend exists, everything
//! routes to that backend.

use pgbearer_config::Config;

/// Compiled routes.
#[derive(Debug, Clone)]
pub struct Router {
    _private: (),
}

impl Router {
    /// Build from a validated config.
    pub fn from_config(config: &Config) -> Router {
        let _ = config;
        todo!("pgbearer-session: Router::from_config")
    }

    /// Backend name for a connection, or `None` when no route matches.
    pub fn resolve(&self, listener: &str, sni: Option<&str>, database: &str) -> Option<String> {
        let _ = (listener, sni, database);
        todo!("pgbearer-session: Router::resolve")
    }
}
