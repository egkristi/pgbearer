//! Role reachability and connection facts ([`crate::INSPECT_QUERY`]), risk
//! classification, and target suitability.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};

use pgbearer_config::{BackendConfig, CnpgService};
use pgbearer_core::RoleRisk;
use pgbearer_wire::messages::TxStatus;

use crate::connect::BackendConnection;
use crate::{BackendError, INSPECT_QUERY, SimpleQueryResult};

/// `pg_read_server_files`, … → [`RoleRisk::ServerFiles`].
const SERVER_FILES_ROLES: &[&str] = &[
    "pg_read_server_files",
    "pg_write_server_files",
    "pg_execute_server_program",
];

/// Predefined roles → [`RoleRisk::PredefinedAdmin`].
const PREDEFINED_ADMIN_ROLES: &[&str] = &[
    "pg_signal_backend",
    "pg_write_all_data",
    "pg_create_subscription",
    "pg_use_reserved_connections",
    "pg_maintain",
    "pg_checkpoint",
    "pg_signal_autovacuum_worker",
];

/// Predefined roles → [`RoleRisk::ReadAll`].
const READ_ALL_ROLES: &[&str] = &[
    "pg_read_all_data",
    "pg_read_all_settings",
    "pg_read_all_stats",
    "pg_monitor",
    "pg_stat_scan_tables",
];

/// Columns of the first result set of [`INSPECT_QUERY`].
const ROLE_COLUMNS: usize = 10;
/// Columns of the second result set of [`INSPECT_QUERY`].
const FACT_COLUMNS: usize = 6;

/// One role reachable from the login role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachableRole {
    /// Role name.
    pub name: String,
    /// Reachable with `SET ROLE`.
    pub via_set: bool,
    /// Privileges inherited.
    pub via_inherit: bool,
    /// Reached through an ADMIN OPTION edge (can be self-granted).
    pub via_admin: bool,
    /// Risks of this role.
    pub risks: BTreeSet<RoleRisk>,
}

/// Facts about a backend connection, from [`INSPECT_QUERY`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendInfo {
    /// Every reachable role (including the login role itself).
    pub reachable_roles: Vec<ReachableRole>,
    /// Union of all risks (including [`RoleRisk::AdminOption`] when any role is
    /// reached through an ADMIN edge).
    pub role_risks: BTreeSet<RoleRisk>,
    /// `pg_backend_pid()`.
    pub backend_pid: u32,
    /// `inet_server_addr()`:`inet_server_port()`, if not NULL.
    pub server_addr: Option<SocketAddr>,
    /// `pg_is_in_recovery()`.
    pub in_recovery: bool,
    /// `server_version_num`.
    pub server_version_num: u32,
    /// Database session id in `%c` format.
    pub backend_session_id: String,
}

/// One row of the first result set of [`INSPECT_QUERY`], parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleRow {
    /// `rolname`.
    pub name: String,
    /// Reachable with SET.
    pub via_set: bool,
    /// Reachable with INHERIT.
    pub via_inherit: bool,
    /// Reached through ADMIN.
    pub via_admin: bool,
    /// `rolsuper`.
    pub superuser: bool,
    /// `rolcreaterole`.
    pub createrole: bool,
    /// `rolreplication`.
    pub replication: bool,
    /// `rolbypassrls`.
    pub bypassrls: bool,
    /// `rolcreatedb`.
    pub createdb: bool,
    /// Owns a database.
    pub database_owner: bool,
}

/// Classify reachable roles into risks (pure; see [`RoleRisk`] for the
/// predefined-role lists). `AdminOption` is added when any row has
/// `via_admin`.
///
/// A role's own [`ReachableRole::risks`] hold its attributes and predefined
/// role class; [`RoleRisk::AdminOption`] describes how a role is reached,
/// so it appears only in the union (and as [`ReachableRole::via_admin`]).
pub fn classify_risks(rows: &[RoleRow]) -> (Vec<ReachableRole>, BTreeSet<RoleRisk>) {
    let mut all = BTreeSet::new();
    let reachable = rows
        .iter()
        .map(|row| {
            let risks = role_risks(row);
            all.extend(risks.iter().copied());
            if row.via_admin {
                all.insert(RoleRisk::AdminOption);
            }
            ReachableRole {
                name: row.name.clone(),
                via_set: row.via_set,
                via_inherit: row.via_inherit,
                via_admin: row.via_admin,
                risks,
            }
        })
        .collect();
    (reachable, all)
}

/// The risks of one role: its attributes and its predefined-role class.
fn role_risks(row: &RoleRow) -> BTreeSet<RoleRisk> {
    let mut risks = BTreeSet::new();
    for (flag, risk) in [
        (row.superuser, RoleRisk::Superuser),
        (row.createrole, RoleRisk::Createrole),
        (row.replication, RoleRisk::Replication),
        (row.bypassrls, RoleRisk::Bypassrls),
        (row.createdb, RoleRisk::Createdb),
        (row.database_owner, RoleRisk::DatabaseOwner),
    ] {
        if flag {
            risks.insert(risk);
        }
    }
    let name = row.name.as_str();
    if SERVER_FILES_ROLES.contains(&name) {
        risks.insert(RoleRisk::ServerFiles);
    }
    if PREDEFINED_ADMIN_ROLES.contains(&name) {
        risks.insert(RoleRisk::PredefinedAdmin);
    }
    if READ_ALL_ROLES.contains(&name) {
        risks.insert(RoleRisk::ReadAll);
    }
    risks
}

impl BackendConnection {
    /// Run [`INSPECT_QUERY`] and parse the result (see the crate documentation).
    pub async fn inspect(&mut self) -> Result<BackendInfo, BackendError> {
        let result = self.simple_query(INSPECT_QUERY).await?;
        if self.tx_status != TxStatus::Idle {
            return Err(BackendError::Protocol(format!(
                "the inspection query left the connection in transaction state {:?}",
                self.tx_status
            )));
        }
        parse_inspect_result(&result)
    }
}

/// Parse both result sets of [`INSPECT_QUERY`].
pub(crate) fn parse_inspect_result(result: &SimpleQueryResult) -> Result<BackendInfo, BackendError> {
    let [roles, facts] = result.result_sets.as_slice() else {
        return Err(protocol(format!(
            "expected 2 result sets, got {}",
            result.result_sets.len()
        )));
    };
    let rows = roles
        .iter()
        .map(|row| parse_role_row(row))
        .collect::<Result<Vec<_>, _>>()?;
    let [fact] = facts.as_slice() else {
        return Err(protocol(format!(
            "expected 1 row of connection facts, got {}",
            facts.len()
        )));
    };
    let [pid, host, port, in_recovery, version, session_id] = fact.as_slice() else {
        return Err(protocol(format!(
            "expected {FACT_COLUMNS} columns of connection facts, got {}",
            fact.len()
        )));
    };
    let backend_pid = parse_number::<u32>(pid, "pg_backend_pid")?;
    let server_addr = match (host, port) {
        (Some(host), Some(port)) => {
            let ip: IpAddr = host
                .parse()
                .map_err(|_| protocol(format!("invalid inet_server_addr {host:?}")))?;
            let port = parse_number::<u16>(&Some(port.clone()), "inet_server_port")?;
            Some(SocketAddr::new(ip, port))
        }
        _ => None,
    };
    let in_recovery = parse_bool(in_recovery, "pg_is_in_recovery")?;
    let server_version_num = parse_number::<u32>(version, "server_version_num")?;
    let backend_session_id = session_id
        .clone()
        .ok_or_else(|| protocol("database session id is NULL".into()))?;
    let (reachable_roles, role_risks) = classify_risks(&rows);
    Ok(BackendInfo {
        reachable_roles,
        role_risks,
        backend_pid,
        server_addr,
        in_recovery,
        server_version_num,
        backend_session_id,
    })
}

fn parse_role_row(row: &[Option<String>]) -> Result<RoleRow, BackendError> {
    let [name, s, i, a, sup, createrole, replication, bypassrls, createdb, owner] = row else {
        return Err(protocol(format!(
            "expected {ROLE_COLUMNS} columns per reachable role, got {}",
            row.len()
        )));
    };
    Ok(RoleRow {
        name: name
            .clone()
            .ok_or_else(|| protocol("role name is NULL".into()))?,
        via_set: parse_bool(s, "via_set")?,
        via_inherit: parse_bool(i, "via_inherit")?,
        via_admin: parse_bool(a, "via_admin")?,
        superuser: parse_bool(sup, "rolsuper")?,
        createrole: parse_bool(createrole, "rolcreaterole")?,
        replication: parse_bool(replication, "rolreplication")?,
        bypassrls: parse_bool(bypassrls, "rolbypassrls")?,
        createdb: parse_bool(createdb, "rolcreatedb")?,
        database_owner: parse_bool(owner, "database_owner")?,
    })
}

/// A boolean in PostgreSQL's text output format (`t`/`f`).
fn parse_bool(value: &Option<String>, what: &str) -> Result<bool, BackendError> {
    match value.as_deref() {
        Some("t") => Ok(true),
        Some("f") => Ok(false),
        other => Err(protocol(format!("invalid boolean {other:?} for {what}"))),
    }
}

fn parse_number<T: std::str::FromStr>(value: &Option<String>, what: &str) -> Result<T, BackendError> {
    value
        .as_deref()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| protocol(format!("invalid value {value:?} for {what}")))
}

fn protocol(message: String) -> BackendError {
    BackendError::Protocol(format!("inspection: {message}"))
}

/// Why a connection does not suit its backend's target (CNPG service).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetMismatch {
    /// A `-rw` backend reached a server in recovery (a replica).
    ReplicaForReadWrite,
    /// A `-ro` backend reached a server not in recovery (the primary).
    PrimaryForReadOnly,
}

impl std::fmt::Display for TargetMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TargetMismatch::ReplicaForReadWrite => {
                "the read-write service reached a server in recovery"
            }
            TargetMismatch::PrimaryForReadOnly => {
                "the read-only service reached a server that is not in recovery"
            }
        })
    }
}

/// Target suitability (ARCHITECTURE §10.6): for CNPG backends, service `rw`
/// requires `in_recovery = false` and `ro` requires `true`; `r` and static
/// backends accept any server.
pub(crate) fn check_target(backend: &BackendConfig, in_recovery: bool) -> Result<(), TargetMismatch> {
    let Some(cnpg) = &backend.cnpg else {
        return Ok(());
    };
    match (cnpg.service, in_recovery) {
        (CnpgService::Rw, true) => Err(TargetMismatch::ReplicaForReadWrite),
        (CnpgService::Ro, false) => Err(TargetMismatch::PrimaryForReadOnly),
        _ => Ok(()),
    }
}
