//! Unit tests for [`StartupProfile`], [`split_options`] and the deny-list.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use super::*;

fn params(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn profile(pairs: &[(&str, &str)]) -> StartupProfile {
    match StartupProfile::from_startup(&params(pairs)) {
        Ok(p) => p,
        Err(e) => panic!("{pairs:?} was refused: {e:?}"),
    }
}

fn error(pairs: &[(&str, &str)]) -> ProfileError {
    match StartupProfile::from_startup(&params(pairs)) {
        Ok(p) => panic!("{pairs:?} was accepted: {p:?}"),
        Err(e) => e,
    }
}

fn kind(pairs: &[(&str, &str)]) -> ProfileErrorKind {
    error(pairs).kind
}

/// A profile for `alice` with the given `options` string.
fn with_options(options: &str) -> Result<StartupProfile, ProfileError> {
    StartupProfile::from_startup(&params(&[("user", "alice"), ("options", options)]))
}

fn options_ok(options: &str) -> Vec<(String, String)> {
    match with_options(options) {
        Ok(p) => p.settings,
        Err(e) => panic!("options {options:?} were refused: {e:?}"),
    }
}

fn options_err(options: &str) -> ProfileError {
    match with_options(options) {
        Ok(p) => panic!("options {options:?} were accepted: {p:?}"),
        Err(e) => e,
    }
}

fn settings(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    params(pairs)
}

fn split(s: &str) -> Vec<String> {
    split_options(s)
}

fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

fn hash_of(p: &StartupProfile) -> u64 {
    let mut h = DefaultHasher::new();
    p.hash(&mut h);
    h.finish()
}

// ---------------------------------------------------------------------------
// Reserved keys: user, database
// ---------------------------------------------------------------------------

#[test]
fn user_and_database_are_taken_out_of_the_settings() {
    let p = profile(&[("user", "alice"), ("database", "orders")]);
    assert_eq!(p.user, "alice");
    assert_eq!(p.database, "orders");
    assert!(p.settings.is_empty());
}

#[test]
fn missing_database_defaults_to_user() {
    let p = profile(&[("user", "alice")]);
    assert_eq!(p.database, "alice");
}

#[test]
fn empty_database_defaults_to_user() {
    let p = profile(&[("database", ""), ("user", "alice")]);
    assert_eq!(p.user, "alice");
    assert_eq!(p.database, "alice");
}

#[test]
fn empty_user_is_allowed_with_a_database() {
    let p = profile(&[("user", ""), ("database", "orders")]);
    assert_eq!(p.user, "");
    assert_eq!(p.database, "orders");
    let p = profile(&[("database", "orders")]);
    assert_eq!(p.user, "");
    assert_eq!(p.database, "orders");
}

#[test]
fn no_database_name_is_malformed() {
    for pairs in [
        &[][..],
        &[("user", "")][..],
        &[("database", "")][..],
        &[("user", ""), ("database", "")][..],
        &[("application_name", "x")][..],
    ] {
        let e = error(pairs);
        assert_eq!(e.kind, ProfileErrorKind::Malformed, "{pairs:?}");
        assert_eq!(e.message, "no database name in the startup packet");
        assert_eq!(e.sqlstate(), "08P01");
    }
}

#[test]
fn duplicate_reserved_keys_are_malformed() {
    for key in ["user", "database", "options", "replication"] {
        let value = if key == "replication" { "off" } else { "" };
        let e = error(&[("user", "alice"), (key, value), (key, value)]);
        assert_eq!(e.kind, ProfileErrorKind::Malformed, "{key}");
        assert!(e.message.contains("duplicate startup parameter"), "{e}");
        assert!(e.message.contains(key), "{e}");
    }
    // Duplicates with different values too.
    assert_eq!(
        kind(&[("user", "alice"), ("user", "postgres")]),
        ProfileErrorKind::Malformed
    );
    assert_eq!(
        kind(&[("user", "a"), ("database", "x"), ("database", "y")]),
        ProfileErrorKind::Malformed
    );
    assert_eq!(
        kind(&[("user", "a"), ("options", "-c a=1"), ("options", "-c b=2")]),
        ProfileErrorKind::Malformed
    );
}

// ---------------------------------------------------------------------------
// Reserved keys: replication
// ---------------------------------------------------------------------------

#[test]
fn replication_off_values_are_accepted_and_not_forwarded() {
    for value in [
        "false", "off", "0", "no", "FALSE", "False", "OFF", "Off", "NO", "No", "fAlSe",
    ] {
        let p = profile(&[("user", "alice"), ("replication", value)]);
        assert!(p.settings.is_empty(), "{value}: {p:?}");
        assert_eq!(p.get("replication"), None);
        assert!(
            p.backend_parameters(&[])
                .iter()
                .all(|(k, _)| k != "replication")
        );
    }
}

#[test]
fn replication_on_values_are_unsupported() {
    for value in [
        "true", "on", "1", "yes", "database", "TRUE", "Database", "", "f", "n", "of", " false",
        "false ", "2",
    ] {
        let e = error(&[("user", "alice"), ("replication", value)]);
        assert_eq!(e.kind, ProfileErrorKind::Unsupported, "{value:?}");
        assert_eq!(e.message, "replication connections are not supported");
        assert_eq!(e.sqlstate(), "0A000");
    }
}

// ---------------------------------------------------------------------------
// Reserved keys: _pq_.* and options
// ---------------------------------------------------------------------------

#[test]
fn protocol_options_are_ignored() {
    let p = profile(&[
        ("user", "alice"),
        ("_pq_.test_option", "on"),
        ("_pq_.other", "x"),
        ("_pq_.test_option", "again"),
        ("_pq_.", ""),
        ("_pq_.Mixed-Case!", "y"),
    ]);
    assert!(p.settings.is_empty(), "{p:?}");
    assert!(p.backend_parameters(&[]).is_empty());
}

#[test]
fn case_variants_of_protocol_options_are_forbidden() {
    // Forwarded lower-cased, the backend would read these as protocol options.
    for key in ["_PQ_.x", "_Pq_.test_option"] {
        let e = error(&[("user", "alice"), (key, "1")]);
        assert_eq!(e.kind, ProfileErrorKind::Forbidden, "{key}");
    }
    for options in ["-c _pq_.x=1", "--_pq_.x=1", "-c_PQ_.x=1", "-c _pq-.x=1"] {
        assert_eq!(
            options_err(options).kind,
            ProfileErrorKind::Forbidden,
            "{options}"
        );
    }
}

#[test]
fn options_are_never_forwarded_raw() {
    let p = profile(&[("user", "alice"), ("options", "-c search_path=app")]);
    assert_eq!(p.settings, settings(&[("search_path", "app")]));
    assert!(
        p.backend_parameters(&[])
            .iter()
            .all(|(k, _)| k != "options")
    );
}

#[test]
fn empty_or_blank_options_give_no_settings() {
    for options in ["", " ", "\t\n\r\x0B\x0C  "] {
        assert!(options_ok(options).is_empty(), "{options:?}");
    }
}

// ---------------------------------------------------------------------------
// split_options
// ---------------------------------------------------------------------------

#[test]
fn split_on_runs_of_ascii_whitespace() {
    assert_eq!(split(""), Vec::<String>::new());
    assert_eq!(split("   "), Vec::<String>::new());
    assert_eq!(split("a"), strs(&["a"]));
    assert_eq!(split("a b"), strs(&["a", "b"]));
    assert_eq!(split("  a   b  "), strs(&["a", "b"]));
    assert_eq!(
        split("a\tb\nc\rd\x0Be\x0Cf g"),
        strs(&["a", "b", "c", "d", "e", "f", "g"])
    );
    assert_eq!(split("\t\x0B-c\x0C\r\na=1\n"), strs(&["-c", "a=1"]));
}

#[test]
fn split_does_not_treat_non_ascii_whitespace_as_separator() {
    // U+00A0 (no-break space), U+2003 (em space), U+0085 (next line).
    assert_eq!(split("a\u{a0}b"), strs(&["a\u{a0}b"]));
    assert_eq!(split("a\u{2003}b c"), strs(&["a\u{2003}b", "c"]));
    assert_eq!(split("a\u{85}b"), strs(&["a\u{85}b"]));
    assert_eq!(split("ä ö"), strs(&["ä", "ö"]));
}

#[test]
fn split_backslash_escapes() {
    assert_eq!(split(r"a\ b"), strs(&["a b"]));
    assert_eq!(split(r"a\\b"), strs(&[r"a\b"]));
    assert_eq!(split(r"a\\ b"), strs(&[r"a\", "b"]));
    assert_eq!(split(r"\a\b\c"), strs(&["abc"]));
    assert_eq!(split("a\\\tb"), strs(&["a\tb"]));
    assert_eq!(split("a\\\nb"), strs(&["a\nb"]));
    assert_eq!(split(r"\\\\"), strs(&[r"\\"]));
    assert_eq!(split(r"\ "), strs(&[" "]));
    assert_eq!(split(r"\ \ x"), strs(&["  x"]));
    assert_eq!(split("\\é"), strs(&["é"]));
    assert_eq!(
        split(r"-c search_path=a,\ b -c x=1"),
        strs(&["-c", "search_path=a, b", "-c", "x=1"])
    );
}

#[test]
fn split_trailing_backslash_is_dropped() {
    assert_eq!(split("a\\"), strs(&["a"]));
    assert_eq!(split("a b\\"), strs(&["a", "b"]));
    // A lone backslash is an empty argument, as in pg_split_opts.
    assert_eq!(split("\\"), strs(&[""]));
    assert_eq!(split("a \\"), strs(&["a", ""]));
    assert_eq!(split("a \\ "), strs(&["a", " "]));
    assert_eq!(split("a\\\\\\"), strs(&["a\\"]));
}

// ---------------------------------------------------------------------------
// options: accepted forms
// ---------------------------------------------------------------------------

#[test]
fn the_three_dash_c_forms_are_accepted() {
    assert_eq!(options_ok("-c a=1"), settings(&[("a", "1")]));
    assert_eq!(options_ok("-ca=1"), settings(&[("a", "1")]));
    assert_eq!(options_ok("--a=1"), settings(&[("a", "1")]));
    assert_eq!(
        options_ok("-c a=1 -cb=2 --c=3"),
        settings(&[("a", "1"), ("b", "2"), ("c", "3")])
    );
}

#[test]
fn dash_c_takes_the_next_argument_whatever_it_looks_like() {
    // As getopt: the argument after `-c` is its value, even if it starts
    // with `-`; `-` in the name becomes `_`.
    assert_eq!(options_ok("-c -x=1"), settings(&[("_x", "1")]));
    assert_eq!(options_ok("-c --x=1"), settings(&[("__x", "1")]));
}

#[test]
fn value_is_everything_after_the_first_equals_sign() {
    assert_eq!(options_ok("-c a="), settings(&[("a", "")]));
    assert_eq!(options_ok("--a="), settings(&[("a", "")]));
    assert_eq!(options_ok("-ca=b=c"), settings(&[("a", "b=c")]));
    assert_eq!(options_ok("-c a==="), settings(&[("a", "==")]));
    assert_eq!(
        options_ok(r"-c search_path=a,\ b"),
        settings(&[("search_path", "a, b")])
    );
    assert_eq!(
        options_ok(r"-c application_name=my\ app\\x"),
        settings(&[("application_name", r"my app\x")])
    );
    assert_eq!(
        options_ok("-c application_name=caf\u{e9}"),
        settings(&[("application_name", "caf\u{e9}")])
    );
}

#[test]
fn dashes_in_option_names_become_underscores() {
    assert_eq!(
        options_ok("--statement-timeout=5s -c lock-timeout=1 -cidle-session-timeout=0"),
        settings(&[
            ("idle_session_timeout", "0"),
            ("lock_timeout", "1"),
            ("statement_timeout", "5s"),
        ])
    );
    // Only in the name: the value keeps its dashes.
    assert_eq!(
        options_ok("-c search-path=a-b"),
        settings(&[("search_path", "a-b")])
    );
}

#[test]
fn dashes_in_direct_keys_are_malformed() {
    let e = error(&[("user", "alice"), ("statement-timeout", "5")]);
    assert_eq!(e.kind, ProfileErrorKind::Malformed);
    assert!(e.message.contains("statement-timeout"), "{e}");
}

// ---------------------------------------------------------------------------
// options: rejected forms
// ---------------------------------------------------------------------------

#[test]
fn other_switches_are_unsupported() {
    for (options, shown) in [
        ("-P", "-P"),
        ("-W 10", "-W"),
        ("-d 5", "-d"),
        ("-e", "-e"),
        ("-f s", "-f"),
        ("-S 1000", "-S"),
        ("-B 100", "-B"),
        ("-F", "-F"),
        ("-o x", "-o"),
        ("-ec a=1", "-ec"),
        ("-Pc a=1", "-Pc"),
        ("-C a=1", "-C"),
        ("-", "-"),
        ("bare", "bare"),
        ("a=1", "a=1"),
        ("-c a=1 -P", "-P"),
        ("-c a=1 b=2", "b=2"),
        ("--a=1 word", "word"),
    ] {
        let e = options_err(options);
        assert_eq!(e.kind, ProfileErrorKind::Unsupported, "{options}");
        assert_eq!(
            e.message,
            format!("startup option \"{shown}\" is not supported; only -c name=value"),
            "{options}"
        );
        assert_eq!(e.sqlstate(), "0A000");
    }
}

#[test]
fn dash_c_at_the_end_is_unsupported() {
    for options in ["-c", "-c a=1 -c", " -c ", "--a=1\t-c\n"] {
        let e = options_err(options);
        assert_eq!(e.kind, ProfileErrorKind::Unsupported, "{options:?}");
        assert!(e.message.contains("only -c name=value"), "{e}");
    }
}

#[test]
fn an_empty_argument_is_unsupported() {
    // A lone backslash is an empty argument (neither -c nor --).
    assert_eq!(options_err("\\").kind, ProfileErrorKind::Unsupported);
}

#[test]
fn a_name_without_equals_is_malformed() {
    for options in [
        "-c foo",
        "-cfoo",
        "--foo",
        "--",
        "-c a=1 --b",
        "-c \\",
        "-c -c",
    ] {
        let e = options_err(options);
        assert_eq!(e.kind, ProfileErrorKind::Malformed, "{options:?}");
        assert!(e.message.contains("expected -c name=value"), "{e}");
        assert_eq!(e.sqlstate(), "08P01");
    }
}

#[test]
fn syntax_errors_come_before_name_errors() {
    // The whole `options` string is parsed before names are checked.
    assert_eq!(
        options_err("-c 1bad=x -P").kind,
        ProfileErrorKind::Unsupported
    );
    assert_eq!(
        options_err("-c role=x -P").kind,
        ProfileErrorKind::Unsupported
    );
    assert_eq!(
        options_err("-c role=x --y").kind,
        ProfileErrorKind::Malformed
    );
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

#[test]
fn names_are_lower_cased() {
    let p = profile(&[
        ("user", "alice"),
        ("TimeZone", "UTC"),
        ("DateStyle", "ISO, MDY"),
        ("options", "-c IntervalStyle=iso_8601 --Search-Path=app"),
    ]);
    assert_eq!(
        p.settings,
        settings(&[
            ("datestyle", "ISO, MDY"),
            ("intervalstyle", "iso_8601"),
            ("search_path", "app"),
            ("timezone", "UTC"),
        ])
    );
}

#[test]
fn valid_names() {
    let long_part = "a".repeat(63);
    let long_dotted = format!("{long_part}.{long_part}");
    for name in [
        "a",
        "_",
        "_a",
        "a1",
        "a_b",
        "A",
        "Z9",
        "my.custom",
        "my_ext.some_setting",
        "a.b.c",
        "_x._y",
        long_part.as_str(),
        long_dotted.as_str(),
    ] {
        let p = profile(&[("user", "alice"), (name, "v")]);
        assert_eq!(p.get(name), Some("v"), "{name}");
        assert_eq!(p.settings[0].0, name.to_ascii_lowercase());
    }
}

#[test]
fn invalid_names_are_malformed() {
    let too_long = "a".repeat(64);
    let too_long_part = format!("x.{too_long}");
    for name in [
        "",
        "1a",
        "9",
        "a.1b",
        "a..b",
        ".a",
        "a.",
        ".",
        too_long.as_str(),
        too_long_part.as_str(),
        "a$",
        "a b",
        "a-b",
        "a.b-c",
        "\u{e9}",
        "caf\u{e9}",
        "a\0b",
        "a=b",
        "a\\b",
        "\"a\"",
    ] {
        let e = error(&[("user", "alice"), (name, "v")]);
        assert_eq!(e.kind, ProfileErrorKind::Malformed, "{name:?}");
        assert!(
            e.message.starts_with("invalid startup parameter name"),
            "{e}"
        );
    }
    // The same rules for names from options.
    for options in [
        "-c 1a=v", "--a..b=v", "-c.a=v", "-ca$=v", "--=v", "-c=v", "-c \\ =v",
    ] {
        let e = options_err(options);
        assert_eq!(e.kind, ProfileErrorKind::Malformed, "{options:?}");
        assert!(
            e.message.starts_with("invalid startup parameter name"),
            "{e}"
        );
    }
}

#[test]
fn a_name_part_may_have_63_bytes_but_not_64() {
    let ok = format!("-c x.{}=1", "b".repeat(63));
    assert_eq!(options_ok(&ok).len(), 1);
    let too_long = format!("-c x.{}=1", "b".repeat(64));
    assert_eq!(options_err(&too_long).kind, ProfileErrorKind::Malformed);
}

// ---------------------------------------------------------------------------
// Precedence and duplicates
// ---------------------------------------------------------------------------

#[test]
fn a_later_option_replaces_an_earlier_one() {
    assert_eq!(
        options_ok("-c timezone=UTC -c TimeZone=CET --TIMEZONE=EST"),
        settings(&[("timezone", "EST")])
    );
    assert_eq!(
        options_ok("-c search-path=a --search_path=b"),
        settings(&[("search_path", "b")])
    );
}

#[test]
fn direct_keys_replace_options_whatever_the_packet_order() {
    let expected = settings(&[("search_path", "app"), ("timezone", "CET")]);
    let p = profile(&[
        ("user", "alice"),
        ("options", "-c TimeZone=UTC -c search_path=app"),
        ("timezone", "CET"),
    ]);
    assert_eq!(p.settings, expected);
    let p = profile(&[
        ("TIMEZONE", "CET"),
        ("user", "alice"),
        ("options", "-c timezone=UTC -c search_path=app"),
    ]);
    assert_eq!(p.settings, expected);
}

#[test]
fn a_direct_key_and_an_option_for_the_same_name_are_not_duplicates() {
    let p = profile(&[
        ("user", "alice"),
        ("options", "-c application_name=a -c application_name=b"),
        ("Application_Name", "c"),
    ]);
    assert_eq!(p.settings, settings(&[("application_name", "c")]));
}

#[test]
fn duplicate_direct_keys_after_lower_casing_are_malformed() {
    for (a, b) in [
        ("TimeZone", "timezone"),
        ("timezone", "timezone"),
        ("TIMEZONE", "TimeZone"),
        ("search_path", "Search_Path"),
    ] {
        let e = error(&[("user", "alice"), (a, "UTC"), (b, "UTC")]);
        assert_eq!(e.kind, ProfileErrorKind::Malformed, "{a} {b}");
        assert!(e.message.starts_with("duplicate startup parameter"), "{e}");
        assert!(e.message.contains(&a.to_ascii_lowercase()), "{e}");
    }
}

#[test]
fn duplicates_are_reported_before_the_deny_list() {
    let e = error(&[("user", "alice"), ("role", "x"), ("ROLE", "y")]);
    assert_eq!(e.kind, ProfileErrorKind::Malformed);
}

#[test]
fn settings_are_sorted_and_profiles_are_canonical() {
    let a = profile(&[
        ("user", "alice"),
        ("database", "orders"),
        ("timezone", "UTC"),
        ("application_name", "psql"),
        ("options", "-c search_path=app --extra-float-digits=3"),
    ]);
    let names: Vec<&str> = a.settings.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "application_name",
            "extra_float_digits",
            "search_path",
            "timezone"
        ]
    );
    let b = profile(&[
        ("options", "--Search-Path=app -c extra_float_digits=3"),
        ("Application_Name", "psql"),
        ("database", "orders"),
        ("TimeZone", "UTC"),
        ("user", "alice"),
    ]);
    assert_eq!(a, b);
    assert_eq!(hash_of(&a), hash_of(&b));
    let c = profile(&[
        ("user", "alice"),
        ("database", "orders"),
        ("timezone", "UTC"),
        ("application_name", "psql"),
    ]);
    assert_ne!(a, c);
}

// ---------------------------------------------------------------------------
// Deny-list
// ---------------------------------------------------------------------------

/// Spellings of a denied name: as is, upper case, and mixed case.
fn case_variants(name: &str) -> Vec<String> {
    let mixed: String = name
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    vec![name.to_owned(), name.to_ascii_uppercase(), mixed]
}

fn assert_forbidden(e: &ProfileError, name: &str) {
    assert_eq!(e.kind, ProfileErrorKind::Forbidden, "{name}: {e}");
    assert_eq!(
        e.message,
        format!("startup parameter \"{name}\" may not be set through pgbearer")
    );
    assert_eq!(e.sqlstate(), "42501");
}

#[test]
fn every_denied_setting_is_forbidden_from_options() {
    for &denied in DENIED_SETTINGS {
        for spelled in case_variants(denied) {
            let dashed = spelled.replace('_', "-");
            for options in [
                format!("-c {spelled}=x"),
                format!("-c{spelled}=x"),
                format!("--{spelled}=x"),
                format!("-c {dashed}=x"),
                format!("--{dashed}=x"),
                format!("-c timezone=UTC -c {spelled}= -c search_path=a"),
            ] {
                assert_forbidden(&options_err(&options), denied);
            }
        }
    }
}

#[test]
fn every_denied_setting_except_replication_is_forbidden_as_a_direct_key() {
    for &denied in DENIED_SETTINGS {
        for spelled in case_variants(denied) {
            if spelled == "replication" {
                continue; // The reserved key itself (see below).
            }
            assert_forbidden(&error(&[("user", "alice"), (&spelled, "x")]), denied);
        }
    }
}

#[test]
fn replication_is_forbidden_as_a_setting_even_when_false() {
    for options in [
        "-c replication=false",
        "--replication=off",
        "-cREPLICATION=0",
    ] {
        assert_forbidden(&options_err(options), "replication");
    }
    // A case variant of the reserved key is a setting, not the key.
    assert_forbidden(
        &error(&[("user", "alice"), ("Replication", "false")]),
        "replication",
    );
}

#[test]
fn role_and_session_authorization_in_any_spelling_are_forbidden() {
    assert_forbidden(&error(&[("user", "alice"), ("ROLE", "postgres")]), "role");
    assert_forbidden(&error(&[("user", "alice"), ("Role", "postgres")]), "role");
    assert_forbidden(&options_err("-c Role=x"), "role");
    assert_forbidden(&options_err("-cROLE=x"), "role");
    assert_forbidden(
        &options_err("--session-authorization=x"),
        "session_authorization",
    );
    assert_forbidden(
        &options_err("--SESSION-AUTHORIZATION=x"),
        "session_authorization",
    );
    assert_forbidden(
        &error(&[("user", "alice"), ("Session_Authorization", "x")]),
        "session_authorization",
    );
    // Escapes do not hide a name.
    assert_forbidden(&options_err(r"-c \r\o\l\e=x"), "role");
}

#[test]
fn the_pgbearer_namespace_is_forbidden() {
    for name in [
        "pgbearer.sub",
        "pgbearer.username",
        "pgbearer.session_id",
        "pgbearer.x.y",
    ] {
        for spelled in case_variants(name) {
            assert_forbidden(&error(&[("user", "alice"), (&spelled, "x")]), name);
            assert_forbidden(&options_err(&format!("-c {spelled}=x")), name);
            assert_forbidden(&options_err(&format!("--{spelled}=x")), name);
        }
    }
    assert_forbidden(
        &options_err("-c pgbearer.session-id=x"),
        "pgbearer.session_id",
    );
}

#[test]
fn names_that_only_resemble_denied_ones_are_allowed() {
    for name in [
        "pgbearer",
        "pgbearerx.sub",
        "my.pgbearer",
        "my.role",
        "roles",
        "default_role",
        "log_connections_extra",
        "app.session_authorization",
        "pq_.x",
        "_pq.x",
    ] {
        let p = profile(&[("user", "alice"), (name, "v")]);
        assert_eq!(p.get(name), Some("v"), "{name}");
    }
}

#[test]
fn reserved_key_names_are_forbidden_as_settings() {
    // From options: a forwarded `user`/`database` key would change the login,
    // and a forwarded `options` key would be parsed again by the backend.
    for key in ["user", "database", "options"] {
        assert_forbidden(&options_err(&format!("-c {key}=postgres")), key);
        assert_forbidden(
            &options_err(&format!("--{}=postgres", key.to_uppercase())),
            key,
        );
    }
    assert_forbidden(&options_err(r"-c options=-c\ role=postgres"), "options");
    // Case variants of reserved keys sent directly.
    for key in ["USER", "User", "DATABASE", "Database", "OPTIONS", "Options"] {
        assert_forbidden(
            &error(&[("user", "alice"), (key, "postgres")]),
            &key.to_ascii_lowercase(),
        );
    }
}

#[test]
fn is_denied_setting_matches_the_rules() {
    for &name in DENIED_SETTINGS {
        assert!(is_denied_setting(name), "{name}");
        assert!(is_denied_setting(&name.to_ascii_uppercase()), "{name}");
    }
    for name in [
        "user",
        "DATABASE",
        "options",
        "replication",
        "pgbearer.sub",
        "PGBEARER.X",
        "_pq_.x",
        "_PQ_.y",
    ] {
        assert!(is_denied_setting(name), "{name}");
    }
    for name in [
        "timezone",
        "pgbearer",
        "pgbearerx",
        "rolex",
        "",
        "_pq_",
        "search_path",
    ] {
        assert!(!is_denied_setting(name), "{name}");
    }
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

fn numbered(prefix: &str, n: usize) -> Vec<(String, String)> {
    (0..n)
        .map(|i| (format!("{prefix}{i:03}"), i.to_string()))
        .collect()
}

fn with_user(mut settings: Vec<(String, String)>) -> Vec<(String, String)> {
    settings.insert(0, ("user".to_owned(), "alice".to_owned()));
    settings
}

#[test]
fn max_settings_direct() {
    let p = StartupProfile::from_startup(&with_user(numbered("s.n", MAX_SETTINGS))).unwrap();
    assert_eq!(p.settings.len(), MAX_SETTINGS);
    let e =
        StartupProfile::from_startup(&with_user(numbered("s.n", MAX_SETTINGS + 1))).unwrap_err();
    assert_eq!(e.kind, ProfileErrorKind::TooMany);
    assert_eq!(e.sqlstate(), "54023");
    assert!(e.message.contains("64"), "{e}");
}

#[test]
fn max_settings_counts_after_merging() {
    // 64 names from options, all replaced by direct keys: 64 settings.
    let options: Vec<String> = (0..MAX_SETTINGS)
        .map(|i| format!("-c s.n{i:03}=o"))
        .collect();
    let mut packet = with_user(numbered("s.n", MAX_SETTINGS));
    packet.push(("options".to_owned(), options.join(" ")));
    let p = StartupProfile::from_startup(&packet).unwrap();
    assert_eq!(p.settings.len(), MAX_SETTINGS);
    assert!(p.settings.iter().all(|(_, v)| v != "o"));

    // 100 `-c` arguments for one name: one setting.
    let options = vec!["-c a=1"; 100].join(" ");
    assert_eq!(options_ok(&options).len(), 1);

    // 33 from options and 32 direct, all distinct: 65.
    let options: Vec<String> = (0..33).map(|i| format!("-c o.n{i:03}=o")).collect();
    let mut packet = with_user(numbered("d.n", 32));
    packet.push(("options".to_owned(), options.join(" ")));
    let e = StartupProfile::from_startup(&packet).unwrap_err();
    assert_eq!(e.kind, ProfileErrorKind::TooMany);
}

#[test]
fn reserved_and_protocol_keys_do_not_count_towards_the_limit() {
    let mut packet = with_user(numbered("s.n", MAX_SETTINGS));
    packet.push(("database".to_owned(), "orders".to_owned()));
    packet.push(("replication".to_owned(), "false".to_owned()));
    packet.push(("options".to_owned(), String::new()));
    packet.push(("_pq_.x".to_owned(), "1".to_owned()));
    let p = StartupProfile::from_startup(&packet).unwrap();
    assert_eq!(p.settings.len(), MAX_SETTINGS);
}

#[test]
fn the_deny_list_is_checked_before_the_limit() {
    let mut packet = with_user(numbered("s.n", MAX_SETTINGS + 10));
    packet.push(("role".to_owned(), "x".to_owned()));
    let e = StartupProfile::from_startup(&packet).unwrap_err();
    assert_eq!(e.kind, ProfileErrorKind::Forbidden);
}

// ---------------------------------------------------------------------------
// get and backend_parameters
// ---------------------------------------------------------------------------

#[test]
fn get_by_name() {
    let p = profile(&[
        ("user", "alice"),
        ("TimeZone", "UTC"),
        ("options", "-c search_path=app"),
    ]);
    assert_eq!(p.get("timezone"), Some("UTC"));
    assert_eq!(p.get("TimeZone"), Some("UTC"));
    assert_eq!(p.get("search_path"), Some("app"));
    assert_eq!(p.get("datestyle"), None);
    assert_eq!(p.get("user"), None);
    assert_eq!(p.get("options"), None);
    assert_eq!(p.get(""), None);
}

fn extra() -> Vec<(String, String)> {
    params(&[
        ("pgbearer.sub", "abc"),
        ("pgbearer.username", "alice@example.com"),
        ("tcp_keepalives_idle", "30"),
        ("tcp_keepalives_interval", "10"),
        ("tcp_keepalives_count", "3"),
        ("client_connection_check_interval", "10000"),
    ])
}

#[test]
fn backend_parameters_are_settings_then_extra() {
    let p = profile(&[
        ("user", "alice"),
        ("timezone", "UTC"),
        ("application_name", "psql"),
    ]);
    let mut expected = settings(&[("application_name", "psql"), ("timezone", "UTC")]);
    expected.extend(extra());
    assert_eq!(p.backend_parameters(&extra()), expected);
    assert_eq!(p.backend_parameters(&[]), p.settings);
}

#[test]
fn backend_parameters_client_wins_for_keepalive_settings() {
    let p = profile(&[
        ("user", "alice"),
        ("tcp_keepalives_idle", "5"),
        ("options", "-c client-connection-check-interval=0"),
    ]);
    let params = p.backend_parameters(&extra());
    assert_eq!(
        params,
        settings(&[
            ("client_connection_check_interval", "0"),
            ("tcp_keepalives_idle", "5"),
            ("pgbearer.sub", "abc"),
            ("pgbearer.username", "alice@example.com"),
            ("tcp_keepalives_interval", "10"),
            ("tcp_keepalives_count", "3"),
        ])
    );
}

#[test]
fn backend_parameters_never_repeat_a_name() {
    let p = profile(&[("user", "alice"), ("tcp_keepalives_idle", "5")]);
    let extra = params(&[
        ("pgbearer.sub", "first"),
        ("pgbearer.sub", "second"),
        ("TCP_KEEPALIVES_IDLE", "30"),
    ]);
    assert_eq!(
        p.backend_parameters(&extra),
        settings(&[("tcp_keepalives_idle", "5"), ("pgbearer.sub", "first")])
    );
}

#[test]
fn backend_parameters_fit_in_a_startup_message() {
    let p = profile(&[
        ("user", "alice"),
        ("database", "orders"),
        ("options", r"-c search_path=a,\ b"),
        ("application_name", "psql"),
    ]);
    let params = p.backend_parameters(&extra());
    let mut all: Vec<(&str, &str)> = vec![("user", "app_rw"), ("database", &p.database)];
    all.extend(params.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    let mut buf = bytes::BytesMut::new();
    pgbearer_wire::startup::encode_startup_message(
        &mut buf,
        pgbearer_wire::startup::ProtocolVersion::V3_0,
        &all,
    )
    .unwrap();
    assert!(!buf.is_empty());
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[test]
fn sqlstates() {
    let e = |kind| ProfileError {
        kind,
        message: String::new(),
    };
    assert_eq!(e(ProfileErrorKind::Unsupported).sqlstate(), "0A000");
    assert_eq!(e(ProfileErrorKind::Forbidden).sqlstate(), "42501");
    assert_eq!(e(ProfileErrorKind::Malformed).sqlstate(), "08P01");
    assert_eq!(e(ProfileErrorKind::TooMany).sqlstate(), "54023");
}

#[test]
fn display_is_the_message() {
    let e = options_err("-P");
    assert_eq!(e.to_string(), e.message);
}

/// The longest run of `c` in `s`.
fn longest_run(s: &str, c: char) -> usize {
    s.split(|x| x != c).map(str::len).max().unwrap_or(0)
}

#[test]
fn messages_never_echo_more_than_64_bytes() {
    let long = "x".repeat(5000);
    let cases = [
        options_err(&format!("-c {long}")),                  // no `=`
        options_err(&format!("-c{long}")),                   // no `=`
        options_err(&format!("--{long}")),                   // no `=`
        options_err(&format!("-P{long}")),                   // unsupported
        options_err(&long),                                  // bare word
        options_err(&format!("-c 1{long}=v")),               // invalid name
        error(&[("user", "a"), (&format!("1{long}"), "v")]), // invalid name
        error(&[("user", "a"), (&format!("a{long}"), "v")]), // part too long
    ];
    for e in cases {
        assert!(longest_run(&e.message, 'x') <= 64, "{}", e.message.len());
        assert!(e.message.len() < 200, "{}", e.message);
        assert!(e.message.contains("..."), "{}", e.message);
    }
}

#[test]
fn messages_are_cut_at_character_boundaries() {
    // 63 ASCII bytes and then a two-byte character crossing byte 64.
    let name = format!("{}\u{e9}{}", "a".repeat(63), "b".repeat(10));
    let e = error(&[("user", "a"), (&name, "v")]);
    assert_eq!(e.kind, ProfileErrorKind::Malformed);
    assert!(
        e.message.contains(&format!("\"{}\"...", "a".repeat(63))),
        "{e}"
    );
}

#[test]
fn messages_escape_control_characters_and_quotes() {
    let e = options_err("-P\\\n\x01\\\t\\\"\\\\");
    assert_eq!(e.kind, ProfileErrorKind::Unsupported);
    assert!(!e.message.chars().any(char::is_control), "{:?}", e.message);
    assert_eq!(
        e.message,
        "startup option \"-P\\n\\u{1}\\t\\\"\\\\\" is not supported; only -c name=value"
    );
}

#[test]
fn nul_bytes_in_values_are_malformed() {
    for pairs in [
        &[("user", "a\0b")][..],
        &[("user", "a"), ("database", "\0")][..],
        &[("user", "a"), ("timezone", "UTC\0user\0postgres")][..],
        &[("user", "a"), ("options", "-c a=\0")][..],
    ] {
        let e = error(pairs);
        assert_eq!(e.kind, ProfileErrorKind::Malformed, "{pairs:?}");
        assert!(e.message.contains("NUL"), "{e}");
    }
}
