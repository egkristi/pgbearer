//! Property tests: [`split_options`] round-trips escaped arguments, every
//! accepted profile is canonical and free of denied names, and
//! [`StartupProfile::from_startup`] never panics.

use proptest::prelude::*;
use proptest::sample::select;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;

use super::*;

const SPACES: &[char] = &[' ', '\t', '\n', '\r', '\x0B', '\x0C'];

/// Characters that matter to the parser, mixed with arbitrary ones.
fn interesting_char() -> impl Strategy<Value = char> {
    prop_oneof![
        2 => any::<char>(),
        3 => select(
            &[
                ' ', '\t', '\n', '\r', '\x0B', '\x0C', '\\', '-', 'c', '=', '.', '_', 'a', 'Z',
                '1', '\u{a0}', '\u{85}', '\u{e9}', '"', '\0',
            ][..]
        ),
    ]
}

fn interesting_string(len: std::ops::Range<usize>) -> impl Strategy<Value = String> {
    prop::collection::vec(interesting_char(), len).prop_map(|v| v.into_iter().collect())
}

/// A run of `pg_split_opts` whitespace.
fn separator() -> impl Strategy<Value = String> {
    prop::collection::vec(select(SPACES), 1..4).prop_map(|v| v.into_iter().collect())
}

/// Escape `arg` so that it splits as one argument: backslash and whitespace
/// must be escaped; `extra[i]` escapes the `i`-th character needlessly.
fn escape(arg: &str, extra: &[bool]) -> String {
    let mut out = String::with_capacity(arg.len() * 2);
    for (i, c) in arg.chars().enumerate() {
        if c == '\\' || SPACES.contains(&c) || extra.get(i).copied().unwrap_or(false) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Setting names: denied, reserved and special names, valid names, and
/// names that are probably invalid.
fn base_name() -> impl Strategy<Value = String> {
    prop_oneof![
        1 => select(DENIED_SETTINGS).prop_map(str::to_owned),
        1 => select(
            &[
                "user",
                "database",
                "options",
                "replication",
                "_pq_.x",
                "_pq_.test",
                "pgbearer.sub",
                "pgbearer.session_id",
                "pgbearer",
                "timezone",
                "search_path",
                "application_name",
                "datestyle",
                "my.setting",
                "statement_timeout",
                "tcp_keepalives_idle",
                "session_authorization",
            ][..]
        )
        .prop_map(str::to_owned),
        8 => "[a-z_][a-z0-9_]{0,5}(\\.[a-z_][a-z0-9_]{0,3}){0,2}",
        1 => "[a-zA-Z0-9_.$ -]{0,8}",
    ]
}

/// A base name with random ASCII case.
fn cased_name() -> impl Strategy<Value = String> {
    (base_name(), any::<u64>()).prop_map(|(name, mask)| {
        name.chars()
            .enumerate()
            .map(|(i, c)| {
                if mask >> (i % 64) & 1 == 1 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect()
    })
}

fn value() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => "[a-zA-Z0-9_,. =-]{0,8}",
        1 => interesting_string(0..8).prop_map(|s| s.replace('\0', "")),
    ]
}

/// One `options` argument (or two, for `-c name=value`), already escaped.
fn option_arg() -> impl Strategy<Value = String> {
    (cased_name(), value(), 0..20u8, any::<bool>()).prop_map(|(name, value, form, dashes)| {
        let name = if dashes { name.replace('_', "-") } else { name };
        let name = escape(&name, &[]);
        let value = escape(&value, &[]);
        match form {
            0..=5 => format!("-c {name}={value}"),
            6..=10 => format!("-c{name}={value}"),
            11..=16 => format!("--{name}={value}"),
            17 => format!("-c {name}"),
            18 => format!("--{name}"),
            _ => match value.len() % 6 {
                0 => "-P".to_owned(),
                1 => "-W 10".to_owned(),
                2 => "-d 5".to_owned(),
                3 => "-e".to_owned(),
                4 => "bare".to_owned(),
                _ => "-c".to_owned(),
            },
        }
    })
}

fn options_string() -> impl Strategy<Value = String> {
    (prop::collection::vec(option_arg(), 0..5), separator()).prop_map(|(args, sep)| args.join(&sep))
}

/// A StartupMessage parameter list with a bias towards packets that are
/// accepted, but every rule exercised.
fn packet() -> impl Strategy<Value = Vec<(String, String)>> {
    let entry = prop_oneof![
        6 => (cased_name(), value()),
        2 => Just(("user".to_owned(), "alice".to_owned())),
        1 => ("[a-z]{0,4}").prop_map(|db| ("database".to_owned(), db)),
        1 => select(&["false", "off", "0", "no", "NO", "Off", "true", "on"][..])
            .prop_map(|v| ("replication".to_owned(), v.to_owned())),
        3 => options_string().prop_map(|o| ("options".to_owned(), o)),
        1 => ("_pq_\\.[a-z]{1,4}", value()),
    ];
    prop::collection::vec(entry, 0..8)
}

/// Everything the module promises about an accepted profile.
fn check_accepted(packet: &[(String, String)], p: &StartupProfile) -> Result<(), TestCaseError> {
    for (name, _) in &p.settings {
        prop_assert!(!is_denied_setting(name), "{name} in {p:?}");
        for &denied in DENIED_SETTINGS {
            prop_assert_ne!(name.as_str(), denied);
        }
        for reserved in ["user", "database", "options", "replication"] {
            prop_assert_ne!(name.as_str(), reserved);
        }
        prop_assert!(!name.starts_with("pgbearer."), "{name}");
        prop_assert!(!name.starts_with("_pq_."), "{name}");
        prop_assert!(is_valid_name(name), "{name}");
        prop_assert_eq!(name, &name.to_ascii_lowercase());
    }
    prop_assert!(
        p.settings.windows(2).all(|w| w[0].0 < w[1].0),
        "not sorted or duplicated: {:?}",
        p.settings
    );
    prop_assert!(p.settings.len() <= MAX_SETTINGS);
    prop_assert!(!p.database.is_empty());
    // Direct keys always win, under their lower-case name.
    for (key, value) in packet {
        if !RESERVED_KEYS.contains(&key.as_str()) && !key.starts_with(PROTOCOL_OPTION_PREFIX) {
            prop_assert_eq!(p.get(&key.to_ascii_lowercase()), Some(value.as_str()));
        }
    }
    // The backend parameters never repeat a name.
    let extra = vec![
        ("pgbearer.sub".to_owned(), "s".to_owned()),
        ("tcp_keepalives_idle".to_owned(), "30".to_owned()),
    ];
    let params = p.backend_parameters(&extra);
    for (i, (a, _)) in params.iter().enumerate() {
        prop_assert!(
            params[..i].iter().all(|(b, _)| !a.eq_ignore_ascii_case(b)),
            "{params:?}"
        );
    }
    Ok(())
}

fn check_error(e: &ProfileError) -> Result<(), TestCaseError> {
    // At most 64 bytes of client text, each escaped to at most 10 bytes.
    prop_assert!(e.message.len() <= 64 * 10 + 128, "{}", e.message.len());
    prop_assert!(!e.message.chars().any(char::is_control), "{:?}", e.message);
    prop_assert_eq!(e.sqlstate().len(), 5);
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// (a) `split_options` never panics, and never yields more arguments
    /// than there are characters (plus one, for a lone backslash).
    #[test]
    fn split_options_never_panics(s in interesting_string(0..40)) {
        let args = split_options(&s);
        prop_assert!(args.len() <= s.chars().count());
        for arg in &args {
            prop_assert!(arg.len() <= s.len());
        }
    }

    #[test]
    fn split_options_never_panics_on_any_string(s in any::<String>()) {
        let _ = split_options(&s);
    }

    /// (a) Arguments escaped with backslashes and joined with whitespace
    /// split back into the same arguments.
    #[test]
    fn split_options_round_trips_escaped_arguments(
        args in prop::collection::vec(interesting_string(1..12), 0..8),
        seps in prop::collection::vec(separator(), 8),
        leading in prop::option::of(separator()),
        trailing in prop::option::of(separator()),
        extra in prop::collection::vec(any::<bool>(), 12),
    ) {
        let mut s = leading.unwrap_or_default();
        for (i, arg) in args.iter().enumerate() {
            if i > 0 {
                s.push_str(&seps[i]);
            }
            s.push_str(&escape(arg, &extra));
        }
        s.push_str(&trailing.unwrap_or_default());
        prop_assert_eq!(split_options(&s), args);
    }

    /// Without backslashes, splitting is plain splitting on ASCII whitespace.
    #[test]
    fn split_options_without_escapes_splits_on_whitespace(s in interesting_string(0..40)) {
        let s = s.replace('\\', "");
        let expected: Vec<String> = s
            .split(|c: char| SPACES.contains(&c))
            .filter(|w| !w.is_empty())
            .map(str::to_owned)
            .collect();
        prop_assert_eq!(split_options(&s), expected);
    }

    /// (b) Every accepted profile is sorted, duplicate-free and contains no
    /// denied name.
    #[test]
    fn accepted_profiles_are_canonical_and_allowed(packet in packet()) {
        match StartupProfile::from_startup(&packet) {
            Ok(p) => check_accepted(&packet, &p)?,
            Err(e) => check_error(&e)?,
        }
    }

    /// Acceptance and the profile do not depend on the order of the packet
    /// (duplicates are refused, so there is no "last one wins" between
    /// direct keys).
    #[test]
    fn profiles_do_not_depend_on_packet_order(
        (packet, shuffled) in packet().prop_flat_map(|p| (Just(p.clone()), Just(p).prop_shuffle())),
    ) {
        let a = StartupProfile::from_startup(&packet);
        let b = StartupProfile::from_startup(&shuffled);
        prop_assert_eq!(a.is_ok(), b.is_ok(), "{:?} vs {:?}", a, b);
        if let (Ok(a), Ok(b)) = (a, b) {
            prop_assert_eq!(a, b);
        }
    }

    /// (c) `from_startup` never panics on arbitrary parameter lists.
    #[test]
    fn from_startup_never_panics_on_arbitrary_params(
        packet in prop::collection::vec((any::<String>(), any::<String>()), 0..10),
    ) {
        match StartupProfile::from_startup(&packet) {
            Ok(p) => check_accepted(&packet, &p)?,
            Err(e) => check_error(&e)?,
        }
    }

    /// (c) Nor on arbitrary values for the reserved keys, including
    /// arbitrary `options` strings.
    #[test]
    fn from_startup_never_panics_on_arbitrary_reserved_values(
        packet in prop::collection::vec(
            (
                prop_oneof![
                    select(&["user", "database", "options", "replication", "_pq_.x"][..])
                        .prop_map(str::to_owned),
                    interesting_string(0..10),
                ],
                interesting_string(0..30),
            ),
            0..6,
        ),
    ) {
        match StartupProfile::from_startup(&packet) {
            Ok(p) => check_accepted(&packet, &p)?,
            Err(e) => check_error(&e)?,
        }
    }

    /// (c) Nor on arbitrary `options` strings for an otherwise valid packet.
    #[test]
    fn from_startup_never_panics_on_arbitrary_options(options in interesting_string(0..60)) {
        let packet = vec![
            ("user".to_owned(), "alice".to_owned()),
            ("options".to_owned(), options),
        ];
        match StartupProfile::from_startup(&packet) {
            Ok(p) => check_accepted(&packet, &p)?,
            Err(e) => check_error(&e)?,
        }
    }
}

/// The packet generator is useful only if it produces both accepted and
/// refused packets, with every kind of refusal.
#[test]
fn the_packet_generator_covers_every_outcome() {
    let mut runner = TestRunner::deterministic();
    let strategy = packet();
    let (mut accepted, mut nonempty) = (0, 0);
    let mut kinds = Vec::new();
    for _ in 0..4000 {
        let packet = strategy.new_tree(&mut runner).unwrap().current();
        match StartupProfile::from_startup(&packet) {
            Ok(p) => {
                accepted += 1;
                if !p.settings.is_empty() {
                    nonempty += 1;
                }
            }
            Err(e) => {
                if !kinds.contains(&e.kind) {
                    kinds.push(e.kind);
                }
            }
        }
    }
    assert!(accepted >= 200, "only {accepted} of 4000 accepted");
    assert!(nonempty >= 100, "only {nonempty} of 4000 with settings");
    for kind in [
        ProfileErrorKind::Unsupported,
        ProfileErrorKind::Forbidden,
        ProfileErrorKind::Malformed,
    ] {
        assert!(kinds.contains(&kind), "{kind:?} never produced");
    }
}
