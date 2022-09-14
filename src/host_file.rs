//! Support for OpenSSH-compatible `known_hosts` file.

use guard::guard;
use bytes::Bytes;
use hmac::Mac as _;
use std::str;
use crate::pubkey::Pubkey;

/// Representation of an OpenSSH-compatible `known_hosts` file.
///
/// This file stores information about host keys. It is a list of entries, where each entry has a
/// hostname and a public key. The hostname can be represented in plaintext (`example.com`), as a
/// plaintext pattern (`*.examp?e.com`), as a list of such patterns (`example.com,github.com`) or
/// in a hashed format that hides the hostname (`|1|kRjF0OC...`).
///
/// You can iterate over all entries using [`entries()`][Self::entries()], or you can use
/// [`match_hostname_key()`][Self::match_hostname_key()]/[`match_host_port_key()`][Self::match_host_port_key()]
/// to lookup the entries that either accept or revoke a given combination of host and key.
#[derive(Debug, Clone)]
pub struct File {
    lines: Vec<Line>,
}

#[derive(Debug, Clone)]
struct Line {
    #[allow(dead_code)] // be ready for writing files
    bytes: Bytes,
    content: LineContent,
}

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
enum LineContent {
    Comment,
    Entry(Entry),
    Error(&'static str),
}

/// An entry in [`File`].
///
/// The entry constains a hostname pattern and a public key assigned to that hostname.
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Entry {
    line_i: usize,
    marker: Option<Marker>,
    pattern: Pattern,
    key: Pubkey,
    key_comment: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
enum Marker {
    CertAuthority,
    Revoked,
}

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
enum Pattern {
    Hashed(HashedPattern),
    List(Vec<PlaintextPattern>),
}

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
struct HashedPattern {
    salt: Vec<u8>,
    hash: Vec<u8>,
}

#[derive(Debug, Clone)]
struct PlaintextPattern {
    is_negated: bool,
    regex: regex::Regex,
}

/// A match returned by [`File::match_hostname_key()`].
#[derive(Debug, Clone)]
pub enum KeyMatch<'e> {
    /// The key was accepted for this hostname.
    ///
    /// The `Vec` lists the entries that match the hostname and the key, it is always non-empty.
    Accepted(Vec<&'e Entry>),

    /// The key was revoked.
    ///
    /// The `Entry` is the first revoked entry in the file that matches the hostname and the key.
    Revoked(&'e Entry),

    /// The combination of key and host was not found.
    NotFound,
}

impl File {
    /// Parses a file in OpenSSH `known_hosts` format.
    ///
    /// This function never fails: invalid lines are silently ignored.
    pub fn parse(data: Bytes) -> Self {
        parse(data)
    }

    /// Iterates through all entries in the file.
    ///
    /// Comments and invalid lines are not returned by this method.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.lines.iter().filter_map(|line| match &line.content {
            LineContent::Entry(entry) => Some(entry),
            LineContent::Comment | LineContent::Error(_) => None,
        })
    }

    /// Finds the match for the given hostname and key in this file.
    ///
    /// See [`host_port_to_hostname()`][Self::host_port_to_hostname()] for the format of the
    /// `hostname`; you can use [`match_host_port_key()`][Self::match_host_port_key()] to match a
    /// `(host, port)` pair.
    ///
    /// If you want more advanced processing, you can use [`entries()`][Self::entries()] to list
    /// all entries and the [`Entry::matches_hostname()`] and [`Entry::pubkey()`] methods to match
    /// them to a hostname and key.
    pub fn match_hostname_key(&self, hostname: &str, pubkey: &Pubkey) -> KeyMatch<'_> {
        let mut accepted = Vec::new();
        for entry in self.entries() {
            if !entry.matches_hostname(hostname) {
                continue
            }

            if entry.pubkey() != pubkey {
                continue
            }

            if entry.is_revoked() {
                return KeyMatch::Revoked(entry)
            } else {
                accepted.push(entry);
            }
        }

        if !accepted.is_empty() {
            KeyMatch::Accepted(accepted)
        } else {
            KeyMatch::NotFound
        }
    }

    /// Finds the match for the given host and port in this file.
    ///
    /// Same as [`match_hostname_key()`][Self::match_hostname_key()], but formats the host and port
    /// using [`host_port_to_hostname()`][Self::host_port_to_hostname()].
    pub fn match_host_port_key(&self, host: &str, port: u16, pubkey: &Pubkey) -> KeyMatch<'_> {
        self.match_hostname_key(&Self::host_port_to_hostname(host, port), pubkey)
    }

    /// Converts a host and port to an OpenSSH-compatible hostname.
    ///
    /// If the port is not 22, it returns `[host]:port`, otherwise the `host` is returned as-is.
    /// `host` can be either a domain name or an IP address.
    pub fn host_port_to_hostname(host: &str, port: u16) -> String {
        if port == 22 {
            host.into()
        } else {
            format!("[{}]:{}", host, port)
        }
    }
}

impl Entry {
    /// The line number of this entry in the [`File`].
    ///
    /// Lines are counted from 1.
    pub fn line(&self) -> usize {
        self.line_i + 1
    }

    /// Has this entry been revoked using the `@revoked` marker?
    ///
    /// This signifies that the public key from this entry has been revoked for the host, so
    /// if the server provides this key, the connection should be rejected.
    pub fn is_revoked(&self) -> bool {
        matches!(self.marker, Some(Marker::Revoked))
    }

    /// The public key of this entry.
    pub fn pubkey(&self) -> &Pubkey {
        &self.key
    }

    /// The optional comment of the [public key][Self::pubkey()].
    pub fn key_comment(&self) -> Option<&str> {
        self.key_comment.as_deref()
    }

    /// Tests whether the hostname matches this entry.
    pub fn matches_hostname(&self, hostname: &str) -> bool {
        pattern_matches(&self.pattern, hostname)
    }
}

fn pattern_matches(pattern: &Pattern, hostname: &str) -> bool {
    match pattern {
        Pattern::Hashed(pattern) => {
            guard!{let Ok(mut hmac) = hmac::Hmac::<sha1::Sha1>::new_from_slice(&pattern.salt) else {
                return false;
            }};
            hmac.update(hostname.as_bytes());
            hmac.verify_slice(&pattern.hash).is_ok()
        },
        Pattern::List(patterns) => {
            let mut matches = false;
            for pattern in patterns.iter() {
                if pattern.regex.is_match(hostname) {
                    if pattern.is_negated {
                        return false
                    } else {
                        matches = true
                    }
                }
            }
            matches
        },
    }
}

fn parse(data: Bytes) -> File {
    let lines = data.split(|&b| b == b'\n')
        .enumerate()
        .map(|(line_i, bytes)| {
            let bytes = data.slice_ref(bytes);
            let content = match parse_line(&bytes, line_i) {
                Ok(content) => content,
                Err(msg) => LineContent::Error(msg),
            };
            Line { bytes, content }
        })
        .collect();
    File { lines }
}

fn parse_line(mut bytes: &[u8], line_i: usize) -> Result<LineContent, &'static str> {
    // empty lines are treated as comments
    guard!{let Some(first_field) = read_field(&mut bytes) else {
        return Ok(LineContent::Comment)
    }};

    // first comes the optional marker preceded with '@'
    let (pattern_field, marker) = if first_field[0] == b'@' {
        let marker = parse_marker(first_field)?;
        let pattern_field = read_field(&mut bytes).ok_or("expected host pattern after a @-marker")?;
        (pattern_field, Some(marker))
    } else {
        (first_field, None)
    };

    // the hostname pattern
    let pattern = parse_pattern(pattern_field)?;

    // the key type...
    let key_type = read_field(&mut bytes).ok_or("expected key type after host pattern")?;
    let key_type = str::from_utf8(key_type).ok().ok_or("key type is not valid utf-8")?;

    // ...followed by base64-encoded public key
    let key_base64 = read_field(&mut bytes).ok_or("expected key data in base64 after key type")?;
    let key_blob = base64::decode(key_base64).map_err(|_| "key data is invalid base64")?;
    let key = Pubkey::decode(Bytes::copy_from_slice(&key_blob))
        .ok().ok_or("could not decode the public key")?;
    if key.type_str() != key_type {
        return Err("key type is different from the specified type");
    }

    // optional comment
    consume_whitespace(&mut bytes);
    let key_comment = match str::from_utf8(bytes) {
        Ok(comment) if !comment.is_empty() => Some(comment.to_string()),
        _ => None,
    };

    let entry = Entry { line_i, marker, pattern, key, key_comment };
    Ok(LineContent::Entry(entry))
}

fn parse_marker(bytes: &[u8]) -> Result<Marker, &'static str> {
    match bytes {
        b"@cert-authority" => Ok(Marker::CertAuthority),
        b"@revoked" => Ok(Marker::Revoked),
        _ => Err("unknown @-marker"),
    }
}

fn parse_pattern(bytes: &[u8]) -> Result<Pattern, &'static str> {
    if let Some(bytes) = bytes.strip_prefix(b"|1|") {
        parse_hashed_pattern(bytes).map(Pattern::Hashed)
    } else {
        parse_list_pattern(bytes).map(Pattern::List)
    }
}

fn parse_hashed_pattern(bytes: &[u8]) -> Result<HashedPattern, &'static str> {
    let mut parts = bytes.splitn(2, |&b| b == b'|');
    let salt_base64 = parts.next().ok_or("invalid format of hashed pattern")?;
    let hash_base64 = parts.next().ok_or("expected a pipe '|' in the hashed pattern")?;

    let salt = base64::decode(salt_base64).ok().ok_or("invalid base64 in the salt")?;
    let hash = base64::decode(hash_base64).ok().ok_or("invalid base64 in the hash")?;
    Ok(HashedPattern { salt, hash })
}

fn parse_list_pattern(bytes: &[u8]) -> Result<Vec<PlaintextPattern>, &'static str> {
    bytes.split(|&b| b == b',')
        .filter(|bs| !bs.is_empty())
        .map(parse_plaintext_pattern)
        .collect()
}

fn parse_plaintext_pattern(bytes: &[u8]) -> Result<PlaintextPattern, &'static str> {
    let mut pattern = str::from_utf8(bytes).map_err(|_| "host pattern is not valid utf-8")?;

    let mut is_negated = false;
    if let Some(p) = pattern.strip_prefix("!") {
        pattern = p;
        is_negated = true;
    }

    let mut regex = String::new();
    regex.push('^');
    for c in pattern.chars() {
        match c {
            '*' => regex.push_str(".*"),
            '?' => regex.push_str("."),
            c if regex_syntax::is_meta_character(c) => {
                regex.push('\\');
                regex.push(c);
            },
            c => regex.push(c),
        }
    }
    regex.push('$');

    let regex = regex::Regex::new(&regex).unwrap();
    Ok(PlaintextPattern { is_negated, regex })
}

fn read_field<'b>(bytes: &mut &'b [u8]) -> Option<&'b [u8]> {
    consume_whitespace(bytes);

    // '#' starts a comment, which should be ignored
    if matches!(bytes.get(0), None | Some(b'#')) {
        return None
    }

    let mut field_len = 1;
    while field_len < bytes.len() {
        if bytes[field_len].is_ascii_whitespace() {
            break;
        }
        field_len += 1;
    }

    let field = &bytes[..field_len];
    *bytes = &bytes[field_len..];
    Some(field)
}

fn consume_whitespace(bytes: &mut &[u8]) {
    let mut white_len = 0;
    while white_len < bytes.len() && bytes[white_len].is_ascii_whitespace() {
        white_len += 1;
    }
    *bytes = &bytes[white_len..];
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use regex::Regex;
    use super::*;

    impl std::cmp::PartialEq for PlaintextPattern {
        fn eq(&self, other: &Self) -> bool {
            self.is_negated == other.is_negated &&
                self.regex.as_str() == other.regex.as_str()
        }
    }

    #[test]
    fn test_parse_hashed_pattern() {
        fn check(pattern: &str, salt: &[u8], hash: &[u8]) {
            assert_eq!(
                parse_hashed_pattern(pattern.as_bytes()).unwrap(),
                HashedPattern {
                    salt: salt.into(),
                    hash: hash.into(),
                }
            );
        }

        check(
            // github.com
            "kRjF0OC+k0NXr8wZhiz/+2qYE+M=|8/wJhcR4K2kE/vz6LJH7m06YQTM=",
            &hex!("9118c5d0e0be934357afcc19862cfffb6a9813e3"),
            &hex!("f3fc0985c4782b6904fefcfa2c91fb9b4e984133"),
        );

        check(
            // 140.82.121.3
            "CX7HfI5Z+Ruic/z1x52VYsyeLlM=|sZ70Dk9euq7IBddgujbngUaWwec=",
            &hex!("097ec77c8e59f91ba273fcf5c79d9562cc9e2e53"),
            &hex!("b19ef40e4f5ebaaec805d760ba36e7814696c1e7"),
        );

        assert!(parse_hashed_pattern("".as_bytes()).is_err());
        assert!(parse_hashed_pattern("deadbeef".as_bytes()).is_err());
        assert!(parse_hashed_pattern("invalid|sZ70Dk9euq7IBddgujbngUaWwec=".as_bytes()).is_err());
    }

    #[test]
    fn test_parse_plaintext_pattern() {
        fn check(text: &str, is_negated: bool, regex: &str) {
            assert_eq!(
                parse_plaintext_pattern(text.as_bytes()).unwrap(),
                PlaintextPattern {
                    is_negated,
                    regex: Regex::new(regex).unwrap(),
                }
            );
        }

        check("example.com", false, r"^example\.com$");
        check("!example.com", true, r"^example\.com$");
        check("1.203.45.67", false, r"^1\.203\.45\.67$");
        check("*.example.com", false, r"^.*\.example\.com$");
        check("*.exam?le.com", false, r"^.*\.exam.le\.com$");
        check("example.*.??", false, r"^example\..*\...$");
        check("[8.8.4.4]:1234", false, r"^\[8\.8\.4\.4\]:1234$");

        assert!(parse_plaintext_pattern(&b"\xff"[..]).is_err());
    }

    #[test]
    fn test_parse_list_pattern() {
        fn check(text: &str, patterns: &[(bool, &str)]) {
            assert_eq!(
                parse_list_pattern(text.as_bytes()).unwrap(),
                patterns.iter().map(|&(is_negated, regex)| {
                    PlaintextPattern { is_negated, regex: Regex::new(regex).unwrap() }
                }).collect::<Vec<_>>(),
            );
        }

        check("topsecret.maralagoclub.com", &[(false, r"^topsecret\.maralagoclub\.com$")]);
        check("github.com,gitlab.org", &[(false, r"^github\.com$"), (false, r"^gitlab\.org$")]);
        check("*.com,!github.com", &[(false, r"^.*\.com$"), (true, r"^github\.com$")]);
    }

    #[test]
    fn test_parse_pattern() {
        assert_eq!(
            parse_pattern("|1|kRjF0OC+k0NXr8wZhiz/+2qYE+M=|8/wJhcR4K2kE/vz6LJH7m06YQTM=".as_bytes()).unwrap(),
            Pattern::Hashed(HashedPattern {
                salt: hex!("9118c5d0e0be934357afcc19862cfffb6a9813e3").into(),
                hash: hex!("f3fc0985c4782b6904fefcfa2c91fb9b4e984133").into(),
            }),
        );

        assert_eq!(
            parse_pattern("!exampl?.com,*.com".as_bytes()).unwrap(),
            Pattern::List(vec![
                PlaintextPattern {
                    is_negated: true,
                    regex: Regex::new(r"^exampl.\.com$").unwrap(),
                },
                PlaintextPattern {
                    is_negated: false,
                    regex: Regex::new(r"^.*\.com$").unwrap(),
                },
            ]),
        );
    }

    #[test]
    fn test_parse_line() {
        fn check_error(text: &str) {
            assert!(parse_line(text.as_bytes(), 42).is_err());
        }

        fn check_comment(text: &str) {
            assert_eq!(parse_line(text.as_bytes(), 42).unwrap(), LineContent::Comment);
        }

        fn check_entry(text: String, entry: Entry) {
            assert_eq!(parse_line(text.as_bytes(), 42).unwrap(), LineContent::Entry(entry));
        }

        check_comment("");
        check_comment("  \t\r");
        check_comment("  # this is a comment");

        let pubkey_b64 = "AAAAC3NzaC1lZDI1NTE5AAAAIPJUmxF+H42aRAqDYOHqs9Wh2JDecL51WgYygy1hxswl";
        let pubkey_bytes = hex!("f2549b117e1f8d9a440a8360e1eab3d5a1d890de70be755a0632832d61c6cc25");
        let pubkey = ed25519_dalek::PublicKey::from_bytes(&pubkey_bytes).unwrap();
        let pubkey = Pubkey::Ed25519(pubkey.into());

        check_entry(format!("example.com ssh-ed25519 {} edward", pubkey_b64), Entry {
            line_i: 42,
            marker: None,
            pattern: Pattern::List(vec![PlaintextPattern {
                is_negated: false,
                regex: Regex::new(r"^example\.com$").unwrap(),
            }]),
            key: pubkey.clone(),
            key_comment: Some("edward".into()),
        });

        check_entry(format!("@revoked example.com ssh-ed25519 {}", pubkey_b64), Entry {
            line_i: 42,
            marker: Some(Marker::Revoked),
            pattern: Pattern::List(vec![PlaintextPattern {
                is_negated: false,
                regex: Regex::new(r"^example\.com$").unwrap(),
            }]),
            key: pubkey.clone(),
            key_comment: None,
        });

        check_error("example.com");
        check_error(&format!("example.com ssh-rsa {}", pubkey_b64));
        check_error(&format!("@bad-marker example.com ssh-ed25519 {}", pubkey_b64));
    }

    #[test]
    fn test_pattern_matches() {
        fn check(pattern_text: &str, examples: &[(&str, bool)]) {
            let pattern = parse_pattern(pattern_text.as_bytes()).unwrap();
            for (hostname, should_match) in examples.iter() {
                assert_eq!(pattern_matches(&pattern, hostname), *should_match,
                    "{:?} {:?}", pattern_text, hostname);
            }
        }

        check("example.com", &[
            ("example.com", true),
            ("prefix.example.com", false),
            ("example.com.suffix", false),
            ("examplexcom", false),
            ("something.completely.different", false),
        ]);

        check("*.example.com", &[
            ("something.example.com", true),
            (".example.com", true),
            ("example.com", false),
        ]);

        check("examp?e.com", &[
            ("example.com", true),
            ("exampxe.com", true),
            ("exampe.com", false),
            ("some.example.com", false),
            ("examplle.com", false),
        ]);

        check("*host,!local*", &[
            ("remotehost", true),
            ("localhost", false),
            ("localname", false),
        ]);

        check("|1|kRjF0OC+k0NXr8wZhiz/+2qYE+M=|8/wJhcR4K2kE/vz6LJH7m06YQTM=", &[
            ("github.com", true),
            ("prefix.github.com", false),
            ("gitlab.org", false),
        ]);
    }

    #[test]
    fn test_file() {
        fn check_accepted(file: &File, host: &str, port: u16, pubkey: &Pubkey, checks: Vec<fn(&Entry)>) {
            match file.match_host_port_key(host, port, pubkey) {
                KeyMatch::Accepted(entries) => {
                    assert_eq!(entries.len(), checks.len());
                    for (entry, check) in entries.iter().zip(checks.iter().copied()) {
                        check(entry);
                    }
                },
                res => panic!("expected Accepted, got: {:?}", res),
            }
        }

        fn check_revoked(file: &File, host: &str, port: u16, pubkey: &Pubkey, check: fn(&Entry)) {
            match file.match_host_port_key(host, port, pubkey) {
                KeyMatch::Revoked(entry) => check(entry),
                res => panic!("expected Revoked, got {:?}", res),
            }
        }

        fn check_not_found(file: &File, host: &str, port: u16, pubkey: &Pubkey) {
            match file.match_host_port_key(host, port, pubkey) {
                KeyMatch::NotFound => (),
                res => panic!("expected NotFound, got {:?}", res),
            }
        }

        let file = File::parse(concat!(
            // line 1
            "# this is an example comment\n",
            // line 2
            "example.com ssh-ed25519 ",
                "AAAAC3NzaC1lZDI1NTE5AAAAIPJUmxF+H42aRAqDYOHqs9Wh2JDecL51WgYygy1hxswl edward\n",
            // line 3
            "\n",
            // line 4
            "github.com ssh-rsa ",
                "AAAAB3NzaC1yc2EAAAADAQABAAAAgQDnLg5lad1AyvxMYIxO47fxOVa35bMBzI",
                "3EfJ4mAZsFPQ+d4O1IVvicXPI1XwjEFIbXxoQKZw4uqkJafbWKjpmz5GvykCob",  
                "aZ3pZt9zT3sScSmQmy4AmhAuVT8LaDhwsScWVptuircH1b9S0VdcgJO1BvO/VM",
                "KiPWRAI85tD72KEQ== ruth\n",
            // line 5
            "*.gitlab.org ssh-ed25519 ",
                "AAAAC3NzaC1lZDI1NTE5AAAAIAklXWCTvkbJ2y9Ib9CpRvIfVykSdgOBHiDC/dv1hZKz alice\n",
            // line 6
            "secure.gitlab.org ssh-ed25519 ",
                "AAAAC3NzaC1lZDI1NTE5AAAAIAklXWCTvkbJ2y9Ib9CpRvIfVykSdgOBHiDC/dv1hZKz alice\n",
            // line 7
            "syntax error\n",
            // line 8
            "@revoked insecure.gitlab.org ssh-ed25519 ",
                "AAAAC3NzaC1lZDI1NTE5AAAAIAklXWCTvkbJ2y9Ib9CpRvIfVykSdgOBHiDC/dv1hZKz alice\n",
        ).into());

        let edward = keys::edward_ed25519().pubkey();
        let ruth = keys::ruth_rsa_1024().pubkey();
        let alice = keys::alice_ed25519().pubkey();

        assert_eq!(file.entries().count(), 5);

        check_accepted(&file, "example.com", 22, &edward, vec![
            |e| {
                assert_eq!(e.line(), 2);
                assert_eq!(e.is_revoked(), false);
                assert_eq!(e.key_comment(), Some("edward"));
            },
        ]);
        check_not_found(&file, "prefix.example.com", 22, &edward);
        check_not_found(&file, "example.com", 42, &edward);

        check_accepted(&file, "github.com", 22, &ruth, vec![
            |e| assert_eq!(e.line(), 4),
        ]);
        check_not_found(&file, "github.com", 22, &edward);
            
        check_accepted(&file, "secure.gitlab.org", 22, &alice, vec![
            |e| assert_eq!(e.line(), 5),
            |e| assert_eq!(e.line(), 6),
        ]);
        check_accepted(&file, "www.gitlab.org", 22, &alice, vec![
            |e| assert_eq!(e.line(), 5),
        ]);
        check_revoked(&file, "insecure.gitlab.org", 22, &alice,
            |e| assert_eq!(e.line(), 8),
        );
    }

    #[allow(dead_code)]
    mod keys {
        mod makiko {
            pub use crate::*;
        }
        include!("../tests/keys/keys.rs");
    }
}
