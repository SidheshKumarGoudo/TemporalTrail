//! Gateway: network-layer isolation for trial timelines.
//! Phase 3, step 1: validated allowlist + nftables ruleset generation.
//! This module only produces text; it never touches the system.

use std::fmt;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayError {
    BadAddress(String),
    BadName(String),
}

impl fmt::Display for GatewayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GatewayError::BadAddress(s) => write!(f, "invalid allowlist address: {s}"),
            GatewayError::BadName(s) => write!(f, "invalid name: {s}"),
        }
    }
}

impl std::error::Error for GatewayError {}

/// One allowlisted destination: a single IPv4 address or a CIDR range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowEntry {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl AllowEntry {
    /// Accepts "1.1.1.1" or "10.0.0.0/8". Rejects anything else.
    /// A /0 prefix is rejected because "allow everything" is not an allowlist.
    pub fn parse(s: &str) -> Result<Self, GatewayError> {
        let s = s.trim();
        let bad = || GatewayError::BadAddress(s.to_string());
        let (ip_part, prefix) = match s.split_once('/') {
            Some((ip, p)) => (ip, p.parse::<u8>().map_err(|_| bad())?),
            None => (s, 32),
        };
        if prefix == 0 || prefix > 32 {
            return Err(bad());
        }
        let addr: Ipv4Addr = ip_part.parse().map_err(|_| bad())?;
        // Normalize host bits away: 10.1.2.3/8 becomes 10.0.0.0/8
        let mask = u32::MAX << (32 - prefix as u32);
        let addr = Ipv4Addr::from(u32::from(addr) & mask);
        Ok(AllowEntry { addr, prefix })
    }
}

impl fmt::Display for AllowEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.prefix == 32 {
            write!(f, "{}", self.addr)
        } else {
            write!(f, "{}/{}", self.addr, self.prefix)
        }
    }
}

/// Names that get pasted into nft rules must be boring: letters, digits, '_' (and '-' for interfaces).
fn check_name(s: &str, max_len: usize, allow_dash: bool) -> Result<(), GatewayError> {
    let ok = !s.is_empty()
        && s.len() <= max_len
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || (allow_dash && c == '-'));
    if ok {
        Ok(())
    } else {
        Err(GatewayError::BadName(s.to_string()))
    }
}

/// Build the full nftables script for one trial.
/// - `table`: base name for the nft tables (e.g. "tt_gw_trial1")
/// - `host_if`: the host-side veth interface (max 15 chars, Linux limit)
/// - `subnet`: the trial's subnet, used for NAT (e.g. 10.200.0.0/24)
/// - `allow`: destinations the trial may reach
pub fn render_ruleset(
    table: &str,
    host_if: &str,
    subnet: AllowEntry,
    allow: &[AllowEntry],
) -> Result<String, GatewayError> {
    check_name(table, 32, false)?;
    check_name(host_if, 15, true)?;

    let mut l: Vec<String> = Vec::new();
    l.push(format!("table inet {table} {{"));
    l.push("  chain gw_forward {".to_string());
    l.push("    type filter hook forward priority 0; policy accept;".to_string());
    for entry in allow {
        l.push(format!("    iifname \"{host_if}\" ip daddr {entry} accept"));
    }
    l.push(format!(
        "    oifname \"{host_if}\" ct state established,related accept"
    ));
    l.push(format!("    iifname \"{host_if}\" drop"));
    l.push(format!("    oifname \"{host_if}\" drop"));
    l.push("  }".to_string());
    l.push("}".to_string());
    l.push(format!("table ip {table}_nat {{"));
    l.push("  chain post {".to_string());
    l.push("    type nat hook postrouting priority 100;".to_string());
    l.push(format!("    ip saddr {subnet} masquerade"));
    l.push("  }".to_string());
    l.push("}".to_string());
    Ok(l.join("\n") + "\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subnet() -> AllowEntry {
        AllowEntry::parse("10.200.0.0/24").unwrap()
    }

    #[test]
    fn parses_single_ip_and_cidr() {
        assert_eq!(AllowEntry::parse("1.1.1.1").unwrap().to_string(), "1.1.1.1");
        assert_eq!(
            AllowEntry::parse("10.0.0.0/8").unwrap().to_string(),
            "10.0.0.0/8"
        );
    }

    #[test]
    fn normalizes_host_bits() {
        assert_eq!(
            AllowEntry::parse("10.1.2.3/8").unwrap().to_string(),
            "10.0.0.0/8"
        );
    }

    #[test]
    fn rejects_junk_and_injection() {
        for bad in [
            "",
            "banana",
            "1.1.1.1/33",
            "1.1.1.256",
            "0.0.0.0/0",
            "1.1.1.1; flush ruleset",
            "1.1.1.1 accept\n",
            "1.1.1.1/",
        ] {
            assert!(AllowEntry::parse(bad).is_err(), "should reject: {bad:?}");
        }
    }

    #[test]
    fn rejects_bad_names() {
        let allow = [AllowEntry::parse("1.1.1.1").unwrap()];
        assert!(render_ruleset("bad name", "tt-h", subnet(), &allow).is_err());
        assert!(render_ruleset("ok_table", "tt-h\"; drop", subnet(), &allow).is_err());
        assert!(render_ruleset("ok_table", "this_name_is_way_too_long", subnet(), &allow).is_err());
    }

    #[test]
    fn renders_expected_rules_in_safe_order() {
        let allow = [
            AllowEntry::parse("1.1.1.1").unwrap(),
            AllowEntry::parse("10.0.0.0/8").unwrap(),
        ];
        let out = render_ruleset("tt_gw_t1", "tt-h", subnet(), &allow).unwrap();
        assert!(out.contains("iifname \"tt-h\" ip daddr 1.1.1.1 accept"));
        assert!(out.contains("iifname \"tt-h\" ip daddr 10.0.0.0/8 accept"));
        assert!(out.contains("ip saddr 10.200.0.0/24 masquerade"));
        // every accept must come before the catch-all drop
        let last_accept = out.rfind("ip daddr").unwrap();
        let first_drop = out.find("iifname \"tt-h\" drop").unwrap();
        assert!(last_accept < first_drop);
    }

    #[test]
    fn empty_allowlist_allows_nothing_outbound() {
        let out = render_ruleset("tt_gw_t1", "tt-h", subnet(), &[]).unwrap();
        assert!(!out.contains("ip daddr"));
        assert!(out.contains("iifname \"tt-h\" drop"));
    }
}