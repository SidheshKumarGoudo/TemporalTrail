//! Gateway: network-layer isolation for trial timelines.
//! Phase 3: validated allowlist, nftables ruleset generation, the runtime
//! that builds/tears down a trial's isolated network namespace (needs sudo),
//! and recording of blocked connection attempts.

use std::fmt;
use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayError {
    BadAddress(String),
    BadName(String),
    Command(String),
}

impl fmt::Display for GatewayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GatewayError::BadAddress(s) => write!(f, "invalid allowlist address: {s}"),
            GatewayError::BadName(s) => write!(f, "invalid name: {s}"),
            GatewayError::Command(s) => write!(f, "{s}"),
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

/// Log labels get pasted into an nft rule too: letters, digits, '_', '-', and spaces only.
fn check_prefix(s: &str) -> Result<(), GatewayError> {
    let ok = !s.is_empty()
        && s.len() <= 60
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == ' ');
    if ok {
        Ok(())
    } else {
        Err(GatewayError::BadName(s.to_string()))
    }
}

/// Build the full nftables script for one trial.
/// - `table`: base name for the nft tables (e.g. "ttgw26")
/// - `host_if`: the host-side veth interface (max 15 chars, Linux limit)
/// - `subnet`: the trial's subnet, used for NAT (e.g. 10.200.0.0/24)
/// - `allow`: destinations the trial may reach
/// - `log_prefix`: label stamped on every blocked-packet log line
pub fn render_ruleset(
    table: &str,
    host_if: &str,
    subnet: AllowEntry,
    allow: &[AllowEntry],
    log_prefix: &str,
) -> Result<String, GatewayError> {
    check_name(table, 32, false)?;
    check_name(host_if, 15, true)?;
    check_prefix(log_prefix)?;

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
    // Log (rate-limited) whatever is about to be dropped, then drop it.
    l.push(format!(
        "    iifname \"{host_if}\" limit rate 50/second burst 100 packets log prefix \"{log_prefix}\""
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

// ---------------------------------------------------------------------------
// Blocked-attempt records
// ---------------------------------------------------------------------------

/// One blocked connection attempt, as seen by the firewall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    pub dst: String,
    pub proto: String,
    pub dport: Option<String>,
}

impl Denied {
    /// Human-readable target, e.g. "8.8.8.8/ICMP" or "93.184.216.34:443/TCP".
    pub fn target(&self) -> String {
        match &self.dport {
            Some(p) => format!("{}:{}/{}", self.dst, p, self.proto),
            None => format!("{}/{}", self.dst, self.proto),
        }
    }
}

/// Parse one kernel log line. Returns None unless it carries our exact label.
pub fn parse_denied_line(line: &str, prefix: &str) -> Option<Denied> {
    if !line.contains(prefix) {
        return None;
    }
    let mut dst = None;
    let mut proto = None;
    let mut dport = None;
    for tok in line.split_whitespace() {
        if let Some(v) = tok.strip_prefix("DST=") {
            dst = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("PROTO=") {
            proto = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("DPT=") {
            dport = Some(v.to_string());
        }
    }
    Some(Denied {
        dst: dst?,
        proto: proto?,
        dport,
    })
}

/// Pull the log label back out of `nft list table ...` output.
fn extract_prefix(listing: &str) -> Option<String> {
    let marker = "prefix \"";
    let start = listing.find(marker)? + marker.len();
    let rest = &listing[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Blocked attempts recorded so far for a trial whose gateway is currently up.
/// Returns an empty list if the gateway is not up. De-duplicated, in order seen.
pub fn harvest(timeline: &str) -> Result<Vec<Denied>, GatewayError> {
    let p = plan_for(timeline)?;
    let listing = Command::new("sudo")
        .args(["nft", "list", "table", "inet", p.table.as_str()])
        .output()
        .map_err(|e| GatewayError::Command(format!("could not run nft: {e}")))?;
    if !listing.status.success() {
        return Ok(Vec::new());
    }
    let listing = String::from_utf8_lossy(&listing.stdout).to_string();
    let prefix = match extract_prefix(&listing) {
        Some(x) => x,
        None => return Ok(Vec::new()),
    };
    let log = Command::new("sudo")
        .arg("dmesg")
        .output()
        .map_err(|e| GatewayError::Command(format!("could not read kernel log: {e}")))?;
    let log = String::from_utf8_lossy(&log.stdout);
    let mut out: Vec<Denied> = Vec::new();
    for line in log.lines() {
        if let Some(d) = parse_denied_line(line, &prefix) {
            if !out.contains(&d) {
                out.push(d);
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Runtime: actually creates/destroys the isolated network (needs sudo).
// ---------------------------------------------------------------------------

/// All the names/addresses for one trial's isolated network.
/// Derived from the timeline name, so `up` and `down` always agree.
#[derive(Debug, Clone)]
pub struct Plan {
    pub ns: String,
    pub host_if: String,
    pub trial_if: String,
    pub host_ip: String,
    pub trial_ip: String,
    pub subnet: AllowEntry,
    pub table: String,
}

fn slot_for(name: &str) -> u32 {
    // FNV-1a hash -> a slot number 1..=250 (known limitation: two timelines
    // could collide; `up` then fails safely because the namespace exists).
    let mut h: u32 = 2166136261;
    for b in name.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(16777619);
    }
    h % 250 + 1
}

pub fn plan_for(timeline: &str) -> Result<Plan, GatewayError> {
    check_name(timeline, 32, true)?;
    if timeline == "main" {
        return Err(GatewayError::Command(
            "MAIN is not isolated: it is the one timeline allowed to reach the outside world"
                .into(),
        ));
    }
    let slot = slot_for(timeline);
    Ok(Plan {
        ns: format!("ttns{slot}"),
        host_if: format!("tth{slot}"),
        trial_if: format!("ttt{slot}"),
        host_ip: format!("10.200.{slot}.1"),
        trial_ip: format!("10.200.{slot}.2"),
        subnet: AllowEntry::parse(&format!("10.200.{slot}.0/24"))?,
        table: format!("ttgw{slot}"),
    })
}

fn run_sudo(args: &[&str]) -> Result<(), GatewayError> {
    let out = Command::new("sudo")
        .args(args)
        .output()
        .map_err(|e| GatewayError::Command(format!("could not run sudo: {e}")))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(GatewayError::Command(format!(
            "`sudo {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

fn load_ruleset(script: &str) -> Result<(), GatewayError> {
    let mut child = Command::new("sudo")
        .args(["nft", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| GatewayError::Command(format!("could not run nft: {e}")))?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .map_err(|e| GatewayError::Command(format!("could not send rules to nft: {e}")))?;
    let out = child
        .wait_with_output()
        .map_err(|e| GatewayError::Command(format!("nft did not finish: {e}")))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(GatewayError::Command(format!(
            "nft rejected the ruleset: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

/// Create the namespace, the virtual cable, routing, and the firewall allowlist.
/// If any step fails, everything built so far is torn down again.
pub fn up(timeline: &str, allow: &[AllowEntry]) -> Result<Plan, GatewayError> {
    let p = plan_for(timeline)?;
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let log_prefix = format!("TTDENY {}-{} ", p.table, secs);
    let script = render_ruleset(&p.table, &p.host_if, p.subnet, allow, &log_prefix)?;
    run_sudo(&["ip", "netns", "add", &p.ns])?;

    let host_cidr = format!("{}/24", p.host_ip);
    let trial_cidr = format!("{}/24", p.trial_ip);
    let steps = || -> Result<(), GatewayError> {
        run_sudo(&["ip", "link", "add", &p.host_if, "type", "veth", "peer", "name", &p.trial_if])?;
        run_sudo(&["ip", "link", "set", &p.trial_if, "netns", &p.ns])?;
        run_sudo(&["ip", "addr", "add", &host_cidr, "dev", &p.host_if])?;
        run_sudo(&["ip", "link", "set", &p.host_if, "up"])?;
        run_sudo(&["ip", "netns", "exec", &p.ns, "ip", "addr", "add", &trial_cidr, "dev", &p.trial_if])?;
        run_sudo(&["ip", "netns", "exec", &p.ns, "ip", "link", "set", &p.trial_if, "up"])?;
        run_sudo(&["ip", "netns", "exec", &p.ns, "ip", "link", "set", "lo", "up"])?;
        run_sudo(&["ip", "netns", "exec", &p.ns, "ip", "route", "add", "default", "via", &p.host_ip])?;
        run_sudo(&["sysctl", "-w", "net.ipv4.ip_forward=1"])?;
        load_ruleset(&script)
    };
    match steps() {
        Ok(()) => Ok(p),
        Err(e) => {
            let _ = down(timeline);
            Err(e)
        }
    }
}

/// Remove everything `up` created. Best-effort: missing pieces are ignored.
pub fn down(timeline: &str) -> Result<(), GatewayError> {
    let p = plan_for(timeline)?;
    let nat = format!("{}_nat", p.table);
    let _ = run_sudo(&["nft", "delete", "table", "inet", &p.table]);
    let _ = run_sudo(&["nft", "delete", "table", "ip", &nat]);
    let _ = run_sudo(&["ip", "link", "del", &p.host_if]);
    let _ = run_sudo(&["ip", "netns", "del", &p.ns]);
    Ok(())
}

/// Run a command inside the trial's namespace; returns its exit code.
pub fn exec_in(timeline: &str, cmd: &[String]) -> Result<i32, GatewayError> {
    let p = plan_for(timeline)?;
    let status = Command::new("sudo")
        .args(["ip", "netns", "exec", &p.ns])
        .args(cmd)
        .status()
        .map_err(|e| GatewayError::Command(format!("could not run command: {e}")))?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PFX: &str = "TTDENY t1-100 ";

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
        assert!(render_ruleset("bad name", "tt-h", subnet(), &allow, PFX).is_err());
        assert!(render_ruleset("ok_table", "tt-h\"; drop", subnet(), &allow, PFX).is_err());
        assert!(render_ruleset("ok_table", "this_name_is_way_too_long", subnet(), &allow, PFX).is_err());
        assert!(render_ruleset("ok_table", "tt-h", subnet(), &allow, "bad\"; drop").is_err());
    }

    #[test]
    fn renders_expected_rules_in_safe_order() {
        let allow = [
            AllowEntry::parse("1.1.1.1").unwrap(),
            AllowEntry::parse("10.0.0.0/8").unwrap(),
        ];
        let out = render_ruleset("tt_gw_t1", "tt-h", subnet(), &allow, PFX).unwrap();
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
        let out = render_ruleset("tt_gw_t1", "tt-h", subnet(), &[], PFX).unwrap();
        assert!(!out.contains("ip daddr"));
        assert!(out.contains("iifname \"tt-h\" drop"));
    }

    #[test]
    fn log_rule_sits_between_accepts_and_drop() {
        let allow = [AllowEntry::parse("1.1.1.1").unwrap()];
        let out = render_ruleset("tt_gw_t1", "tt-h", subnet(), &allow, PFX).unwrap();
        let accept = out.find("ip daddr 1.1.1.1 accept").unwrap();
        let log = out.find("log prefix \"TTDENY t1-100 \"").unwrap();
        let drop = out.find("iifname \"tt-h\" drop").unwrap();
        assert!(accept < log && log < drop);
    }

    #[test]
    fn plan_is_stable_and_refuses_main() {
        let a = plan_for("trial-1").unwrap();
        let b = plan_for("trial-1").unwrap();
        assert_eq!(a.ns, b.ns);
        assert_eq!(a.host_if, b.host_if);
        assert!(a.host_if.len() <= 15 && a.trial_if.len() <= 15);
        assert!(plan_for("main").is_err());
        assert!(plan_for("bad name").is_err());
    }

    #[test]
    fn parses_icmp_and_tcp_log_lines() {
        let icmp = "[ 1563.2] TTDENY t1-100 IN=tth26 OUT=eth0 SRC=10.200.26.2 DST=8.8.8.8 LEN=84 PROTO=ICMP TYPE=8 CODE=0";
        let d = parse_denied_line(icmp, PFX).unwrap();
        assert_eq!(d.target(), "8.8.8.8/ICMP");

        let tcp = "[ 9.9] TTDENY t1-100 IN=tth26 OUT=eth0 SRC=10.200.26.2 DST=93.184.216.34 LEN=60 PROTO=TCP SPT=40000 DPT=443 SYN";
        let d = parse_denied_line(tcp, PFX).unwrap();
        assert_eq!(d.target(), "93.184.216.34:443/TCP");
    }

    #[test]
    fn ignores_other_labels_and_other_runs() {
        let other = "[ 1.0] TTDENY t1-999 IN=tth26 DST=8.8.8.8 PROTO=ICMP";
        assert!(parse_denied_line(other, PFX).is_none());
        assert!(parse_denied_line("unrelated kernel message", PFX).is_none());
    }

    #[test]
    fn extracts_label_from_nft_listing() {
        let listing = "chain gw_forward {\n  limit rate 50/second burst 100 packets log prefix \"TTDENY ttgw26-123 \"\n}";
        assert_eq!(extract_prefix(listing).unwrap(), "TTDENY ttgw26-123 ");
        assert!(extract_prefix("no logging here").is_none());
    }
}