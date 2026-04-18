// backend/src/vuln_db.rs
// Static database of known vulnerabilities in Anchor + SPL Token versions.
// No network calls. Update by adding entries to ANCHOR_ADVISORIES.
// Sources: https://github.com/coral-xyz/anchor/security/advisories

use crate::types::{KnownVuln, Severity};

pub fn check_version(anchor_version: &str) -> Vec<KnownVuln> {
    if anchor_version == "unknown" || anchor_version.is_empty() {
        return vec![];
    }

    let av = parse_semver(anchor_version);
    let mut vulns = vec![];

    for entry in ADVISORIES {
        if version_in_range(av, entry.affected_range) {
            vulns.push(KnownVuln {
                cve_id: entry.cve_id.map(|s| s.to_string()),
                advisory_id: entry.advisory_id.to_string(),
                affected_package: entry.package.to_string(),
                affected_versions: entry.affected_range.to_string(),
                fixed_in: entry.fixed_in.map(|s| s.to_string()),
                severity: entry.severity.clone(),
                title: entry.title.to_string(),
                description: entry.description.to_string(),
                url: entry.url.to_string(),
            });
        }
    }

    // Sort: Critical first
    vulns.sort_by(|a, b| a.severity.cmp(&b.severity));
    vulns
}

//   Internal advisory record                          

struct Advisory {
    cve_id: Option<&'static str>,
    advisory_id: &'static str,
    package: &'static str,
    affected_range: &'static str,
    fixed_in: Option<&'static str>,
    severity: Severity,
    title: &'static str,
    description: &'static str,
    url: &'static str,
}

//   Advisory database                             ─

static ADVISORIES: &[Advisory] = &[
    Advisory {
        cve_id: None,
        advisory_id: "GHSA-gxvv-x4p2-rppp",
        package: "anchor-lang",
        affected_range: "<0.29.0",
        fixed_in: Some("0.29.0"),
        severity: Severity::High,
        title: "Account confusion via type cosplay (anchor-lang <0.29.0)",
        description: "Versions prior to 0.29.0 did not enforce account discriminators \
            consistently, allowing type cosplay attacks where an attacker substitutes \
            an account of a different type with a matching byte layout.",
        url: "https://github.com/coral-xyz/anchor/security/advisories/GHSA-gxvv-x4p2-rppp",
    },
    Advisory {
        cve_id: None,
        advisory_id: "ANCHOR-IDL-AUTH-2023",
        package: "anchor-lang",
        affected_range: "<0.28.0",
        fixed_in: Some("0.28.0"),
        severity: Severity::Medium,
        title: "IDL account authority not validated (anchor-lang <0.28.0)",
        description: "In versions prior to 0.28.0, the IDL account authority was not validated \
            during IDL upgrades, potentially allowing unauthorized IDL modifications by \
            any account that could satisfy the IDL account constraint.",
        url: "https://github.com/coral-xyz/anchor/blob/master/CHANGELOG.md",
    },
    Advisory {
        cve_id: None,
        advisory_id: "ANCHOR-INIT-IF-NEEDED-2023",
        package: "anchor-lang",
        affected_range: ">=0.20.0,<0.30.0",
        fixed_in: Some("0.30.0"),
        severity: Severity::High,
        title: "init_if_needed reinitialization attack (anchor-lang >=0.20.0,<0.30.0)",
        description: "Programs using init_if_needed without explicit reinitialization guards \
            are vulnerable. An attacker can pre-create an account with forged data; \
            when the victim calls init_if_needed, Anchor skips initialization and accepts \
            the attacker's pre-existing account unchanged.",
        url: "https://docs.anchor-lang.com/docs/the-program-module#init_if_needed",
    },
    Advisory {
        cve_id: None,
        advisory_id: "ANCHOR-PDA-BUMP-2022",
        package: "anchor-lang",
        affected_range: "<0.26.0",
        fixed_in: Some("0.26.0"),
        severity: Severity::High,
        title: "Non-canonical PDA bump not rejected (anchor-lang <0.26.0)",
        description: "Versions prior to 0.26.0 did not enforce canonical bump validation \
            by default in account constraints. Programs could accept non-canonical bumps, \
            potentially allowing different PDA addresses to be derived with the same seeds.",
        url: "https://github.com/coral-xyz/anchor/blob/master/CHANGELOG.md",
    },
    Advisory {
        cve_id: None,
        advisory_id: "ANCHOR-CLOSE-2022",
        package: "anchor-lang",
        affected_range: "<0.26.0",
        fixed_in: Some("0.26.0"),
        severity: Severity::Medium,
        title: "Account close does not zero data before lamport transfer (anchor-lang <0.26.0)",
        description: "In versions prior to 0.26.0, the close constraint did not zero account \
            data before transferring lamports. This allowed a revival attack where an attacker \
            refunds lamports to a closed account before the transaction finalizes, \
            leaving stale data accessible.",
        url: "https://github.com/coral-xyz/anchor/security/advisories",
    },
    Advisory {
        cve_id: Some("CVE-2022-23534"),
        advisory_id: "SPL-TOKEN-2022-FREEZE",
        package: "spl-token",
        affected_range: "<0.26.0",
        fixed_in: Some("0.26.0"),
        severity: Severity::Critical,
        title: "SPL Token freeze authority bypass in programs bundled with anchor <0.26.0",
        description: "Programs built with anchor <0.26.0 bundle spl-token <3.5.0, \
            which contains a freeze authority bypass under specific multi-instruction \
            transaction conditions.",
        url: "https://github.com/solana-labs/solana-program-library/security/advisories",
    },
];

//   Semver parsing                               ─

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct SemVer(u32, u32, u32);

fn parse_semver(s: &str) -> SemVer {
    let s = s.trim().trim_start_matches('v');
    let parts: Vec<u32> = s.split('.')
        .take(3)
        .map(|p| p.split('-').next().unwrap_or("0").parse().unwrap_or(0))
        .collect();
    SemVer(
        parts.first().copied().unwrap_or(0),
        parts.get(1).copied().unwrap_or(0),
        parts.get(2).copied().unwrap_or(0),
    )
}

fn version_in_range(v: SemVer, range: &str) -> bool {
    range.split(',').all(|part| {
        let part = part.trim();
        if part.starts_with(">=") {
            v >= parse_semver(&part[2..])
        } else if part.starts_with("<=") {
            v <= parse_semver(&part[2..])
        } else if part.starts_with('>') {
            v > parse_semver(&part[1..])
        } else if part.starts_with('<') {
            v < parse_semver(&part[1..])
        } else if let Some(stripped) = part.strip_prefix('=') {
            v == parse_semver(stripped)
        } else {
            true
        }
    })
}

//   Tests                                   ─

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_versions() {
        assert_eq!(parse_semver("0.29.0"), SemVer(0, 29, 0));
        assert_eq!(parse_semver("v0.28.1-rc1"), SemVer(0, 28, 1));
        assert_eq!(parse_semver("0.32.1"), SemVer(0, 32, 1));
    }

    #[test]
    fn range_lt() {
        assert!(version_in_range(SemVer(0, 28, 0), "<0.29.0"));
        assert!(!version_in_range(SemVer(0, 29, 0), "<0.29.0"));
        assert!(!version_in_range(SemVer(0, 30, 0), "<0.29.0"));
    }

    #[test]
    fn range_compound() {
        assert!(version_in_range(SemVer(0, 27, 0), ">=0.20.0,<0.30.0"));
        assert!(!version_in_range(SemVer(0, 19, 0), ">=0.20.0,<0.30.0"));
        assert!(!version_in_range(SemVer(0, 30, 0), ">=0.20.0,<0.30.0"));
    }

    #[test]
    fn known_vulns_for_028() {
        let v = check_version("0.28.0");
        // Should hit: type cosplay (<0.29), init_if_needed (>=0.20,<0.30),
        //             pda bump (<0.26 — NO, 0.28 >= 0.26), close (<0.26 — NO)
        assert!(v.iter().any(|x| x.advisory_id == "GHSA-gxvv-x4p2-rppp"));
        assert!(v.iter().any(|x| x.advisory_id == "ANCHOR-INIT-IF-NEEDED-2023"));
        assert!(!v.iter().any(|x| x.advisory_id == "ANCHOR-PDA-BUMP-2022"));
    }

    #[test]
    fn no_vulns_for_current() {
        let v = check_version("0.32.1");
        // 0.32.1 should not hit any advisories
        assert!(v.is_empty(), "unexpected vulns: {:?}", v.iter().map(|x| &x.advisory_id).collect::<Vec<_>>());
    }

    #[test]
    fn unknown_version_returns_empty() {
        assert!(check_version("unknown").is_empty());
        assert!(check_version("").is_empty());
    }
}
