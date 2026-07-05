import React from 'react';
import { Document, Page, View, Text, StyleSheet } from '@react-pdf/renderer';
import type { AnalysisReport, Finding, Severity } from '@/types';

const SEV_COLORS: Record<Severity, string> = {
  CRITICAL: '#FF3D5C',
  HIGH: '#FFAA33',
  MEDIUM: '#3D8EFF',
  LOW: '#00D98A',
  INFO: '#9D7AFF',
};

const SEV_LABELS: Record<Severity, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  INFO: 'Info',
};

const SEV_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const PAGE_SIZE = { width: 595.28, height: 841.89 };
const MARGIN = 50;
const CONTENT_WIDTH = PAGE_SIZE.width - MARGIN * 2;

const styles = StyleSheet.create({
  page: {
    padding: MARGIN,
    fontFamily: 'Helvetica',
    fontSize: 10,
    color: '#1a1a1a',
  },
  header: {
    position: 'absolute',
    top: 12,
    left: MARGIN,
    right: MARGIN,
    flexDirection: 'row',
    justifyContent: 'space-between',
    fontSize: 7,
    color: '#999',
    letterSpacing: 1,
    textTransform: 'uppercase' as const,
  },
  footer: {
    position: 'absolute',
    bottom: 18,
    left: MARGIN,
    right: MARGIN,
    flexDirection: 'row',
    justifyContent: 'space-between',
    fontSize: 7,
    color: '#999',
  },
  coverPage: {
    padding: MARGIN,
    fontFamily: 'Helvetica',
    justifyContent: 'center',
    alignItems: 'center',
  },
  coverDivider: {
    width: 60,
    height: 2,
    backgroundColor: '#556ADC',
    marginVertical: 24,
  },
  coverTitle: {
    fontSize: 28,
    fontWeight: 'bold',
    textAlign: 'center',
    letterSpacing: 1,
    color: '#111',
  },
  coverSubtitle: {
    fontSize: 12,
    color: '#556ADC',
    textAlign: 'center',
    marginTop: 4,
    letterSpacing: 2,
    textTransform: 'uppercase' as const,
  },
  coverMeta: {
    fontSize: 9,
    color: '#888',
    textAlign: 'center',
    marginTop: 2,
  },
  coverMetaHighlight: {
    fontSize: 9,
    color: '#556ADC',
    textAlign: 'center',
    marginTop: 2,
    fontWeight: 'bold',
  },
  brandLine: {
    fontSize: 11,
    color: '#888',
    textAlign: 'center',
    letterSpacing: 3,
    textTransform: 'uppercase' as const,
    marginTop: 20,
  },
  sectionHeading: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#111',
    marginBottom: 10,
    marginTop: 6,
    borderBottomWidth: 1.5,
    borderBottomColor: '#556ADC',
    paddingBottom: 4,
  },
  subHeading: {
    fontSize: 12,
    fontWeight: 'bold',
    color: '#222',
    marginTop: 14,
    marginBottom: 6,
  },
  subHeading2: {
    fontSize: 10,
    fontWeight: 'bold',
    color: '#333',
    marginTop: 10,
    marginBottom: 4,
  },
  bodyText: {
    fontSize: 10,
    color: '#444',
    lineHeight: 1.6,
    marginBottom: 4,
  },
  bodyBold: {
    fontSize: 10,
    fontWeight: 'bold',
    color: '#222',
  },
  kvRow: {
    flexDirection: 'row',
    paddingVertical: 3,
    borderBottomWidth: 0.5,
    borderBottomColor: '#f0f0f0',
    alignItems: 'center',
  },
  kvLabel: {
    width: 140,
    fontSize: 9,
    color: '#888',
    fontWeight: 'bold',
  },
  kvValue: {
    flex: 1,
    fontSize: 9,
    color: '#222',
    fontFamily: 'Courier',
  },
  scoreRow: {
    flexDirection: 'row',
    gap: 12,
    marginTop: 6,
    marginBottom: 8,
  },
  scoreBox: {
    flex: 1,
    padding: 10,
    borderWidth: 1,
    borderColor: '#e5e7eb',
  },
  scoreLabel: {
    fontSize: 8,
    color: '#888',
    textTransform: 'uppercase' as const,
    letterSpacing: 0.5,
    marginBottom: 4,
    fontWeight: 'bold',
  },
  scoreValue: {
    fontSize: 20,
    fontWeight: 'bold',
  },
  scoreBar: {
    height: 4,
    backgroundColor: '#f3f4f6',
    marginTop: 4,
    borderRadius: 2,
  },
  scoreFill: {
    height: '100%',
    borderRadius: 2,
  },
  sevBreakdown: {
    flexDirection: 'row',
    gap: 4,
    marginTop: 6,
    marginBottom: 8,
  },
  sevPill: {
    paddingHorizontal: 10,
    paddingVertical: 3,
    borderRadius: 2,
  },
  sevPillText: {
    fontSize: 9,
    fontWeight: 'bold',
    color: '#fff',
  },
  fileList: {
    marginTop: 4,
  },
  fileItem: {
    fontSize: 9,
    fontFamily: 'Courier',
    color: '#444',
    paddingVertical: 1,
    paddingLeft: 8,
  },
  summaryTable: {
    marginTop: 8,
    borderWidth: 1,
    borderColor: '#e5e7eb',
  },
  summaryRow: {
    flexDirection: 'row',
    borderBottomWidth: 0.5,
    borderBottomColor: '#f0f0f0',
    alignItems: 'center',
  },
  summaryRowEven: {
    backgroundColor: '#f9fafb',
  },
  summaryHeader: {
    flexDirection: 'row',
    backgroundColor: '#556ADC',
  },
  summaryCellId: {
    width: 50,
    paddingHorizontal: 8,
    paddingVertical: 5,
    fontSize: 9,
    fontWeight: 'bold',
    color: '#fff',
  },
  summaryCellSev: {
    width: 60,
    paddingHorizontal: 8,
    paddingVertical: 5,
    fontSize: 9,
  },
  summaryCellTitle: {
    flex: 1,
    paddingHorizontal: 8,
    paddingVertical: 5,
    fontSize: 9,
    fontWeight: 'bold',
    color: '#fff',
  },
  summaryCellCat: {
    width: 90,
    paddingHorizontal: 8,
    paddingVertical: 5,
    fontSize: 9,
    color: '#fff',
  },
  summaryCellIdData: {
    width: 50,
    paddingHorizontal: 8,
    paddingVertical: 5,
    fontSize: 9,
    fontFamily: 'Courier',
    color: '#555',
  },
  summaryCellSevData: {
    width: 60,
    paddingHorizontal: 8,
    paddingVertical: 5,
    fontSize: 9,
  },
  summaryCellTitleData: {
    flex: 1,
    paddingHorizontal: 8,
    paddingVertical: 5,
    fontSize: 9,
    color: '#333',
  },
  summaryCellCatData: {
    width: 90,
    paddingHorizontal: 8,
    paddingVertical: 5,
    fontSize: 8,
    color: '#888',
  },
  sevBadge: {
    paddingHorizontal: 6,
    paddingVertical: 2,
    borderRadius: 2,
    alignSelf: 'flex-start',
  },
  sevBadgeText: {
    fontSize: 8,
    fontWeight: 'bold',
    color: '#fff',
  },
  findingCard: {
    marginTop: 10,
    marginBottom: 6,
    borderWidth: 1,
    borderColor: '#e5e7eb',
  },
  findingHead: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 12,
    paddingVertical: 7,
    backgroundColor: '#f9fafb',
    borderBottomWidth: 1,
    borderBottomColor: '#e5e7eb',
  },
  findingId: {
    fontSize: 11,
    fontWeight: 'bold',
    fontFamily: 'Courier',
    color: '#556ADC',
  },
  findingTitle: {
    fontSize: 11,
    fontWeight: 'bold',
    color: '#222',
    paddingHorizontal: 12,
    paddingTop: 8,
    paddingBottom: 4,
  },
  findingBody: {
    paddingHorizontal: 12,
    paddingBottom: 10,
  },
  findLabel: {
    fontSize: 7,
    fontWeight: 'bold',
    color: '#888',
    textTransform: 'uppercase' as const,
    letterSpacing: 0.8,
    marginTop: 8,
    marginBottom: 3,
  },
  codeBlock: {
    backgroundColor: '#f9fafb',
    borderWidth: 0.5,
    borderColor: '#e5e7eb',
    padding: 8,
    marginVertical: 4,
    fontFamily: 'Courier',
    fontSize: 8,
    color: '#333',
  },
  codeRef: {
    fontSize: 9,
    fontFamily: 'Courier',
    color: '#555',
    marginBottom: 2,
  },
  pageBreak: {
    break: true,
  },
  spacer4: { height: 4 },
  spacer8: { height: 8 },
  spacer16: { height: 16 },
  spacer24: { height: 24 },
  coverTop: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  coverBottom: {
    alignItems: 'center',
    marginBottom: 30,
  },
  riskBadge: {
    paddingHorizontal: 16,
    paddingVertical: 6,
    borderRadius: 4,
    marginTop: 16,
  },
  riskText: {
    fontSize: 11,
    fontWeight: 'bold',
    color: '#fff',
    letterSpacing: 2,
    textTransform: 'uppercase' as const,
  },
});

function getSevBg(sev: Severity) {
  return SEV_COLORS[sev] || '#888';
}

function getRiskColor(risk: string): string {
  return risk === 'critical' ? '#FF3D5C' : risk === 'high' ? '#FFAA33' : risk === 'medium' ? '#3D8EFF' : '#00D98A';
}

function groupFindings(findings: Finding[]): Record<Severity, Finding[]> {
  const grouped: Record<string, Finding[]> = {};
  for (const f of findings) {
    if (!grouped[f.severity]) grouped[f.severity] = [];
    grouped[f.severity].push(f);
  }
  return grouped as Record<Severity, Finding[]>;
}

function formatLabel(s: string): string {
  return s.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

const CoverPage = ({ report }: { report: AnalysisReport }) => (
  <Page size="A4" style={styles.coverPage}>
    <View style={styles.coverTop}>
      <Text style={{ fontSize: 10, color: '#556ADC', letterSpacing: 4, textTransform: 'uppercase', marginBottom: 20 }}>ChainProbe</Text>
      <Text style={{ fontSize: 9, color: '#888', letterSpacing: 2, textTransform: 'uppercase', marginBottom: 40 }}>Security Audit Report</Text>
      <Text style={styles.coverTitle}>
        {report.profile.program_name.toUpperCase()}
      </Text>
      <View style={styles.coverDivider} />
      <Text style={styles.coverMeta}>
        {new Date(report.analyzed_at).toLocaleDateString('en-US', {
          year: 'numeric',
          month: 'long',
          day: 'numeric',
        })}
      </Text>
      <Text style={styles.coverMeta}>Report ID: {report.id}</Text>
      <View style={[styles.riskBadge, { backgroundColor: getRiskColor(report.summary.overall_risk) }]}>
        <Text style={styles.riskText}>{report.summary.overall_risk.toUpperCase()} RISK</Text>
      </View>
      <View style={{ flexDirection: 'row', gap: 12, marginTop: 16 }}>
        {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as Severity[]).map(sev => {
          const count = report.summary[sev.toLowerCase() as 'critical' | 'high' | 'medium' | 'low' | 'info'];
          if (!count) return null;
          return (
            <View key={sev} style={[styles.sevPill, { backgroundColor: SEV_COLORS[sev] }]}>
              <Text style={styles.sevPillText}>{count} {SEV_LABELS[sev]}</Text>
            </View>
          );
        })}
      </View>
      <Text style={[styles.coverMeta, { marginTop: 12 }]}>
        Security Score: {report.summary.security_score}/100
      </Text>
    </View>
    <View style={styles.coverBottom}>
      <Text style={styles.brandLine}>chainprobe</Text>
      <Text style={[styles.coverMeta, { marginTop: 4 }]}>
        Automated Solana Security Analysis
      </Text>
    </View>
  </Page>
);

const AboutSection = () => (
  <View wrap={false}>
    <Text style={styles.sectionHeading}>About ChainProbe</Text>
    <Text style={styles.bodyText}>
      ChainProbe is an automated Solana security analyzer that performs static analysis
      on Anchor and Pinocchio-based Solana programs. It combines pattern matching, data-flow tracking,
      and invariant analysis to identify potential vulnerabilities across multiple
      categories including account validation, arithmetic overflows, signer authority,
      PDA seed collisions, reentrancy, and access control issues.
    </Text>
    <Text style={styles.subHeading}>Disclaimer</Text>
    <Text style={styles.bodyText}>
      Audits are a time, resource, and expertise-bound effort where automated analysis
      evaluates smart contracts using a combination of static analysis and heuristic
      techniques to identify as many vulnerabilities as possible. This audit can reveal
      the presence of vulnerabilities but cannot guarantee their absence. The analysis
      is automated and should be complemented by manual review. While ChainProbe
      strives to deliver thorough coverage, 100% security can never be guaranteed.
    </Text>
  </View>
);

const SystemOverviewSection = ({ report }: { report: AnalysisReport }) => (
  <View wrap={false}>
    <Text style={styles.sectionHeading}>System Overview</Text>
    <View style={styles.kvRow}>
      <Text style={styles.kvLabel}>Program</Text>
      <Text style={styles.kvValue}>{report.profile.program_name}</Text>
    </View>
    <View style={styles.kvRow}>
      <Text style={styles.kvLabel}>Framework</Text>
      <Text style={[styles.kvValue, { fontFamily: 'Helvetica' }]}>{report.profile.framework || 'Unknown'}</Text>
    </View>
    {report.profile.anchor_version !== 'unknown' && (
      <View style={styles.kvRow}>
        <Text style={styles.kvLabel}>Version</Text>
        <Text style={[styles.kvValue, { fontFamily: 'Helvetica' }]}>{report.profile.anchor_version}</Text>
      </View>
    )}
    <View style={styles.kvRow}>
      <Text style={styles.kvLabel}>Complexity</Text>
      <Text style={[styles.kvValue, { fontFamily: 'Helvetica' }]}>{report.profile.complexity}</Text>
    </View>
    <View style={styles.kvRow}>
      <Text style={styles.kvLabel}>Total Lines</Text>
      <Text style={styles.kvValue}>{report.profile.total_lines.toLocaleString()}</Text>
    </View>
    <View style={styles.kvRow}>
      <Text style={styles.kvLabel}>Files Analyzed</Text>
      <Text style={styles.kvValue}>{report.profile.files_analyzed}</Text>
    </View>
    <View style={styles.kvRow}>
      <Text style={styles.kvLabel}>Instructions</Text>
      <Text style={styles.kvValue}>{report.profile.instructions_count}</Text>
    </View>
    <View style={styles.kvRow}>
      <Text style={styles.kvLabel}>Account Structs</Text>
      <Text style={styles.kvValue}>{report.profile.account_structs_count}</Text>
    </View>
    <View style={styles.kvRow}>
      <Text style={styles.kvLabel}>CPI Calls</Text>
      <Text style={styles.kvValue}>{report.profile.cpi_calls_count}</Text>
    </View>
    <View style={styles.kvRow}>
      <Text style={styles.kvLabel}>PDA Derivation</Text>
      <Text style={styles.kvValue}>{report.profile.pda_count}</Text>
    </View>
    <View style={styles.kvRow}>
      <Text style={styles.kvLabel}>Signer Checks</Text>
      <Text style={styles.kvValue}>{report.profile.signer_count}</Text>
    </View>
    {report.profile.overflow_checks_enabled !== undefined && (
      <View style={styles.kvRow}>
        <Text style={styles.kvLabel}>Overflow Checks</Text>
        <Text style={[styles.kvValue, { fontFamily: 'Helvetica' }]}>{report.profile.overflow_checks_enabled ? 'Enabled' : 'Disabled'}</Text>
      </View>
    )}
  </View>
);

const PerformanceSection = ({ report }: { report: AnalysisReport }) => (
  <View wrap={false}>
    <Text style={styles.sectionHeading}>Performance & Compute</Text>
    <View style={styles.scoreRow}>
      <View style={styles.scoreBox}>
        <Text style={styles.scoreLabel}>Performance Score</Text>
        <Text style={[styles.scoreValue, { color: report.profile.performance_score >= 70 ? '#00D98A' : report.profile.performance_score >= 40 ? '#FFAA33' : '#FF3D5C' }]}>
          {report.profile.performance_score}/100
        </Text>
        <View style={styles.scoreBar}>
          <View style={[styles.scoreFill, { width: `${report.profile.performance_score}%`, backgroundColor: report.profile.performance_score >= 70 ? '#00D98A' : report.profile.performance_score >= 40 ? '#FFAA33' : '#FF3D5C' }]} />
        </View>
      </View>
      <View style={styles.scoreBox}>
        <Text style={styles.scoreLabel}>Estimated CU</Text>
        <Text style={[styles.scoreValue, { color: '#FF8717' }]}>
          {report.profile.estimated_compute_units.toLocaleString()}
        </Text>
        <Text style={{ fontSize: 8, color: '#888', marginTop: 4 }}>total across all instructions</Text>
      </View>
    </View>
    {report.profile.per_instruction_cu && report.profile.per_instruction_cu.length > 0 && (
      <>
        <Text style={styles.subHeading2}>Per-Instruction CU Breakdown</Text>
        {report.profile.per_instruction_cu.map((est, i) => (
          <View key={i} style={styles.kvRow}>
            <Text style={[styles.kvLabel, { fontFamily: 'Courier', fontSize: 9 }]}>{est.name}</Text>
            <Text style={[styles.kvValue, { fontSize: 9, color: '#888' }]}>
              {est.total_cu.toLocaleString()} CU · CPI {est.cpi_cu} · Compute {est.compute_cu} · Acct {est.account_cu}
            </Text>
          </View>
        ))}
      </>
    )}
    {report.profile.top_cu_consumers && report.profile.top_cu_consumers.length > 0 && (
      <>
        <Text style={styles.subHeading2}>Top CU Consumers</Text>
        {report.profile.top_cu_consumers.map((c, i) => (
          <Text key={i} style={[styles.bodyText, { fontSize: 9, marginBottom: 2 }]}>• {c}</Text>
        ))}
      </>
    )}
    {report.performance_issues && report.performance_issues.length > 0 && (
      <>
        <Text style={styles.subHeading2}>Performance Findings ({report.performance_issues.length})</Text>
        {report.performance_issues.map((p, i) => (
          <View key={i} style={{ marginBottom: 6 }}>
            <Text style={[styles.bodyText, { fontWeight: 'bold', fontSize: 9 }]}>
              [{p.severity}] {p.title}
            </Text>
            <Text style={[styles.bodyText, { fontSize: 8, color: '#666', marginTop: 2 }]}>
              {p.description.substring(0, 200)}
            </Text>
            <Text style={[styles.bodyText, { fontSize: 8, color: '#556ADC', marginTop: 2 }]}>
              ~{p.cu_impact.toLocaleString()} CU · {p.file}{p.line ? `:${p.line}` : ''}
            </Text>
          </View>
        ))}
      </>
    )}
  </View>
);

const SecurityPostureSection = ({ report }: { report: AnalysisReport }) => (
  <View wrap={false}>
    <Text style={styles.sectionHeading}>Security Posture</Text>
    <View style={styles.scoreRow}>
      <View style={styles.scoreBox}>
        <Text style={styles.scoreLabel}>Security Score</Text>
        <Text style={[styles.scoreValue, { color: report.summary.security_score >= 70 ? '#00D98A' : report.summary.security_score >= 40 ? '#FFAA33' : '#FF3D5C' }]}>
          {report.summary.security_score}/100
        </Text>
        <View style={styles.scoreBar}>
          <View style={[styles.scoreFill, { width: `${report.summary.security_score}%`, backgroundColor: report.summary.security_score >= 70 ? '#00D98A' : report.summary.security_score >= 40 ? '#FFAA33' : '#FF3D5C' }]} />
        </View>
      </View>
      <View style={styles.scoreBox}>
        <Text style={styles.scoreLabel}>Attack Surface</Text>
        <Text style={[styles.scoreValue, { color: report.summary.attack_surface_score <= 30 ? '#00D98A' : report.summary.attack_surface_score <= 60 ? '#FFAA33' : '#FF3D5C' }]}>
          {report.summary.attack_surface_score}/100
        </Text>
        <View style={styles.scoreBar}>
          <View style={[styles.scoreFill, { width: `${report.summary.attack_surface_score}%`, backgroundColor: report.summary.attack_surface_score <= 30 ? '#00D98A' : report.summary.attack_surface_score <= 60 ? '#FFAA33' : '#FF3D5C' }]} />
        </View>
      </View>
      <View style={styles.scoreBox}>
        <Text style={styles.scoreLabel}>Hardening</Text>
        <Text style={[styles.scoreValue, { color: report.summary.hardening_score >= 70 ? '#00D98A' : report.summary.hardening_score >= 40 ? '#FFAA33' : '#FF3D5C' }]}>
          {report.summary.hardening_score}/100
        </Text>
        <View style={styles.scoreBar}>
          <View style={[styles.scoreFill, { width: `${report.summary.hardening_score}%`, backgroundColor: report.summary.hardening_score >= 70 ? '#00D98A' : report.summary.hardening_score >= 40 ? '#FFAA33' : '#FF3D5C' }]} />
        </View>
      </View>
    </View>
    <View style={[styles.kvRow, { borderBottomWidth: 0 }]}>
      <Text style={styles.kvLabel}>Overall Risk</Text>
      <Text style={[styles.kvValue, { fontFamily: 'Helvetica', fontWeight: 'bold', color: getRiskColor(report.summary.overall_risk) }]}>
        {report.summary.overall_risk.toUpperCase()}
      </Text>
    </View>
    <View style={styles.sevBreakdown}>
      {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as Severity[]).map(sev => {
        const count = report.summary[sev.toLowerCase() as 'critical' | 'high' | 'medium' | 'low' | 'info'];
        if (!count) return null;
        return (
          <View key={sev} style={[styles.sevPill, { backgroundColor: SEV_COLORS[sev] }]}>
            <Text style={styles.sevPillText}>{count} {SEV_LABELS[sev]}</Text>
          </View>
        );
      })}
      <View style={[styles.sevPill, { backgroundColor: '#444' }]}>
        <Text style={styles.sevPillText}>{report.summary.total} Total</Text>
      </View>
    </View>
    {Object.keys(report.category_summary).length > 0 && (
      <>
        <Text style={styles.subHeading2}>Category Breakdown</Text>
        {Object.entries(report.category_summary).map(([cat, cs]) => (
          <View key={cat} style={styles.kvRow}>
            <Text style={styles.kvLabel}>{formatLabel(cat)}</Text>
            <Text style={[styles.kvValue, { fontFamily: 'Helvetica', color: getRiskColor(cs.max_severity.toLowerCase()) }]}>
              {cs.count} finding{cs.count !== 1 ? 's' : ''} · max {cs.max_severity}
            </Text>
          </View>
        ))}
      </>
    )}
  </View>
);

const TechnicalOverviewSection = ({ report }: { report: AnalysisReport }) => (
  <View wrap={false}>
    <Text style={styles.sectionHeading}>Technical Overview</Text>
    {report.profile.instructions.length > 0 && (
      <>
        <Text style={styles.subHeading2}>Instructions</Text>
        {report.profile.instructions.map((ins, i) => (
          <View key={i} style={styles.kvRow}>
            <Text style={[styles.kvLabel, { fontFamily: 'Courier', fontSize: 9 }]}>
              {ins.name}
            </Text>
            <Text style={[styles.kvValue, { fontSize: 9, color: '#888' }]}>
              {ins.file}:{ins.line}
            </Text>
          </View>
        ))}
      </>
    )}
    {report.profile.framework_patterns.length > 0 && (
      <>
        <Text style={styles.subHeading2}>Framework Patterns</Text>
        <Text style={styles.bodyText}>
          {report.profile.framework_patterns.join(', ')}
        </Text>
      </>
    )}
    {report.summary.taint_flow_count > 0 && (
      <Text style={styles.bodyText}>
        <Text style={styles.bodyBold}>Taint Flows: </Text>
        {report.summary.taint_flow_count} attacker-controlled data flow{report.summary.taint_flow_count !== 1 ? 's' : ''} identified
      </Text>
    )}
    {report.summary.invariant_count > 0 && (
      <Text style={styles.bodyText}>
        <Text style={styles.bodyBold}>Invariants: </Text>
        {report.summary.invariant_count} checked ({report.summary.bypassable_invariant_count} bypassable)
      </Text>
    )}
    {report.summary.chain_count > 0 && (
      <Text style={styles.bodyText}>
        <Text style={styles.bodyBold}>Exploit Chains: </Text>
        {report.summary.chain_count} multi-step chain{report.summary.chain_count !== 1 ? 's' : ''}
      </Text>
    )}
    {report.summary.token_flow_anomaly_count > 0 && (
      <Text style={styles.bodyText}>
        <Text style={styles.bodyBold}>Token Flow Anomalies: </Text>
        {report.summary.token_flow_anomaly_count}
      </Text>
    )}
    {report.summary.broken_permission_count > 0 && (
      <Text style={styles.bodyText}>
        <Text style={styles.bodyBold}>Broken Permissions: </Text>
        {report.summary.broken_permission_count}
      </Text>
    )}
    {report.summary.known_vuln_count > 0 && (
      <Text style={styles.bodyText}>
        <Text style={styles.bodyBold}>Known Advisories: </Text>
        {report.summary.known_vuln_count}
      </Text>
    )}
  </View>
);

const ScopeSection = ({ report }: { report: AnalysisReport }) => (
  <View wrap={false}>
    <Text style={styles.sectionHeading}>Scope</Text>
    <View style={styles.fileList}>
      {report.profile.module_tree.length > 0 ? (
        report.profile.module_tree.map((f, i) => (
          <Text key={i} style={styles.fileItem}>src/{f}</Text>
        ))
      ) : (
        <Text style={styles.bodyText}>
          {report.profile.files_analyzed} files analyzed
        </Text>
      )}
    </View>
  </View>
);

const SevBadge = ({ sev }: { sev: Severity }) => (
  <View style={[styles.sevBadge, { backgroundColor: getSevBg(sev) }]}>
    <Text style={styles.sevBadgeText}>{SEV_LABELS[sev]}</Text>
  </View>
);

const FindingsSummarySection = ({ findings }: { findings: Finding[] }) => (
  <View wrap={false}>
    <Text style={styles.sectionHeading}>Findings Summary</Text>
    {SEV_ORDER.map(sev => {
      const cnt = findings.filter(f => f.severity === sev).length;
      if (!cnt) return null;
      return (
        <Text key={sev} style={styles.bodyText}>
          <Text style={{ color: SEV_COLORS[sev], fontWeight: 'bold' }}>{cnt} {SEV_LABELS[sev]}</Text>
        </Text>
      );
    })}
    <View style={styles.summaryTable}>
      <View style={styles.summaryHeader}>
        <Text style={styles.summaryCellId}>ID</Text>
        <Text style={styles.summaryCellSev}>Severity</Text>
        <Text style={styles.summaryCellTitle}>Title</Text>
        <Text style={styles.summaryCellCat}>Category</Text>
      </View>
      {findings.map((f, i) => (
        <View key={f.id} style={i % 2 === 1 ? [styles.summaryRow, styles.summaryRowEven] : styles.summaryRow}>
          <Text style={styles.summaryCellIdData}>{f.id}</Text>
          <View style={styles.summaryCellSevData}>
            <SevBadge sev={f.severity} />
          </View>
          <Text style={styles.summaryCellTitleData}>{f.title}</Text>
          <Text style={styles.summaryCellCatData}>{formatLabel(f.category)}</Text>
        </View>
      ))}
    </View>
  </View>
);

const DetailedFindingsSection = ({ findings }: { findings: Finding[] }) => {
  const grouped = groupFindings(findings);

  return (
    <View>
      <Text style={styles.sectionHeading}>Findings</Text>
      {SEV_ORDER.map(sev => {
        const sevFindings = grouped[sev];
        if (!sevFindings || sevFindings.length === 0) return null;
        return (
          <View key={sev}>
            <Text
              style={[
                styles.subHeading,
                { color: SEV_COLORS[sev], borderBottomWidth: 1, borderBottomColor: SEV_COLORS[sev], paddingBottom: 2, marginTop: 18 },
              ]}
            >
              {SEV_LABELS[sev]} Severity
            </Text>
            {sevFindings.map(f => (
              <View key={f.id} style={styles.findingCard} wrap={false}>
                <View style={styles.findingHead}>
                  <Text style={styles.findingId}>{f.id}</Text>
                  <SevBadge sev={f.severity} />
                </View>
                <Text style={styles.findingTitle}>{f.title}</Text>
                <View style={styles.findingBody}>
                  <View style={styles.kvRow}>
                    <Text style={styles.kvLabel}>File</Text>
                    <Text style={[styles.kvValue, { fontSize: 9 }]}>
                      {f.file}{f.line ? `:${f.line}` : ''}
                    </Text>
                  </View>
                  <View style={styles.kvRow}>
                    <Text style={styles.kvLabel}>Function</Text>
                    <Text style={[styles.kvValue, { fontSize: 9 }]}>
                      {f.function}
                    </Text>
                  </View>
                  <View style={styles.kvRow}>
                    <Text style={styles.kvLabel}>Category</Text>
                    <Text style={[styles.kvValue, { fontFamily: 'Helvetica' }]}>{formatLabel(f.category)}</Text>
                  </View>
                  {f.cwe && (
                    <View style={styles.kvRow}>
                      <Text style={styles.kvLabel}>CWE</Text>
                      <Text style={[styles.kvValue, { fontSize: 9 }]}>
                        {f.cwe}
                      </Text>
                    </View>
                  )}
                  {f.exploitability !== undefined && (
                    <View style={styles.kvRow}>
                      <Text style={styles.kvLabel}>Exploitability</Text>
                      <Text style={styles.kvValue}>{f.exploitability}/100</Text>
                    </View>
                  )}
                  <Text style={styles.findLabel}>Description</Text>
                  <Text style={styles.bodyText}>{f.description}</Text>
                  {f.snippet && (
                    <>
                      <Text style={styles.findLabel}>Code Reference</Text>
                      <Text style={styles.codeRef}>{f.file}:{f.line}</Text>
                      <View style={styles.codeBlock}>
                        <Text>{f.snippet}</Text>
                      </View>
                    </>
                  )}
                  {f.confirmed_by_taint && f.confirmed_by_taint.length > 0 && (
                    <>
                      <Text style={styles.findLabel}>Confirmed by Taint</Text>
                      <Text style={styles.bodyText}>{f.confirmed_by_taint.join(', ')}</Text>
                    </>
                  )}
                  <Text style={styles.findLabel}>Recommendation</Text>
                  <Text style={styles.bodyText}>{f.recommendation}</Text>
                  {f.anchor_fix && (
                    <>
                      <Text style={styles.findLabel}>Anchor Fix</Text>
                      <View style={styles.codeBlock}>
                        <Text>{f.anchor_fix}</Text>
                      </View>
                    </>
                  )}
                </View>
              </View>
            ))}
          </View>
        );
      })}
    </View>
  );
};

const ReportHeader = ({ report }: { report: AnalysisReport }) => (
  <Text style={styles.header}>
    <Text>{report.profile.program_name} · ChainProbe Security Audit</Text>
    <Text>{new Date(report.analyzed_at).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })}</Text>
  </Text>
);

const ReportFooter = () => (
  <Text style={styles.footer}>
    <Text>ChainProbe — Confidential</Text>
    <Text render={({ pageNumber, totalPages }) => `${pageNumber} / ${totalPages}`} />
  </Text>
);

interface PdfReportProps {
  report: AnalysisReport;
}

export const PdfReport = ({ report }: PdfReportProps) => (
  <Document
    title={`${report.profile.program_name} - Security Audit`}
    author="ChainProbe"
    subject="Solana Security Audit Report"
  >
    <CoverPage report={report} />
    <Page size="A4" style={styles.page}>
      <ReportHeader report={report} />
      <ReportFooter />
      <AboutSection />
      <View style={styles.spacer16} />
      <SystemOverviewSection report={report} />
    </Page>
    <Page size="A4" style={styles.page}>
      <ReportHeader report={report} />
      <ReportFooter />
      <SecurityPostureSection report={report} />
      <View style={styles.spacer16} />
      <PerformanceSection report={report} />
      <View style={styles.spacer16} />
      <TechnicalOverviewSection report={report} />
    </Page>
    <Page size="A4" style={styles.page}>
      <ReportHeader report={report} />
      <ReportFooter />
      {report.profile.module_tree.length > 0 && (
        <>
          <ScopeSection report={report} />
          <View style={styles.spacer16} />
        </>
      )}
      <FindingsSummarySection findings={report.findings} />
    </Page>
    {report.findings.length > 0 && (
      <Page size="A4" style={styles.page}>
        <ReportHeader report={report} />
        <ReportFooter />
        <DetailedFindingsSection findings={report.findings} />
      </Page>
    )}
  </Document>
);
