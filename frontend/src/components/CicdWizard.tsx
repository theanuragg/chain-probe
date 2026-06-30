"use client";
import React, { useState, useMemo } from 'react';
import { C } from '@/lib/constants';
import { Sb } from '@/lib/styles';
import { AnalysisReport } from '@/types';

interface CicdWizardProps {
  report: AnalysisReport;
  onClose: () => void;
}

type CiPlatform = 'github' | 'gitlab';
type FailSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM';

export function CicdWizard({ report, onClose }: CicdWizardProps) {
  const [platform, setPlatform] = useState<CiPlatform>('github');
  const [failSeverity, setFailSeverity] = useState<FailSeverity>('HIGH');
  const [sarifUpload, setSarifUpload] = useState(true);
  const [prComment, setPrComment] = useState(true);
  const [failOnNew, setFailOnNew] = useState(true);
  const [copied, setCopied] = useState(false);

  const yaml = useMemo(() => {
    return platform === 'github' ? generateGithubYaml(failSeverity, sarifUpload, prComment, failOnNew) : generateGitlabYaml(failSeverity, sarifUpload, prComment, failOnNew);
  }, [platform, failSeverity, sarifUpload, prComment, failOnNew]);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(yaml);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {}
  };

  const handleDownload = () => {
    const ext = platform === 'github' ? 'yml' : 'yml';
    const name = platform === 'github' ? 'chainprobe-analysis.yml' : '.gitlab-ci.yml';
    const b = new Blob([yaml], { type: 'text/yaml' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(b);
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 500,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'rgba(0,0,0,0.5)', backdropFilter: 'blur(4px)',
      fontFamily: "'Inter',sans-serif",
    }} onClick={onClose}>
      <div style={{
        background: '#fff', borderRadius: 24, width: '90%', maxWidth: 800,
        maxHeight: '90vh', overflow: 'auto', boxShadow: '0 20px 60px rgba(0,0,0,0.3)',
      }} onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '24px 28px', borderBottom: `1px solid ${C.bdr}`,
        }}>
          <div>
            <h3 style={{ fontFamily: "'Playfair Display',serif", fontSize: 22, fontWeight: 700, color: C.txt, margin: 0 }}>
              CI/CD Integration
            </h3>
            <p style={{ fontSize: 13, color: C.t3, margin: '4px 0 0' }}>
              Run ChainProbe automatically on every push and pull request
            </p>
          </div>
          <button style={{
            ...Sb.exBtn, fontSize: 18, lineHeight: 1, padding: '4px 12px',
          }} onClick={onClose}>✕</button>
        </div>

        <div style={{ padding: '24px 28px', display: 'flex', gap: 32 }}>
          {/* Config Panel */}
          <div style={{ flex: '0 0 260px' }}>
            {/* Platform Toggle */}
            <div style={{ marginBottom: 24 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: C.t3, textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 10 }}>Platform</div>
              <div style={{ display: 'flex', gap: 8 }}>
                {(['github', 'gitlab'] as CiPlatform[]).map(p => (
                  <button key={p} style={{
                    flex: 1, padding: '10px 0', borderRadius: 10, border: `1.5px solid ${platform === p ? C.cyan : C.bdr}`,
                    background: platform === p ? `${C.cyan}08` : '#fff', cursor: 'pointer', fontSize: 13, fontWeight: 600,
                    color: platform === p ? C.cyan : C.t3, fontFamily: "'Inter',sans-serif",
                    transition: 'all .2s',
                  }} onClick={() => setPlatform(p)}>
                    {p === 'github' ? 'GitHub Actions' : 'GitLab CI'}
                  </button>
                ))}
              </div>
            </div>

            {/* Fail on */}
            <div style={{ marginBottom: 24 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: C.t3, textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 10 }}>Fail on severity</div>
              {(['CRITICAL', 'HIGH', 'MEDIUM'] as FailSeverity[]).map(s => (
                <label key={s} style={{
                  display: 'flex', alignItems: 'center', gap: 8, padding: '6px 0', cursor: 'pointer', fontSize: 13, color: C.t2,
                }}>
                  <input type="radio" name="fail-sev" checked={failSeverity === s} onChange={() => setFailSeverity(s)} style={{ accentColor: C.cyan }} />
                  {s}
                </label>
              ))}
            </div>

            {/* Toggles */}
            <div style={{ marginBottom: 24 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: C.t3, textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 10 }}>Options</div>
              {[
                { key: 'sarif', label: 'Upload SARIF artifact', value: sarifUpload, set: setSarifUpload },
                { key: 'comment', label: 'Comment PR with results', value: prComment, set: setPrComment },
                { key: 'fail-new', label: 'Fail on new findings vs baseline', value: failOnNew, set: setFailOnNew },
              ].map(opt => (
                <label key={opt.key} style={{
                  display: 'flex', alignItems: 'center', gap: 8, padding: '6px 0', cursor: 'pointer', fontSize: 13, color: C.t2,
                }}>
                  <input type="checkbox" checked={opt.value} onChange={e => opt.set(e.target.checked)} style={{ accentColor: C.cyan }} />
                  {opt.label}
                </label>
              ))}
            </div>
          </div>

          {/* YAML Preview */}
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10,
            }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: C.t3, textTransform: 'uppercase', letterSpacing: '.08em' }}>
                {platform === 'github' ? '.github/workflows/chainprobe-analysis.yml' : '.gitlab-ci.yml'}
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button style={{ ...Sb.exBtn, fontSize: 12 }} onClick={handleDownload}>Download</button>
                <button style={{
                  ...Sb.exBtn, fontSize: 12,
                  background: copied ? C.grn : '#fff', color: copied ? '#fff' : C.t3, borderColor: copied ? C.grn : C.bdr,
                }} onClick={handleCopy}>{copied ? 'Copied!' : 'Copy'}</button>
              </div>
            </div>
            <pre style={{
              background: '#0A101F', color: '#E4E7ED', borderRadius: 16, padding: 20,
              fontSize: 12, lineHeight: 1.6, fontFamily: "'JetBrains Mono','Fira Code',monospace",
              overflow: 'auto', maxHeight: 480, margin: 0, whiteSpace: 'pre',
            }}>{yaml}</pre>
          </div>
        </div>
      </div>
    </div>
  );
}

function generateGithubYaml(failSeverity: string, sarif: boolean, prComment: boolean, failOnNew: boolean): string {
  return `name: ChainProbe Security Audit
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: ['**']

jobs:
  chainprobe-audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write${sarif ? `
      security-events: write` : ''}

    steps:
      - uses: actions/checkout@v4

      - name: Run ChainProbe Analysis
        id: chainprobe
        uses: chainprobe/action@v1
        with:
          target: .
          fail-severity: '${failSeverity}'${sarif ? `
          sarif: true` : ''}${failOnNew ? `
          baseline: .chainprobe-baseline.json` : ''}

${sarif ? `      - name: Upload SARIF to GitHub
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: chainprobe-results.sarif.json
          category: chainprobe
` : ''}${prComment ? `      - name: Comment PR with Results
        if: github.event_name == 'pull_request' && always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = JSON.parse(fs.readFileSync('chainprobe-report.json','utf8'));
            const s = report.summary;
            let body = '## ChainProbe Security Audit\\n';
            body += '| Severity | Count |\\n|---------|------|\\n';
            body += '| Critical | ' + s.critical + ' |\\n';
            body += '| High | ' + s.high + ' |\\n';
            body += '| Medium | ' + s.medium + ' |\\n';
            body += '| Low | ' + s.low + ' |\\n';
            body += '| Info | ' + s.info + ' |\\n';
            body += '\\n**Security Score:** ' + s.security_score + '/100\\n';
            body += '\\n**Overall Risk:** ' + s.overall_risk + '\\n';
            body += '\\n[Download SARIF](${`chainprobe-results.sarif.json`})';
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: body
            });
` : ''}`;
}

function generateGitlabYaml(failSeverity: string, sarif: boolean, prComment: boolean, failOnNew: boolean): string {
  return `include:
  - template: Jobs/SAST.gitlab-ci.yml

chainprobe-audit:
  stage: test
  image: chainprobe/cli:latest
  script:
    - chainprobe analyze --target . --fail-severity ${failSeverity}${failOnNew ? ' --baseline .chainprobe-baseline.json' : ''}
  artifacts:
    reports:${sarif ? `
      sast: chainprobe-results.sarif.json` : ''}
    paths:
      - chainprobe-report.json
      ${sarif ? '- chainprobe-results.sarif.json\n' : ''}
  only:
    - main
    - develop
    - merge_requests

${prComment ? `chainprobe-pr-comment:
  stage: post
  image: alpine/curl:latest
  script:
    - apk add --no-cache jq
    - |
      if [ -n "$CI_MERGE_REQUEST_IID" ]; then
        REPORT=$(cat chainprobe-report.json)
        SCORE=$(echo "$REPORT" | jq '.summary.security_score')
        RISK=$(echo "$REPORT" | jq -r '.summary.overall_risk')
        CRIT=$(echo "$REPORT" | jq '.summary.critical')
        HIGH=$(echo "$REPORT" | jq '.summary.high')
        BODY="**ChainProbe Security Audit**%0A| Severity | Count |%0A|---|---|%0A| Critical | $CRIT |%0A| High | $HIGH |%0A%0A**Score:** $SCORE/100%0A**Risk:** $RISK"
        curl -X POST -H "PRIVATE-TOKEN: $CI_JOB_TOKEN" \
          "$CI_API_V4_URL/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes" \
          --data "body=$BODY"
      fi
  needs: [chainprobe-audit]
  only:
    - merge_requests
` : ''}`;
}
