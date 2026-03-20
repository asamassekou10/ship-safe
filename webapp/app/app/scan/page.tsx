'use client';
import { useState, useRef } from 'react';
import { useRouter } from 'next/navigation';
import styles from './scan.module.css';

type ScanMethod = 'github' | 'url' | 'upload';

export default function NewScan() {
  const router = useRouter();
  const [method, setMethod] = useState<ScanMethod>('github');
  const [repo, setRepo] = useState('');
  const [branch, setBranch] = useState('main');
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const [options, setOptions] = useState({
    deep: true,
    verifySecrets: true,
    deps: true,
    sbom: false,
  });

  function toggleOption(key: keyof typeof options) {
    setOptions(prev => ({ ...prev, [key]: !prev[key] }));
  }

  function handleFile(f: File | null) {
    if (!f) return;
    if (!f.name.endsWith('.zip')) { setError('Only .zip files are accepted.'); return; }
    if (f.size > 50 * 1024 * 1024) { setError('File too large. Max 50MB.'); return; }
    setFile(f);
    setError('');
  }

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setScanning(true);

    try {
      if (method === 'upload') {
        if (!file) { setError('Please select a ZIP file.'); setScanning(false); return; }
        const formData = new FormData();
        formData.append('file', file);
        formData.append('method', 'upload');
        formData.append('options', JSON.stringify(options));

        const res = await fetch('/api/scan/upload', { method: 'POST', body: formData });
        const data = await res.json();
        if (!res.ok) {
          setError(res.status === 429 ? '__LIMIT__' : (data.error || 'Upload failed'));
          setScanning(false);
          return;
        }
        router.push(`/app/scans/${data.id}`);
        return;
      }

      // GitHub / URL method
      let repoValue = repo.trim();
      if (method === 'github') {
        const ghMatch = repoValue.match(/github\.com\/([^/]+\/[^/]+)/);
        if (ghMatch) repoValue = ghMatch[1].replace(/\.git$/, '');
      }

      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo: repoValue, branch, method, options }),
      });

      const data = await res.json();
      if (!res.ok) {
        if (res.status === 429) {
          setError('__LIMIT__');
        } else {
          setError(data.error || 'Scan failed');
        }
        setScanning(false);
        return;
      }
      router.push(`/app/scans/${data.id}`);
    } catch {
      setError('Network error. Please try again.');
      setScanning(false);
    }
  }

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <h1>New Scan</h1>
        <p className={styles.subtitle}>Submit a repository to scan with all 16 security agents.</p>
      </div>

      {/* Method tabs */}
      <div className={styles.methodTabs}>
        {(['github', 'url', 'upload'] as ScanMethod[]).map(m => (
          <button
            key={m}
            className={`${styles.methodTab} ${method === m ? styles.active : ''}`}
            onClick={() => setMethod(m)}
          >
            {m === 'github' && (
              <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" /></svg>
            )}
            {m === 'url' && (
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" /><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" /></svg>
            )}
            {m === 'upload' && (
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="16 16 12 12 8 16" /><line x1="12" y1="12" x2="12" y2="21" /><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3" /></svg>
            )}
            {m === 'github' ? 'GitHub' : m === 'url' ? 'Git URL' : 'Upload ZIP'}
          </button>
        ))}
      </div>

      <form onSubmit={handleScan} className={styles.form}>
        {method === 'github' && (
          <div className={styles.field}>
            <label>GitHub repository (owner/repo or full URL)</label>
            <input
              type="text"
              placeholder="owner/repo or https://github.com/owner/repo"
              value={repo}
              onChange={e => setRepo(e.target.value)}
              className={styles.input}
              required
            />
            <span className={styles.fieldNote}>Public repos only on the Free plan.</span>
          </div>
        )}

        {method === 'url' && (
          <div className={styles.field}>
            <label>Git repository URL</label>
            <input
              type="url"
              placeholder="https://github.com/owner/repo or https://gitlab.com/owner/repo"
              value={repo}
              onChange={e => setRepo(e.target.value)}
              className={styles.input}
              required
            />
            <span className={styles.fieldNote}>Public repos only on the Free plan.</span>
          </div>
        )}

        {method === 'upload' && (
          <div
            className={styles.dropZone}
            style={dragging ? { borderColor: 'var(--cyan)', background: 'var(--cyan-glow)' } : {}}
            onDragOver={e => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={e => { e.preventDefault(); setDragging(false); handleFile(e.dataTransfer.files[0]); }}
            onClick={() => fileRef.current?.click()}
          >
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><polyline points="16 16 12 12 8 16" /><line x1="12" y1="12" x2="12" y2="21" /><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3" /></svg>
            {file ? (
              <p style={{ fontWeight: 600, color: 'var(--cyan)' }}>
                {file.name} <span style={{ fontWeight: 400, color: 'var(--text-dim)' }}>({(file.size / 1024 / 1024).toFixed(1)} MB)</span>
              </p>
            ) : (
              <p>Drop your ZIP file here, or <span className={styles.browseLabel}>browse</span></p>
            )}
            <input
              ref={fileRef}
              type="file"
              accept=".zip"
              className={styles.fileInput}
              onChange={e => handleFile(e.target.files?.[0] ?? null)}
            />
            <span className={styles.fieldNote}>Max 50MB · .zip only</span>
          </div>
        )}

        {(method === 'github' || method === 'url') && (
          <div className={styles.field}>
            <label>Branch</label>
            <input
              type="text"
              value={branch}
              onChange={e => setBranch(e.target.value)}
              className={styles.input}
              placeholder="main"
            />
          </div>
        )}

        {/* Scan options */}
        <div className={styles.optionsGrid}>
          <label className={styles.optionCard}>
            <input type="checkbox" checked={options.deep} onChange={() => toggleOption('deep')} />
            <div>
              <span className={styles.optionName}>Deep AI analysis</span>
              <span className={styles.optionDesc}>LLM-powered exploitability verification (uses your API key)</span>
            </div>
          </label>
          <label className={styles.optionCard}>
            <input type="checkbox" checked={options.verifySecrets} onChange={() => toggleOption('verifySecrets')} />
            <div>
              <span className={styles.optionName}>Verify live secrets</span>
              <span className={styles.optionDesc}>Test if leaked keys are still active</span>
            </div>
          </label>
          <label className={styles.optionCard}>
            <input type="checkbox" checked={options.deps} onChange={() => toggleOption('deps')} />
            <div>
              <span className={styles.optionName}>Dependency CVEs</span>
              <span className={styles.optionDesc}>Audit npm/pip/gem dependencies</span>
            </div>
          </label>
          <label className={styles.optionCard}>
            <input type="checkbox" checked={options.sbom} onChange={() => toggleOption('sbom')} />
            <div>
              <span className={styles.optionName}>Generate SBOM</span>
              <span className={styles.optionDesc}>CycloneDX software bill of materials</span>
            </div>
          </label>
        </div>

        {error === '__LIMIT__' ? (
          <div className={styles.error}>
            Free plan limit reached (5 scans/month).{' '}
            <a href="/app/settings" style={{ color: 'var(--cyan)', textDecoration: 'underline' }}>
              Upgrade to Pro
            </a>{' '}
            for unlimited scans.
          </div>
        ) : error ? (
          <div className={styles.error}>{error}</div>
        ) : null}

        <button type="submit" className={`btn btn-primary ${styles.submitBtn}`} disabled={scanning}>
          {scanning ? (
            <>
              <span className={styles.spinner} />
              Scanning...
            </>
          ) : (
            <>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" /></svg>
              Run security scan
            </>
          )}
        </button>
      </form>

      {/* CLI tip */}
      <div className={styles.cliTip}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>
        Prefer the CLI? <code>npx ship-safe audit .</code> runs locally with no limits, forever free.
      </div>
    </div>
  );
}
