import * as vscode from 'vscode';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';

const execAsync = promisify(exec);

interface Finding {
  file: string;
  line: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  rule: string;
  title: string;
  description?: string;
  fix?: string;
}

interface ScanReport {
  score: number;
  grade: string;
  totalFindings: number;
  findings: Finding[];
  categories: Record<string, { label: string; findingCount: number }>;
}

const diagnosticCollection = vscode.languages.createDiagnosticCollection('ship-safe');
const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);

let watchMode = false;
let lastReport: ScanReport | null = null;

const severityMap: Record<string, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
};

const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function activate(context: vscode.ExtensionContext) {
  // Status bar
  statusBarItem.command = 'shipSafe.scanWorkspace';
  statusBarItem.text = '$(shield) Ship Safe';
  statusBarItem.tooltip = 'Click to scan workspace';
  statusBarItem.show();

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand('shipSafe.scanWorkspace', scanWorkspace),
    vscode.commands.registerCommand('shipSafe.scanFile', scanCurrentFile),
    vscode.commands.registerCommand('shipSafe.showReport', showReport),
    vscode.commands.registerCommand('shipSafe.toggleWatch', toggleWatch),
    diagnosticCollection,
    statusBarItem,
  );

  // Auto-scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const config = vscode.workspace.getConfiguration('shipSafe');
      if (config.get('autoScanOnSave') || watchMode) {
        scanFile(doc.uri);
      }
    })
  );

  // Provide code actions (quick fixes)
  context.subscriptions.push(
    vscode.languages.registerCodeActionProvider('*', new ShipSafeCodeActionProvider(), {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
    })
  );
}

async function scanWorkspace() {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) {
    vscode.window.showWarningMessage('No workspace folder open');
    return;
  }

  const workspacePath = folders[0].uri.fsPath;
  statusBarItem.text = '$(loading~spin) Scanning...';

  try {
    const config = vscode.workspace.getConfiguration('shipSafe');
    const deep = config.get('deep') ? '--deep' : '';

    const { stdout } = await execAsync(
      `npx ship-safe audit "${workspacePath}" --json --deps ${deep}`,
      { timeout: 120_000, maxBuffer: 10 * 1024 * 1024, cwd: workspacePath }
    );

    const report: ScanReport = JSON.parse(stdout);
    lastReport = report;

    applyDiagnostics(report, workspacePath);
    updateStatusBar(report);

    const msg = `Ship Safe: ${report.grade} (${report.score}/100) — ${report.totalFindings} findings`;
    if (report.score >= 80) {
      vscode.window.showInformationMessage(msg);
    } else if (report.score >= 60) {
      vscode.window.showWarningMessage(msg);
    } else {
      vscode.window.showErrorMessage(msg);
    }
  } catch (err) {
    statusBarItem.text = '$(shield) Ship Safe';
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('not found') || msg.includes('not recognized')) {
      vscode.window.showErrorMessage('Ship Safe CLI not found. Install with: npm install -g ship-safe');
    } else {
      vscode.window.showErrorMessage(`Ship Safe scan failed: ${msg.slice(0, 200)}`);
    }
  }
}

async function scanCurrentFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) return;
  await scanFile(editor.document.uri);
}

async function scanFile(uri: vscode.Uri) {
  const filePath = uri.fsPath;
  const workspacePath = vscode.workspace.getWorkspaceFolder(uri)?.uri.fsPath;
  if (!workspacePath) return;

  try {
    const { stdout } = await execAsync(
      `npx ship-safe scan "${filePath}" --json`,
      { timeout: 30_000, maxBuffer: 5 * 1024 * 1024, cwd: workspacePath }
    );

    // Parse findings for this file
    const lines = stdout.split('\n');
    const jsonLine = lines.find(l => l.startsWith('{'));
    if (!jsonLine) return;

    const report: ScanReport = JSON.parse(jsonLine);
    const fileFindings = report.findings.filter(f => {
      const absPath = path.resolve(workspacePath, f.file);
      return absPath === filePath || f.file === path.relative(workspacePath, filePath);
    });

    if (fileFindings.length > 0) {
      const diagnostics = fileFindings.map(f => createDiagnostic(f));
      diagnosticCollection.set(uri, diagnostics);
    } else {
      diagnosticCollection.delete(uri);
    }
  } catch {
    // Silently fail for individual file scans
  }
}

function applyDiagnostics(report: ScanReport, workspacePath: string) {
  diagnosticCollection.clear();

  const config = vscode.workspace.getConfiguration('shipSafe');
  const minSeverity = config.get<string>('severity') || 'medium';
  const minLevel = severityOrder[minSeverity] ?? 2;

  const fileMap = new Map<string, vscode.Diagnostic[]>();

  for (const finding of report.findings) {
    if ((severityOrder[finding.severity] ?? 3) > minLevel) continue;

    const absPath = path.resolve(workspacePath, finding.file);
    const uri = vscode.Uri.file(absPath);
    const key = uri.toString();

    if (!fileMap.has(key)) fileMap.set(key, []);
    fileMap.get(key)!.push(createDiagnostic(finding));
  }

  for (const [uriStr, diagnostics] of fileMap) {
    diagnosticCollection.set(vscode.Uri.parse(uriStr), diagnostics);
  }
}

function createDiagnostic(finding: Finding): vscode.Diagnostic {
  const line = Math.max(0, (finding.line || 1) - 1);
  const range = new vscode.Range(line, 0, line, 999);
  const severity = severityMap[finding.severity] ?? vscode.DiagnosticSeverity.Warning;

  const diagnostic = new vscode.Diagnostic(range, `${finding.title}: ${finding.description || finding.rule}`, severity);
  diagnostic.source = 'Ship Safe';
  diagnostic.code = finding.rule;

  // Store fix info for code actions
  if (finding.fix) {
    diagnostic.relatedInformation = [
      new vscode.DiagnosticRelatedInformation(
        new vscode.Location(vscode.Uri.parse(''), new vscode.Range(0, 0, 0, 0)),
        `Fix: ${finding.fix}`
      ),
    ];
  }

  return diagnostic;
}

function updateStatusBar(report: ScanReport) {
  const icon = report.score >= 80 ? '$(pass)' : report.score >= 60 ? '$(warning)' : '$(error)';
  statusBarItem.text = `${icon} ${report.grade} ${report.score}/100`;
  statusBarItem.tooltip = `Ship Safe: ${report.totalFindings} findings\nClick to re-scan`;
  statusBarItem.color = report.score >= 80 ? '#4ade80' : report.score >= 60 ? '#fbbf24' : '#f87171';
}

function toggleWatch() {
  watchMode = !watchMode;
  vscode.window.showInformationMessage(`Ship Safe watch mode: ${watchMode ? 'ON' : 'OFF'}`);
}

function showReport() {
  if (!lastReport) {
    vscode.window.showInformationMessage('No scan report available. Run a scan first.');
    return;
  }

  const panel = vscode.window.createWebviewPanel('shipSafeReport', `Ship Safe Report — ${lastReport.grade}`, vscode.ViewColumn.One, {});

  const cats = Object.entries(lastReport.categories || {})
    .filter(([, v]) => v.findingCount > 0)
    .map(([k, v]) => `<tr><td>${v.label}</td><td>${v.findingCount}</td></tr>`)
    .join('');

  const findings = lastReport.findings
    .map(f => `<tr><td><span class="sev sev-${f.severity}">${f.severity}</span></td><td>${f.title}</td><td><code>${f.file}:${f.line || ''}</code></td><td>${f.fix || ''}</td></tr>`)
    .join('');

  panel.webview.html = `<!DOCTYPE html>
<html><head><style>
  body { font-family: var(--vscode-font-family); color: var(--vscode-foreground); padding: 20px; }
  h1 { font-size: 20px; } h2 { font-size: 16px; margin-top: 24px; }
  table { width: 100%; border-collapse: collapse; margin-top: 8px; }
  th, td { padding: 8px; text-align: left; border-bottom: 1px solid var(--vscode-panel-border); }
  .sev { padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
  .sev-critical { background: #f8717120; color: #f87171; }
  .sev-high { background: #fb923c20; color: #fb923c; }
  .sev-medium { background: #fbbf2420; color: #fbbf24; }
  .sev-low { background: #4ade8020; color: #4ade80; }
  code { font-size: 12px; color: var(--vscode-textLink-foreground); }
  .score { font-size: 36px; font-weight: 800; font-family: monospace; }
</style></head><body>
  <h1>Ship Safe Security Report</h1>
  <p class="score">${lastReport.grade} — ${lastReport.score}/100</p>
  <p>${lastReport.totalFindings} findings</p>
  ${cats ? `<h2>Categories</h2><table><tr><th>Category</th><th>Findings</th></tr>${cats}</table>` : ''}
  ${findings ? `<h2>Findings</h2><table><tr><th>Severity</th><th>Title</th><th>File</th><th>Fix</th></tr>${findings}</table>` : '<p>No findings — your code looks clean!</p>'}
</body></html>`;
}

class ShipSafeCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(document: vscode.TextDocument, range: vscode.Range): vscode.CodeAction[] {
    const diagnostics = vscode.languages.getDiagnostics(document.uri);
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of diagnostics) {
      if (diagnostic.source !== 'Ship Safe') continue;
      if (!diagnostic.range.intersection(range)) continue;

      // Suppress action
      const suppress = new vscode.CodeAction(`Ship Safe: Ignore ${diagnostic.code}`, vscode.CodeActionKind.QuickFix);
      suppress.diagnostics = [diagnostic];
      suppress.edit = new vscode.WorkspaceEdit();
      const line = document.lineAt(diagnostic.range.start.line);
      suppress.edit.insert(document.uri, line.range.end, ' // ship-safe-ignore');
      actions.push(suppress);

      // Fix suggestion from related info
      if (diagnostic.relatedInformation?.[0]) {
        const fixAction = new vscode.CodeAction(`Ship Safe: ${diagnostic.relatedInformation[0].message}`, vscode.CodeActionKind.QuickFix);
        fixAction.diagnostics = [diagnostic];
        fixAction.isPreferred = true;
        actions.push(fixAction);
      }
    }

    return actions;
  }
}

export function deactivate() {
  diagnosticCollection.dispose();
  statusBarItem.dispose();
}
