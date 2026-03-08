/**
 * PDF Generator
 * ==============
 *
 * Zero-dependency PDF generation via Chrome/Chromium headless mode.
 * Falls back to generating a print-optimized HTML file if Chrome is not found.
 */

import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';

/**
 * Well-known Chrome/Chromium paths by platform.
 */
function findChrome() {
  const candidates = process.platform === 'win32'
    ? [
        process.env.CHROME_PATH,
        'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
        process.env.LOCALAPPDATA && path.join(process.env.LOCALAPPDATA, 'Google\\Chrome\\Application\\chrome.exe'),
      ]
    : process.platform === 'darwin'
    ? [
        process.env.CHROME_PATH,
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        '/Applications/Chromium.app/Contents/MacOS/Chromium',
      ]
    : [
        process.env.CHROME_PATH,
        '/usr/bin/google-chrome',
        '/usr/bin/google-chrome-stable',
        '/usr/bin/chromium',
        '/usr/bin/chromium-browser',
        '/snap/bin/chromium',
      ];

  for (const c of candidates) {
    if (c && fs.existsSync(c)) return c;
  }
  return null;
}

/**
 * Check if Chrome is available.
 */
export function isChromeAvailable() {
  return findChrome() !== null;
}

/**
 * Generate PDF from an HTML file using Chrome headless.
 * Returns the output path, or null if Chrome is not available.
 */
export function generatePDF(htmlPath, outputPath) {
  const chrome = findChrome();
  if (!chrome) return null;

  try {
    const args = [
      '--headless',
      '--disable-gpu',
      '--no-sandbox',
      `--print-to-pdf=${outputPath}`,
      '--print-to-pdf-no-header',
      htmlPath,
    ];
    execFileSync(chrome, args, { timeout: 30000, stdio: 'pipe' });
    return outputPath;
  } catch {
    return null;
  }
}

/**
 * Generate a print-optimized HTML file as PDF fallback.
 */
export function generatePrintHTML(htmlPath, outputPath) {
  let html = fs.readFileSync(htmlPath, 'utf-8');
  // Add print-optimized styles
  const printCSS = `
<style media="print">
  body { background: #fff !important; color: #1e293b !important; }
  .score-card, .stat, .summary-card, .toc { background: #f8fafc !important; border: 1px solid #e2e8f0 !important; }
  table, th, td { border: 1px solid #e2e8f0 !important; }
  code { background: #f1f5f9 !important; color: #0f172a !important; }
  pre { background: #f1f5f9 !important; }
  a { color: #0369a1 !important; }
</style>`;
  html = html.replace('</head>', printCSS + '\n</head>');
  fs.writeFileSync(outputPath, html);
  return outputPath;
}
