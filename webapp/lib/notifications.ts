import { prisma } from './prisma';
import crypto from 'crypto';

/* ── Types ────────────────────────────────────────────── */

interface ScanResult {
  id: string;
  repo: string;
  branch: string;
  score: number | null;
  grade: string | null;
  findings: number;
  secrets: number;
  vulns: number;
  cves: number;
  status: string;
  userId: string;
  orgId?: string | null;
}

/* ── Email (Resend-compatible HTTP API) ───────────────── */

async function sendEmail(to: string, subject: string, html: string) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return;

  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: process.env.EMAIL_FROM || 'Ship Safe <noreply@shipsafe.dev>',
      to: [to],
      subject,
      html,
    }),
  }).catch(console.error);
}

function scanEmailHtml(scan: ScanResult): string {
  const gradeColor = (scan.score ?? 0) >= 80 ? '#4ade80' : (scan.score ?? 0) >= 60 ? '#fbbf24' : '#f87171';
  return `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 500px; margin: 0 auto; background: #09090b; color: #fafafa; border-radius: 12px; overflow: hidden;">
      <div style="padding: 24px; border-bottom: 1px solid #27272a;">
        <h2 style="margin: 0; font-size: 18px;">🛡️ Ship Safe Scan Complete</h2>
      </div>
      <div style="padding: 24px;">
        <p style="color: #a1a1aa; font-size: 14px; margin: 0 0 16px;">
          <strong style="color: #fafafa;">${scan.repo}</strong> · ${scan.branch}
        </p>
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 20px;">
          <span style="font-size: 36px; font-weight: 800; color: ${gradeColor}; font-family: monospace;">
            ${scan.grade ?? '-'}
          </span>
          <span style="font-size: 20px; font-weight: 700; color: ${gradeColor}; font-family: monospace;">
            ${scan.score ?? 0}/100
          </span>
        </div>
        <table style="width: 100%; font-size: 14px; border-collapse: collapse;">
          <tr><td style="padding: 8px 0; color: #71717a;">Findings</td><td style="text-align: right; font-weight: 600;">${scan.findings}</td></tr>
          <tr><td style="padding: 8px 0; color: #71717a;">Secrets</td><td style="text-align: right; font-weight: 600;">${scan.secrets}</td></tr>
          <tr><td style="padding: 8px 0; color: #71717a;">Code Vulns</td><td style="text-align: right; font-weight: 600;">${scan.vulns}</td></tr>
          <tr><td style="padding: 8px 0; color: #71717a;">CVEs</td><td style="text-align: right; font-weight: 600;">${scan.cves}</td></tr>
        </table>
        <a href="${process.env.AUTH_URL || 'https://shipsafe.dev'}/app/scans/${scan.id}"
           style="display: inline-block; margin-top: 20px; padding: 10px 24px; background: #22d3ee; color: #09090b; font-weight: 700; border-radius: 8px; text-decoration: none; font-size: 14px;">
          View Full Report
        </a>
      </div>
    </div>
  `;
}

/* ── Slack ─────────────────────────────────────────────── */

async function sendSlack(webhookUrl: string, scan: ScanResult) {
  const emoji = (scan.score ?? 0) >= 80 ? '🟢' : (scan.score ?? 0) >= 60 ? '🟡' : '🔴';

  await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      blocks: [
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `${emoji} *Ship Safe Scan Complete*\n*${scan.repo}* (${scan.branch})\nScore: *${scan.score}/100* (${scan.grade}) · ${scan.findings} findings`,
          },
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Secrets:* ${scan.secrets}` },
            { type: 'mrkdwn', text: `*Code Vulns:* ${scan.vulns}` },
            { type: 'mrkdwn', text: `*CVEs:* ${scan.cves}` },
            { type: 'mrkdwn', text: `*Duration:* scan complete` },
          ],
        },
        {
          type: 'actions',
          elements: [{
            type: 'button',
            text: { type: 'plain_text', text: 'View Report' },
            url: `${process.env.AUTH_URL || 'https://shipsafe.dev'}/app/scans/${scan.id}`,
          }],
        },
      ],
    }),
  }).catch(console.error);
}

/* ── Webhooks ─────────────────────────────────────────── */

async function dispatchWebhooks(event: string, payload: Record<string, unknown>, orgId?: string | null) {
  const webhooks = await prisma.webhook.findMany({
    where: {
      enabled: true,
      ...(orgId ? { orgId } : {}),
    },
  });

  for (const wh of webhooks) {
    const events = wh.events as string[];
    if (!events.includes(event)) continue;

    const body = JSON.stringify({ event, timestamp: new Date().toISOString(), data: payload });
    const signature = crypto.createHmac('sha256', wh.secret).update(body).digest('hex');

    fetch(wh.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-ShipSafe-Signature': `sha256=${signature}`,
        'X-ShipSafe-Event': event,
      },
      body,
    })
      .then(res => {
        prisma.webhook.update({ where: { id: wh.id }, data: { lastStatus: res.status } }).catch(() => {});
      })
      .catch(() => {
        prisma.webhook.update({ where: { id: wh.id }, data: { lastStatus: 0 } }).catch(() => {});
      });
  }
}

/* ── Main dispatcher ──────────────────────────────────── */

export async function notifyScanComplete(scan: ScanResult) {
  // 1. Email notification
  const settings = await prisma.notificationSetting.findUnique({
    where: { userId: scan.userId },
    include: { user: { select: { email: true } } },
  });

  if (settings?.user.email) {
    const hasCritical = scan.secrets > 0 || scan.findings > 5;

    if (settings.emailOnComplete) {
      await sendEmail(settings.user.email, `Scan complete: ${scan.repo} — ${scan.grade} (${scan.score}/100)`, scanEmailHtml(scan));
    } else if (settings.emailOnCritical && hasCritical) {
      await sendEmail(settings.user.email, `⚠️ Critical findings in ${scan.repo}`, scanEmailHtml(scan));
    }

    // Slack
    if (settings.slackWebhookUrl) {
      if (settings.slackOnComplete || (settings.slackOnCritical && hasCritical)) {
        await sendSlack(settings.slackWebhookUrl, scan);
      }
    }
  }

  // 2. Webhooks
  await dispatchWebhooks('scan.completed', {
    scanId: scan.id,
    repo: scan.repo,
    branch: scan.branch,
    score: scan.score,
    grade: scan.grade,
    findings: scan.findings,
    secrets: scan.secrets,
    vulns: scan.vulns,
    cves: scan.cves,
    status: scan.status,
  }, scan.orgId);
}

export async function notifyScanFailed(scan: ScanResult, error: string) {
  await dispatchWebhooks('scan.failed', {
    scanId: scan.id,
    repo: scan.repo,
    error,
  }, scan.orgId);
}

/* ── Guardian Notifications ──────────────────────────── */

interface GuardianResult {
  id: string;
  userId: string;
  orgId?: string | null;
  repo: string;
  prNumber: number;
  prTitle?: string | null;
  status: string;
  fixSummary?: string | null;
  attempts: number;
  mergeSha?: string | null;
}

export async function notifyGuardianComplete(run: GuardianResult) {
  const settings = await prisma.notificationSetting.findUnique({
    where: { userId: run.userId },
  });

  if (!settings) return;

  const [owner, repo] = run.repo.split('/');
  const prUrl = `https://github.com/${owner}/${repo}/pull/${run.prNumber}`;
  const statusEmoji = run.status === 'merged' ? '🟢' : run.status === 'blocked' ? '🟡' : '🔴';

  // Email notification
  if (settings.emailOnComplete && process.env.RESEND_API_KEY) {
    const user = await prisma.user.findUnique({ where: { id: run.userId }, select: { email: true } });
    if (user?.email) {
      await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: process.env.EMAIL_FROM || 'Ship Safe <noreply@shipsafe.dev>',
          to: [user.email],
          subject: `${statusEmoji} PR Guardian: ${run.prTitle || `PR #${run.prNumber}`} — ${run.status}`,
          html: `<div style="font-family:system-ui;background:#09090b;color:#fafafa;padding:2rem;border-radius:12px;max-width:560px">
            <h2 style="margin:0 0 1rem;font-size:1.1rem">PR Guardian — ${run.status.charAt(0).toUpperCase() + run.status.slice(1)}</h2>
            <p style="margin:0.5rem 0;font-size:0.9rem"><strong>Repo:</strong> ${run.repo}</p>
            <p style="margin:0.5rem 0;font-size:0.9rem"><strong>PR:</strong> <a href="${prUrl}" style="color:#22d3ee">#${run.prNumber} ${run.prTitle || ''}</a></p>
            ${run.fixSummary ? `<p style="margin:0.5rem 0;font-size:0.9rem"><strong>Fixes:</strong> ${run.fixSummary}</p>` : ''}
            ${run.mergeSha ? `<p style="margin:0.5rem 0;font-size:0.9rem"><strong>Merge:</strong> ${run.mergeSha.slice(0, 7)}</p>` : ''}
            <p style="margin:1rem 0 0;font-size:0.75rem;color:#71717a">Attempts: ${run.attempts}</p>
          </div>`,
        }),
      }).catch(() => {});
    }
  }

  // Slack notification
  if (settings.slackWebhookUrl && settings.slackOnComplete) {
    await fetch(settings.slackWebhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        blocks: [
          { type: 'section', text: { type: 'mrkdwn', text: `${statusEmoji} *PR Guardian — ${run.status}*\n<${prUrl}|${run.repo}#${run.prNumber}>` } },
          { type: 'section', fields: [
            { type: 'mrkdwn', text: `*Fixes:* ${run.fixSummary || 'None'}` },
            { type: 'mrkdwn', text: `*Attempts:* ${run.attempts}` },
          ]},
        ],
      }),
    }).catch(() => {});
  }

  // Webhooks
  await dispatchWebhooks(`guardian.${run.status}`, {
    runId: run.id,
    repo: run.repo,
    prNumber: run.prNumber,
    status: run.status,
    fixSummary: run.fixSummary,
    attempts: run.attempts,
  }, run.orgId);
}

export async function notifyGuardianBlocked(run: GuardianResult, reason: string) {
  await dispatchWebhooks('guardian.blocked', {
    runId: run.id,
    repo: run.repo,
    prNumber: run.prNumber,
    reason,
  }, run.orgId);
}
