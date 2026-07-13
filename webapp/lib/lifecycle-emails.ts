import crypto from 'crypto';
import { prisma } from './prisma';

/**
 * Lifecycle emails
 * ================
 *
 * Welcome (on signup) → day-3 check-in (non-paying) / outreach (paying),
 * plus a one-time re-engagement template for the existing signup backlog.
 *
 * Idempotency: every send is claimed in the EmailEvent table first
 * (unique on [userId, type]), so the daily cron can run any number of
 * times without double-sending. Welcome is treated as transactional;
 * check-in / outreach / re-engage are marketing and honor lifecycleOptOut.
 *
 * Requires env: RESEND_API_KEY. Optional: EMAIL_FROM_FOUNDER, EMAIL_FROM,
 * EMAIL_REPLY_TO, NEXTAUTH_URL, AUTH_SECRET (for unsubscribe tokens).
 */

export type LifecycleType = 'welcome' | 'day3_checkin' | 'day3_outreach' | 'reengage';

export interface LifecycleUser {
  id: string;
  email: string | null;
  name: string | null;
  plan: string;
  lifecycleOptOut: boolean;
}

const USER_SELECT = { id: true, email: true, name: true, plan: true, lifecycleOptOut: true } as const;
const DAY = 24 * 60 * 60 * 1000;

// ── Unsubscribe tokens ───────────────────────────────────────────────────────

function unsubSecret(): string {
  return process.env.AUTH_SECRET || process.env.NEXTAUTH_SECRET || process.env.CRON_SECRET || 'insecure-dev-secret';
}

export function unsubToken(userId: string): string {
  return crypto.createHmac('sha256', unsubSecret()).update(`unsub:${userId}`).digest('hex').slice(0, 32);
}

export function verifyUnsubToken(userId: string, token: string): boolean {
  const expected = unsubToken(userId);
  if (!token || token.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected));
}

function baseUrl(): string {
  return process.env.NEXTAUTH_URL || process.env.NEXT_PUBLIC_APP_URL || 'https://www.shipsafecli.com';
}

function unsubUrl(userId: string): string {
  return `${baseUrl()}/api/unsubscribe?u=${encodeURIComponent(userId)}&t=${unsubToken(userId)}`;
}

// ── Sender ───────────────────────────────────────────────────────────────────

async function send(to: string, subject: string, html: string): Promise<boolean> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    console.warn('[lifecycle] RESEND_API_KEY not set — skipping send');
    return false;
  }
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: process.env.EMAIL_FROM_FOUNDER || process.env.EMAIL_FROM || 'Ship Safe <hello@shipsafecli.com>',
        to: [to],
        subject,
        html,
        reply_to: process.env.EMAIL_REPLY_TO || undefined,
      }),
    });
    if (!res.ok) console.error('[lifecycle] Resend responded', res.status, await res.text().catch(() => ''));
    return res.ok;
  } catch (err) {
    console.error('[lifecycle] send failed', err);
    return false;
  }
}

// ── Templates (plain, founder-voice) ─────────────────────────────────────────

function firstName(user: LifecycleUser): string {
  return user.name?.trim().split(/\s+/)[0] || 'there';
}

function layout(body: string, userId: string): string {
  return `<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:15px;line-height:1.6;color:#1a1a1a;max-width:520px;margin:0 auto;">
${body}
<hr style="border:none;border-top:1px solid #e5e5e5;margin:28px 0 12px;" />
<p style="font-size:12px;color:#999;margin:0;">
Ship Safe · <a href="https://www.shipsafecli.com" style="color:#0891b2;">shipsafecli.com</a><br/>
You're getting this because you signed up for Ship Safe.
<a href="${unsubUrl(userId)}" style="color:#999;">Unsubscribe</a> from these emails.
</p>
</div>`;
}

function template(user: LifecycleUser, type: LifecycleType): { subject: string; html: string } {
  const name = firstName(user);
  const dashboard = `${baseUrl()}/app`;

  switch (type) {
    case 'welcome':
      return {
        subject: 'Welcome to Ship Safe 🛡️',
        html: layout(
          `<p>Hi ${name},</p>
<p>Thanks for signing up for Ship Safe. It scans your code for secrets, injections, AI/LLM and supply-chain risks — 24 agents, one command.</p>
<p>The fastest way to see it work, right now, in any repo:</p>
<p style="background:#f4f4f5;border-radius:6px;padding:10px 14px;font-family:ui-monospace,monospace;font-size:14px;">npx ship-safe audit .</p>
<p>Or run it from the dashboard: <a href="${dashboard}" style="color:#0891b2;">${dashboard}</a></p>
<p>I read every reply — what are you hoping to use it for?</p>
<p>— Alhassane, Ship Safe</p>`,
          user.id,
        ),
      };

    case 'day3_checkin':
      return {
        subject: 'Did you get a scan running?',
        html: layout(
          `<p>Hi ${name},</p>
<p>You signed up for Ship Safe a few days ago — I wanted to check in.</p>
<p>Did you manage to get a scan running, or did something get in the way? Honestly, either answer is useful to me. If you hit a snag, just reply and I'll help you sort it.</p>
<p>— Alhassane, Ship Safe</p>`,
          user.id,
        ),
      };

    case 'day3_outreach':
      return {
        subject: 'Thank you — quick question',
        html: layout(
          `<p>Hi ${name},</p>
<p>Thank you for upgrading — genuinely, as a small project that means a lot.</p>
<p>Two quick things I'd love to know: what made you decide to pay, and what's the one thing that would make Ship Safe more valuable to you?</p>
<p>Reply straight to this email — it comes to me directly, and I'll act on it.</p>
<p>— Alhassane, Ship Safe</p>`,
          user.id,
        ),
      };

    case 'reengage':
      return {
        subject: 'Ship Safe is active again — v9.4.0',
        html: layout(
          `<p>Hi ${name},</p>
<p>You signed up for Ship Safe a little while back, and it went quiet for a bit. That's on me — and it's changed: we're shipping again.</p>
<p>The latest release (v9.4.0) adds a 24th agent that catches malicious game-engine supply-chain assets and cross-platform "ClickFix" paste-and-run lures, on top of the existing secrets, injection, and AI/LLM coverage.</p>
<p>If you've got a minute, a fresh scan takes one command:</p>
<p style="background:#f4f4f5;border-radius:6px;padding:10px 14px;font-family:ui-monospace,monospace;font-size:14px;">npx ship-safe audit .</p>
<p>And if Ship Safe wasn't useful the first time, I'd really like to know why — just reply.</p>
<p>— Alhassane, Ship Safe</p>`,
          user.id,
        ),
      };
  }
}

// ── Idempotent send ──────────────────────────────────────────────────────────

function isUniqueViolation(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: string }).code === 'P2002';
}

/**
 * Send one lifecycle email to one user, exactly once.
 * Returns the outcome. Safe to call repeatedly.
 */
export async function sendLifecycle(user: LifecycleUser, type: LifecycleType): Promise<
  'sent' | 'already-sent' | 'opted-out' | 'no-email' | 'send-failed'
> {
  if (!user.email) return 'no-email';

  // Claim first — the unique [userId, type] constraint guarantees at-most-once.
  try {
    await prisma.emailEvent.create({ data: { userId: user.id, type } });
  } catch (err) {
    if (isUniqueViolation(err)) return 'already-sent';
    throw err;
  }

  // Marketing emails honor opt-out; welcome is transactional. We keep the claim
  // either way so opted-out users aren't re-evaluated every run.
  if (type !== 'welcome' && user.lifecycleOptOut) return 'opted-out';

  const { subject, html } = template(user, type);
  const ok = await send(user.email, subject, html);
  if (!ok) {
    // Roll back the claim so the next run retries.
    await prisma.emailEvent.deleteMany({ where: { userId: user.id, type } }).catch(() => {});
    return 'send-failed';
  }
  return 'sent';
}

/** Send the welcome email (used by the auth createUser hook). Non-throwing. */
export async function sendWelcome(userId: string): Promise<void> {
  try {
    const user = await prisma.user.findUnique({ where: { id: userId }, select: USER_SELECT });
    if (user) await sendLifecycle(user, 'welcome');
  } catch (err) {
    console.error('[lifecycle] sendWelcome failed', err);
  }
}

// ── Daily runner (called from the cron) ──────────────────────────────────────

/**
 * Idempotent, window-scoped. Runs safely on every cron invocation regardless
 * of schedule. Intentionally does NOT target the pre-existing signup backlog
 * (users older than the day-3 window) — those get the one-time re-engagement
 * send, run separately.
 */
export async function runLifecycleEmails(now: Date = new Date()): Promise<{
  welcomeBackfill: number;
  day3Checkin: number;
  day3Outreach: number;
}> {
  const results = { welcomeBackfill: 0, day3Checkin: 0, day3Outreach: 0 };

  // Welcome backfill — recent signups (<= 2 days) that somehow missed the
  // event-driven welcome. Bounded so it never reaches old users.
  const recent = await prisma.user.findMany({
    where: {
      email: { not: null },
      createdAt: { gte: new Date(now.getTime() - 2 * DAY) },
      emailEvents: { none: { type: 'welcome' } },
    },
    select: USER_SELECT,
    take: 200,
  });
  for (const u of recent) {
    if ((await sendLifecycle(u, 'welcome')) === 'sent') results.welcomeBackfill++;
  }

  // Day-3 — users 3–5 days old with no day-3 email yet. The tight window means
  // the first deploy touches only a handful of edge users, not the backlog.
  const day3 = await prisma.user.findMany({
    where: {
      email: { not: null },
      createdAt: { gte: new Date(now.getTime() - 5 * DAY), lte: new Date(now.getTime() - 3 * DAY) },
      emailEvents: { none: { type: { in: ['day3_checkin', 'day3_outreach'] } } },
    },
    select: USER_SELECT,
    take: 200,
  });
  for (const u of day3) {
    const paying = !!u.plan && u.plan !== 'free';
    const outcome = await sendLifecycle(u, paying ? 'day3_outreach' : 'day3_checkin');
    if (outcome === 'sent') {
      if (paying) results.day3Outreach++;
      else results.day3Checkin++;
    }
  }

  return results;
}

/**
 * One-time re-engagement to the existing signup backlog (users older than the
 * day-3 window). Call manually/deliberately (Phase 3), not from the cron.
 * `limit` keeps sends batched for deliverability on a fresh domain.
 */
export async function sendReengagementBatch(limit = 20): Promise<{ sent: number; scanned: number }> {
  const users = await prisma.user.findMany({
    where: {
      email: { not: null },
      lifecycleOptOut: false,
      createdAt: { lte: new Date(Date.now() - 5 * DAY) },
      emailEvents: { none: { type: 'reengage' } },
    },
    select: USER_SELECT,
    orderBy: { createdAt: 'asc' },
    take: limit,
  });
  let sent = 0;
  for (const u of users) {
    if ((await sendLifecycle(u, 'reengage')) === 'sent') sent++;
  }
  return { sent, scanned: users.length };
}
