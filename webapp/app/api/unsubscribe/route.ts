import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { verifyUnsubToken } from '@/lib/lifecycle-emails';

/**
 * GET /api/unsubscribe?u=<userId>&t=<token>
 *
 * One-click unsubscribe from lifecycle/marketing emails. The token is an
 * HMAC of the user id, so a link can't be forged to opt out someone else.
 */
function page(title: string, message: string, status = 200): NextResponse {
  const html = `<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><title>${title}</title></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#fafafa;color:#1a1a1a;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;">
<div style="max-width:420px;text-align:center;padding:32px;">
<h1 style="font-size:20px;margin:0 0 12px;">${title}</h1>
<p style="color:#555;line-height:1.6;margin:0 0 20px;">${message}</p>
<a href="https://www.shipsafecli.com" style="color:#0891b2;text-decoration:none;">← Back to Ship Safe</a>
</div></body></html>`;
  return new NextResponse(html, { status, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

export async function GET(req: NextRequest) {
  const userId = req.nextUrl.searchParams.get('u') ?? '';
  const token = req.nextUrl.searchParams.get('t') ?? '';

  if (!userId || !token || !verifyUnsubToken(userId, token)) {
    return page('Invalid link', 'This unsubscribe link is invalid or expired. If you keep getting emails, reply to one and we\'ll remove you.', 400);
  }

  try {
    await prisma.user.update({ where: { id: userId }, data: { lifecycleOptOut: true } });
  } catch {
    return page('Something went wrong', 'We couldn\'t process that just now. Please reply to any email and we\'ll unsubscribe you manually.', 500);
  }

  return page('You\'re unsubscribed', 'You won\'t receive any more check-in or product emails from Ship Safe. Account and security-scan notifications are unaffected.');
}
