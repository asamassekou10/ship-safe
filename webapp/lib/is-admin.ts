/**
 * Admin gate — an email is an admin iff it appears in the comma-separated
 * ADMIN_EMAILS env var. Centralized so the dashboard, layout nav, and admin
 * API routes can't drift apart.
 */
export function isAdmin(email: string | null | undefined): boolean {
  if (!email) return false;
  const admins = (process.env.ADMIN_EMAILS ?? '')
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);
  return admins.includes(email.toLowerCase());
}
