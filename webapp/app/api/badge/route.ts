import { NextRequest, NextResponse } from 'next/server';

/**
 * Badge Service — Returns a shields.io-compatible SVG badge.
 *
 * Usage:
 *   /api/badge?score=85&grade=A
 *   /api/badge?grade=B
 *
 * Returns:
 *   Redirects to shields.io badge URL with appropriate color.
 */

const GRADE_COLORS: Record<string, string> = {
  A: 'brightgreen',
  B: '06b6d4',    // cyan
  C: 'yellow',
  D: 'red',
  F: 'dc2626',    // dark red
};

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const score = searchParams.get('score') || '';
  const grade = searchParams.get('grade')?.toUpperCase() || '';

  if (!grade || !GRADE_COLORS[grade]) {
    return NextResponse.json(
      { error: 'Missing or invalid grade parameter. Use ?grade=A&score=85' },
      { status: 400 }
    );
  }

  const color = GRADE_COLORS[grade];
  const label = 'ship--safe';
  const message = score ? `${grade}%20(${score})` : grade;

  const badgeUrl = `https://img.shields.io/badge/${label}-${message}-${color}?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHZpZXdCb3g9IjAgMCAxNiAxNiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHJ4PSIzIiBmaWxsPSIjMDg5MWIyIi8+PHBhdGggZD0iTTQgOGw0IDQgNC04IiBzdHJva2U9IiNmZmYiIHN0cm9rZS13aWR0aD0iMiIgZmlsbD0ibm9uZSIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIi8+PC9zdmc+`;

  return NextResponse.redirect(badgeUrl, { status: 302, headers: { 'Cache-Control': 'public, max-age=3600' } });
}
