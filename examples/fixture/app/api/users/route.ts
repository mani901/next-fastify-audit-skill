// Fixture: intentionally vulnerable Next.js route handler.
// Planted issues: no auth check (SEC-009), no input validation (SEC-010).

export async function POST(req) {
  const body = await req.json();

  // No validation: body.email and body.role are trusted as-is.
  const user = {
    email: body.email,
    role: body.role || 'user',
    isAdmin: body.isAdmin === true,
  };

  // No auth check anywhere in this handler.
  return Response.json({ ok: true, user });
}

export async function GET() {
  return Response.json({ users: [] });
}
