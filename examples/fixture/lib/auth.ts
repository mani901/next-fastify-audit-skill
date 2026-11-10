// Fixture: a clean file, included to show the scanner does not flag good code.
// - Secrets come from process.env.
// - JWT is verified with an env secret.
// - Input is validated before use.

import jwt from 'jsonwebtoken';
import { z } from 'zod';

const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

export function verifyToken(token) {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error('JWT_SECRET is not set');
  return jwt.verify(token, secret);
}

export async function login(req) {
  const body = LoginSchema.parse(await req.json());
  return { email: body.email };
}
