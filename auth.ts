import bcrypt from 'bcryptjs';
import * as jose from 'jose';
import dotenv from 'dotenv';

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-for-local-development-only';
const secret = new TextEncoder().encode(JWT_SECRET);
const TOKEN_TTL = '7d';

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  user_type: string;
}

export async function hashPassword(plain: string): Promise<string> {
  return bcrypt.hash(plain, 10);
}

// Verifies a plaintext password against a bcrypt hash.
// Supabase Auth stores bcrypt hashes ($2a/$2b), so migrated hashes validate here too.
export async function verifyPassword(plain: string, hash: string | null | undefined): Promise<boolean> {
  if (!hash) return false;
  // Normalize $2y (PHP) prefix which bcryptjs doesn't accept, to $2b.
  const normalized = hash.startsWith('$2y$') ? '$2b$' + hash.slice(4) : hash;
  try {
    return await bcrypt.compare(plain, normalized);
  } catch {
    return false;
  }
}

export async function signToken(user: AuthUser): Promise<string> {
  return new jose.SignJWT({
    email: user.email,
    name: user.name,
    user_type: user.user_type,
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(user.id)
    .setIssuedAt()
    .setExpirationTime(TOKEN_TTL)
    .sign(secret);
}

export async function verifyToken(token: string): Promise<AuthUser> {
  const { payload } = await jose.jwtVerify(token, secret, { algorithms: ['HS256'] });
  return {
    id: (payload.sub as string) || '',
    email: (payload.email as string) || '',
    name: (payload.name as string) || '',
    user_type: (payload.user_type as string) || 'user',
  };
}

// Extracts and validates the bearer token from an Authorization header.
export async function getAuthenticatedUser(authHeader: string | null): Promise<AuthUser> {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new Error('Missing or invalid authorization header');
  }
  const token = authHeader.split(' ')[1];
  try {
    return await verifyToken(token);
  } catch (error: any) {
    throw new Error('Invalid or expired token');
  }
}

// User type hierarchy: who can create/manage whom.
export function canManageUserType(creatorType: string, targetType: string): boolean {
  const hierarchy: Record<string, string[]> = {
    super_admin: ['super_admin', 'admin', 'manager', 'user'],
    admin: ['admin', 'manager', 'user'],
    manager: ['user'],
    user: [],
  };
  return hierarchy[creatorType]?.includes(targetType) || false;
}
