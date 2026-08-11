import bcrypt from 'bcryptjs';
import * as jose from 'jose';
import dotenv from 'dotenv';

dotenv.config();

const isProd = process.env.NODE_ENV === 'production';
const rawSecret = process.env.JWT_SECRET;

if (!rawSecret || rawSecret.length < 32) {
  if (isProd) {
    throw new Error(
      'JWT_SECRET must be set with at least 32 characters in production. Refusing to start.'
    );
  }
  console.warn(
    '⚠️ [AUTH] JWT_SECRET ausente ou curto — usando fallback apenas para desenvolvimento local.'
  );
}

const JWT_SECRET = rawSecret && rawSecret.length >= 32
  ? rawSecret
  : 'fallback-secret-for-local-development-only-do-not-use-in-prod';

const secret = new TextEncoder().encode(JWT_SECRET);
/** Preferível a 7d; sobrescreva com JWT_TTL (ex.: 8h, 1d). */
const TOKEN_TTL = process.env.JWT_TTL || '8h';

const PASSWORD_MIN_LENGTH = Math.max(
  8,
  Number.parseInt(process.env.PASSWORD_MIN_LENGTH || '8', 10) || 8
);

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  user_type: string;
}

export class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = 'HttpError';
  }
}

export async function hashPassword(plain: string): Promise<string> {
  return bcrypt.hash(plain, 12);
}

/** Retorna mensagem de erro ou null se a senha for aceitável. */
export function assertStrongPassword(password: string): string | null {
  if (!password || password.length < PASSWORD_MIN_LENGTH) {
    return `A senha deve ter no mínimo ${PASSWORD_MIN_LENGTH} caracteres`;
  }
  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password)) {
    return 'A senha deve incluir maiúscula, minúscula e número';
  }
  return null;
}

export function getPasswordMinLength(): number {
  return PASSWORD_MIN_LENGTH;
}

// Verifies a plaintext password against a bcrypt hash.
// Supabase Auth stores bcrypt hashes ($2a/$2b), so migrated hashes validate here too.
export async function verifyPassword(
  plain: string,
  hash: string | null | undefined
): Promise<boolean> {
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
  if (!payload.sub) {
    throw new Error('Invalid token subject');
  }
  return {
    id: payload.sub as string,
    email: (payload.email as string) || '',
    name: (payload.name as string) || '',
    user_type: (payload.user_type as string) || 'user',
  };
}

// Extracts and validates the bearer token from an Authorization header.
export async function getAuthenticatedUser(
  authHeader: string | null
): Promise<AuthUser> {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new HttpError(401, 'Missing or invalid authorization header');
  }
  const token = authHeader.split(' ')[1];
  try {
    return await verifyToken(token);
  } catch {
    throw new HttpError(401, 'Invalid or expired token');
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

export function isPlatformAdmin(userType: string): boolean {
  return userType === 'admin' || userType === 'super_admin';
}
