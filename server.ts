import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { secureHeaders } from 'hono/secure-headers';
import { randomUUID } from 'crypto';
import { query } from './db.js';
import dotenv from 'dotenv';
import {
  hashPassword,
  verifyPassword,
  signToken,
  getAuthenticatedUser,
  canManageUserType,
  assertStrongPassword,
  isPlatformAdmin,
  HttpError,
  type AuthUser,
} from './auth.js';
import { ensurePhaseDSchema } from './schemaPhaseD.js';
import { writeAuditLog } from './audit.js';

dotenv.config();

const app = new Hono();
const PORT = process.env.PORT ? parseInt(process.env.PORT) : 3001;

const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || 'http://localhost:5173,http://localhost:3000')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

type ProjectRole = 'owner' | 'admin' | 'editor' | 'viewer';

/** Create (POST) — aligned with frontend canCreate (admin/owner only). */
const ROLE_CREATE: ProjectRole[] = ['owner', 'admin'];
/** Update (PUT) — editors can edit existing records. */
const ROLE_WRITE: ProjectRole[] = ['owner', 'admin', 'editor'];
const ROLE_DELETE: ProjectRole[] = ['owner', 'admin'];
const ROLE_MANAGE: ProjectRole[] = ['owner', 'admin'];
const ROLE_READ: ProjectRole[] = ['owner', 'admin', 'editor', 'viewer'];

// Rate limit in-memory (use Redis in multi-instance production).
const rateBuckets = new Map<string, { count: number; reset: number }>();
function rateLimit(key: string, limit: number, windowMs: number): boolean {
  const now = Date.now();
  const b = rateBuckets.get(key);
  if (!b || now > b.reset) {
    rateBuckets.set(key, { count: 1, reset: now + windowMs });
    return true;
  }
  if (b.count >= limit) return false;
  b.count += 1;
  return true;
}

function clientIp(c: any): string {
  const xf = c.req.header('x-forwarded-for');
  if (xf) return xf.split(',')[0].trim();
  return c.req.header('x-real-ip') || 'unknown';
}

// Middleware
app.use('*', logger(console.log));
app.use(
  '*',
  secureHeaders({
    xFrameOptions: 'DENY',
    xContentTypeOptions: 'nosniff',
    referrerPolicy: 'no-referrer',
  })
);
app.use(
  '*',
  cors({
    origin: (origin) => {
      // Sem Origin (curl/health): ok com primeira origem permitida
      if (!origin) return ALLOWED_ORIGINS[0] || '*';
      // Só ecoa a origem se estiver na allowlist (nunca devolver domínio "errado")
      return ALLOWED_ORIGINS.includes(origin) ? origin : '';
    },
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowHeaders: ['Content-Type', 'Authorization', 'X-Client-Info'],
    exposeHeaders: ['Content-Length', 'X-JSON'],
    maxAge: 86400,
  })
);

app.options('*', (c) => c.body(null, 204));

// Global error handler
app.onError((err, c) => {
  console.error('❌ [SERVER ERROR]', err);
  const status =
    err instanceof HttpError
      ? err.status
      : typeof (err as any)?.status === 'number'
        ? (err as any).status
        : String(err.message || '').toLowerCase().includes('forbidden')
          ? 403
          : String(err.message || '').toLowerCase().includes('token') ||
              String(err.message || '').toLowerCase().includes('authorization')
            ? 401
            : 500;

  if (status === 401) return c.json({ error: 'Unauthorized', code: 401 }, 401);
  if (status === 403) return c.json({ error: 'Forbidden', code: 403 }, 403);
  if (status === 429) return c.json({ error: err.message || 'Too many requests', code: 429 }, 429);
  if (status >= 400 && status < 500) {
    return c.json({ error: err.message || 'Bad request', code: status }, status as any);
  }
  return c.json({ error: 'Internal server error', code: 500 }, 500);
});

/** Authenticated user with fresh user_type from DB (not stale JWT claim). */
async function requireUser(c: any): Promise<AuthUser> {
  const tokenUser = await getAuthenticatedUser(c.req.header('Authorization'));
  const res = await query(
    'SELECT id, email, name, user_type FROM profiles WHERE id = $1 LIMIT 1',
    [tokenUser.id]
  );
  if ((res.rowCount ?? 0) === 0) {
    throw new HttpError(401, 'Invalid or expired token');
  }
  const row = res.rows[0];
  return {
    id: String(row.id),
    email: row.email,
    name: row.name,
    user_type: row.user_type,
  };
}

function requirePlatformAdmin(user: AuthUser): void {
  if (!isPlatformAdmin(user.user_type)) {
    throw new HttpError(403, 'Forbidden');
  }
}

async function getProjectRole(user: AuthUser, projectId: string): Promise<ProjectRole | null> {
  if (user.user_type === 'super_admin') return 'owner';
  const owner = await query(
    'SELECT 1 FROM projects WHERE id = $1 AND user_id::text = $2 LIMIT 1',
    [projectId, user.id]
  );
  if ((owner.rowCount ?? 0) > 0) return 'owner';
  const link = await query(
    'SELECT role FROM project_users WHERE project_id = $1 AND user_id::text = $2 LIMIT 1',
    [projectId, user.id]
  );
  if ((link.rowCount ?? 0) === 0) return null;
  const role = String(link.rows[0].role || 'viewer').toLowerCase();
  if (role === 'admin' || role === 'editor' || role === 'viewer' || role === 'owner') {
    return role as ProjectRole;
  }
  return 'viewer';
}

async function assertProjectRole(
  c: any,
  projectId: string,
  allowed: ProjectRole[]
): Promise<AuthUser> {
  const user = await requireUser(c);
  const role = await getProjectRole(user, projectId);
  if (!role || !allowed.includes(role)) {
    throw new HttpError(403, 'Forbidden: insufficient project role');
  }
  return user;
}

async function assertProjectAccess(c: any, projectId: string): Promise<AuthUser> {
  return assertProjectRole(c, projectId, ROLE_READ);
}

async function assertProjectCreate(c: any, projectId: string): Promise<AuthUser> {
  return assertProjectRole(c, projectId, ROLE_CREATE);
}

async function assertProjectWrite(c: any, projectId: string): Promise<AuthUser> {
  return assertProjectRole(c, projectId, ROLE_WRITE);
}

async function assertProjectDelete(c: any, projectId: string): Promise<AuthUser> {
  return assertProjectRole(c, projectId, ROLE_DELETE);
}

async function assertProjectManage(c: any, projectId: string): Promise<AuthUser> {
  return assertProjectRole(c, projectId, ROLE_MANAGE);
}

// Health check
app.get('/api/health', (c) => c.json({ status: 'ok', database: 'postgres' }));

// ==================== AUTH ====================

app.post('/api/auth/register', async (c) => {
  const ip = clientIp(c);
  if (!rateLimit(`register:${ip}`, 5, 15 * 60_000)) {
    return c.json({ error: 'Muitas tentativas. Tente novamente mais tarde.' }, 429);
  }

  const body = await c.req.json();
  const { name, email, password } = body;

  if (!name || !email || !password) {
    return c.json({ error: 'Nome, email e senha são obrigatórios' }, 400);
  }
  const pwErr = assertStrongPassword(password);
  if (pwErr) {
    return c.json({ error: pwErr }, 400);
  }

  const existing = await query('SELECT id FROM profiles WHERE lower(email) = lower($1) LIMIT 1', [email]);
  if ((existing.rowCount ?? 0) > 0) {
    return c.json({ error: 'Este email já está cadastrado' }, 400);
  }

  const id = randomUUID();
  const password_hash = await hashPassword(password);

  const res = await query(
    `INSERT INTO profiles (id, name, email, user_type, password_hash, created_at, updated_at)
     VALUES ($1, $2, $3, 'user', $4, NOW(), NOW())
     RETURNING id, name, email, user_type`,
    [id, name, email, password_hash]
  );

  const user = res.rows[0];
  const token = await signToken(user);
  return c.json({ token, user });
});

app.post('/api/auth/login', async (c) => {
  const ip = clientIp(c);
  if (!rateLimit(`login:${ip}`, 10, 15 * 60_000)) {
    return c.json({ error: 'Muitas tentativas. Tente novamente mais tarde.' }, 429);
  }

  const body = await c.req.json();
  const { email, password } = body;

  if (!email || !password) {
    return c.json({ error: 'Email e senha são obrigatórios' }, 400);
  }

  const res = await query(
    'SELECT id, name, email, user_type, password_hash FROM profiles WHERE lower(email) = lower($1) LIMIT 1',
    [email]
  );

  if (res.rowCount === 0) {
    return c.json({ error: 'Usuário não encontrado ou senha incorreta' }, 401);
  }

  const row = res.rows[0];
  const valid = await verifyPassword(password, row.password_hash);
  if (!valid) {
    return c.json({ error: 'Usuário não encontrado ou senha incorreta' }, 401);
  }

  const user = { id: row.id, name: row.name, email: row.email, user_type: row.user_type };
  const token = await signToken(user);
  await writeAuditLog({
    userId: user.id,
    userEmail: user.email,
    action: 'login',
    entityType: 'user',
    entityId: user.id,
    entityName: user.name,
    summary: 'Login bem-sucedido',
    ip: clientIp(c),
  });
  return c.json({ token, user });
});

app.get('/api/auth/me', async (c) => {
  const authUser = await requireUser(c);
  const res = await query('SELECT id, name, email, user_type, created_at FROM profiles WHERE id = $1 LIMIT 1', [authUser.id]);
  if (res.rowCount === 0) {
    throw new HttpError(401, 'Invalid or expired token');
  }
  return c.json(res.rows[0]);
});

app.post('/api/auth/change-password', async (c) => {
  const authUser = await requireUser(c);
  const body = await c.req.json();
  const { current_password, new_password } = body;

  if (!current_password || !new_password) {
    return c.json({ error: 'Missing required fields' }, 400);
  }
  const pwErr = assertStrongPassword(new_password);
  if (pwErr) {
    return c.json({ error: pwErr }, 400);
  }
  if (current_password === new_password) {
    return c.json({ error: 'New password must be different from current password' }, 400);
  }

  const res = await query('SELECT password_hash FROM profiles WHERE id = $1 LIMIT 1', [authUser.id]);
  if (res.rowCount === 0) {
    return c.json({ error: 'Usuário não encontrado' }, 404);
  }

  const valid = await verifyPassword(current_password, res.rows[0].password_hash);
  if (!valid) {
    return c.json({ error: 'Senha atual incorreta' }, 401);
  }

  const newHash = await hashPassword(new_password);
  await query('UPDATE profiles SET password_hash = $1, updated_at = NOW() WHERE id = $2', [newHash, authUser.id]);
  return c.json({ success: true, message: 'Password changed successfully' });
});

// ==================== PROFILE ====================

app.get('/api/profile', async (c) => {
  const authUser = await requireUser(c);
  const res = await query('SELECT id, name, email, user_type, created_at FROM profiles WHERE id = $1 LIMIT 1', [authUser.id]);
  if (res.rowCount === 0) {
    throw new HttpError(401, 'Invalid or expired token');
  }
  return c.json(res.rows[0]);
});

// ==================== USER MANAGEMENT (admin) ====================

app.get('/api/users', async (c) => {
  const user = await requireUser(c);
  if (!isPlatformAdmin(user.user_type) && user.user_type !== 'manager') {
    throw new HttpError(403, 'Forbidden');
  }
  const res = await query(
    'SELECT id, email, name, user_type, created_at, updated_at FROM profiles ORDER BY created_at DESC'
  );
  const profiles =
    user.user_type === 'manager'
      ? res.rows.filter((p: any) => canManageUserType(user.user_type, p.user_type) || p.id === user.id)
      : res.rows;
  return c.json({ profiles });
});

app.post('/api/users', async (c) => {
  const requester = await requireUser(c);
  const body = await c.req.json();
  const { email, password, name, user_type } = body;
  const creatorType = requester.user_type;
  const targetType = user_type || 'user';

  if (!email || !password || !name) {
    return c.json({ error: 'Nome, email e senha são obrigatórios' }, 400);
  }
  const pwErr = assertStrongPassword(password);
  if (pwErr) {
    return c.json({ error: pwErr }, 400);
  }
  if (!canManageUserType(creatorType, targetType)) {
    return c.json({ error: `Você não tem permissão para criar usuários do tipo "${targetType}".`, code: 403 }, 403);
  }

  const existing = await query('SELECT id FROM profiles WHERE lower(email) = lower($1) LIMIT 1', [email]);
  if ((existing.rowCount ?? 0) > 0) {
    return c.json({ error: 'Este email já está cadastrado' }, 400);
  }

  const id = randomUUID();
  const password_hash = await hashPassword(password);
  const res = await query(
    `INSERT INTO profiles (id, name, email, user_type, password_hash, created_by, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
     RETURNING id, name, email, user_type`,
    [id, name, email, targetType, password_hash, requester.id]
  );
  return c.json({ success: true, user: res.rows[0] });
});

app.put('/api/users/:id', async (c) => {
  const requester = await requireUser(c);
  const userId = c.req.param('id');
  const body = await c.req.json();
  const { email, name, user_type } = body;

  const targetRes = await query('SELECT id, user_type, email, name FROM profiles WHERE id = $1 LIMIT 1', [userId]);
  if (targetRes.rowCount === 0) {
    return c.json({ error: 'Usuário não encontrado', code: 404 }, 404);
  }
  const target = targetRes.rows[0];
  const isEditingSelf = requester.id === userId;

  if (!isEditingSelf && !canManageUserType(requester.user_type, target.user_type)) {
    return c.json({ error: 'Você não tem permissão para editar este usuário.', code: 403 }, 403);
  }

  // Users cannot change their own user_type.
  if (isEditingSelf && user_type && user_type !== target.user_type) {
    return c.json({ error: 'Você não pode alterar seu próprio tipo de usuário.', code: 403 }, 403);
  }
  // Validate hierarchy when editing others' type.
  if (!isEditingSelf && user_type && !canManageUserType(requester.user_type, user_type)) {
    return c.json({ error: `Você não tem permissão para atribuir o tipo "${user_type}".`, code: 403 }, 403);
  }

  const finalType = isEditingSelf ? target.user_type : (user_type || target.user_type);
  const finalEmail = email ?? target.email;
  const finalName = name ?? target.name;
  await query(
    'UPDATE profiles SET email = $1, name = $2, user_type = $3, updated_at = NOW() WHERE id = $4',
    [finalEmail, finalName, finalType, userId]
  );
  return c.json({ success: true });
});

app.delete('/api/users/:id', async (c) => {
  const requester = await requireUser(c);
  const userId = c.req.param('id');

  const targetRes = await query('SELECT user_type FROM profiles WHERE id = $1 LIMIT 1', [userId]);
  if (targetRes.rowCount === 0) {
    return c.json({ error: 'Usuário não encontrado' }, 404);
  }
  if (requester.id === userId) {
    return c.json({ error: 'Você não pode excluir a própria conta.', code: 403 }, 403);
  }
  if (!canManageUserType(requester.user_type, targetRes.rows[0].user_type)) {
    return c.json({ error: 'Você não tem permissão para excluir este usuário.', code: 403 }, 403);
  }

  await query('DELETE FROM project_users WHERE user_id = $1', [userId]);
  await query('DELETE FROM profiles WHERE id = $1', [userId]);
  return c.json({ success: true });
});

// List all users (admin / super_admin only).
app.get('/api/auth-users', async (c) => {
  const user = await requireUser(c);
  requirePlatformAdmin(user);
  const res = await query(
    'SELECT id, email, name, user_type, created_at FROM profiles ORDER BY created_at DESC'
  );
  return c.json({
    users: res.rows.map((u: any) => ({
      id: u.id,
      email: u.email,
      email_confirmed_at: u.created_at,
      created_at: u.created_at,
      user_metadata: { name: u.name, user_type: u.user_type },
    })),
  });
});

app.post('/api/users/:id/reset-password', async (c) => {
  const requester = await requireUser(c);
  const userId = c.req.param('id');
  const body = await c.req.json();
  const { new_password } = body;

  const pwErr = assertStrongPassword(new_password || '');
  if (pwErr) {
    return c.json({ error: pwErr }, 400);
  }

  const targetRes = await query('SELECT id, email, user_type FROM profiles WHERE id = $1 LIMIT 1', [userId]);
  if (targetRes.rowCount === 0) {
    return c.json({ error: 'Usuário não encontrado' }, 404);
  }
  if (requester.user_type !== 'super_admin' && !canManageUserType(requester.user_type, targetRes.rows[0].user_type)) {
    return c.json({ error: 'Sem permissão para redefinir a senha deste usuário.', code: 403 }, 403);
  }

  const newHash = await hashPassword(new_password);
  await query('UPDATE profiles SET password_hash = $1, updated_at = NOW() WHERE id = $2', [newHash, userId]);
  return c.json({ success: true, message: 'Password reset successfully', user: { id: targetRes.rows[0].id, email: targetRes.rows[0].email } });
});

// ==================== PROJECTS ====================

app.get('/api/projects', async (c) => {
  const user = await requireUser(c);
  const res = await query(`
    SELECT p.* FROM projects p
    WHERE p.user_id::text = $1
    OR p.id IN (SELECT project_id FROM project_users WHERE user_id::text = $1)
    ORDER BY p.created_at DESC
  `, [user.id]);
  return c.json({ projects: res.rows });
});

app.post('/api/projects', async (c) => {
  const user = await requireUser(c);
  const body = await c.req.json();
  const id = body.id || `project-${Date.now()}`;

  const res = await query(
    `INSERT INTO projects (id, name, description, powerbi_url, logo_url, logo_dark_url, user_id, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW()) RETURNING *`,
    [id, body.name, body.description || '', body.powerbi_url || '', body.logo_url || '', body.logo_dark_url || '', user.id]
  );
  return c.json(res.rows[0]);
});

app.get('/api/projects/:id', async (c) => {
  const id = c.req.param('id');
  await assertProjectAccess(c, id);
  const res = await query('SELECT * FROM projects WHERE id = $1 LIMIT 1', [id]);
  if (res.rowCount === 0) return c.json({ error: 'Project not found' }, 404);
  return c.json(res.rows[0]);
});

app.put('/api/projects/:id', async (c) => {
  const id = c.req.param('id');
  await assertProjectManage(c, id);
  const body = await c.req.json();

  const res = await query(
    `UPDATE projects SET name = $1, description = $2, powerbi_url = $3, logo_url = $4, logo_dark_url = $5, updated_at = NOW()
     WHERE id = $6 RETURNING *`,
    [body.name, body.description || '', body.powerbi_url || '', body.logo_url || '', body.logo_dark_url || '', id]
  );
  return c.json(res.rows[0]);
});

app.delete('/api/projects/:id', async (c) => {
  const user = await requireUser(c);
  const id = c.req.param('id');

  const projRes = await query('SELECT user_id FROM projects WHERE id = $1 LIMIT 1', [id]);
  if (projRes.rowCount === 0) return c.json({ error: 'Projeto não encontrado' }, 404);
  const isOwner = String(projRes.rows[0].user_id) === user.id;
  if (!isOwner && user.user_type !== 'super_admin') {
    return c.json({ error: 'Apenas o criador do projeto pode deletá-lo', code: 403 }, 403);
  }

  await query('DELETE FROM relationships WHERE project_id = $1', [id]);
  await query('DELETE FROM locations WHERE project_id = $1', [id]);
  await query('DELETE FROM activities WHERE project_id = $1', [id]);
  await query('DELETE FROM institutions WHERE project_id = $1', [id]);
  await query('DELETE FROM people WHERE project_id = $1', [id]);
  await query('DELETE FROM project_users WHERE project_id = $1', [id]);
  await query('DELETE FROM map_configurations WHERE project_id = $1', [id]);
  await query('DELETE FROM projects WHERE id = $1', [id]);

  return c.json({ success: true });
});

// ==================== PROJECT COLLABORATORS (project_users) ====================

app.get('/api/projects/:projectId/users', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);

  const puRes = await query(
    'SELECT * FROM project_users WHERE project_id = $1 ORDER BY created_at DESC',
    [projectId]
  );
  if (puRes.rowCount === 0) {
    return c.json({ success: true, users: [] });
  }

  const userIds = puRes.rows.map((r: any) => r.user_id);
  const profRes = await query(
    'SELECT id, email, name, user_type FROM profiles WHERE id = ANY($1::uuid[])',
    [userIds]
  );
  const profMap = new Map(profRes.rows.map((p: any) => [String(p.id), p]));

  const linkedByIds = puRes.rows.map((r: any) => r.linked_by).filter((x: any) => x);
  let linkedByMap = new Map<string, any>();
  if (linkedByIds.length > 0) {
    const lbRes = await query('SELECT id, email FROM profiles WHERE id = ANY($1::uuid[])', [linkedByIds]);
    linkedByMap = new Map(lbRes.rows.map((p: any) => [String(p.id), p]));
  }

  const users = puRes.rows.map((item: any) => {
    const prof = profMap.get(String(item.user_id));
    const lb = item.linked_by ? linkedByMap.get(String(item.linked_by)) : null;
    return {
      id: item.id,
      project_id: item.project_id,
      user_id: item.user_id,
      role: item.role,
      linked_by: item.linked_by,
      created_at: item.created_at,
      user_email: prof?.email || '',
      user_name: prof?.name || '',
      user_type: prof?.user_type || '',
      linked_by_email: lb?.email || '',
    };
  });

  return c.json({ success: true, users });
});

app.get('/api/projects/:projectId/available-users', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectManage(c, projectId);

  const allProfiles = await query('SELECT id, email, name, user_type FROM profiles ORDER BY name ASC');
  const linked = await query('SELECT user_id FROM project_users WHERE project_id = $1', [projectId]);
  const project = await query('SELECT user_id FROM projects WHERE id = $1 LIMIT 1', [projectId]);

  const linkedIds = new Set(linked.rows.map((r: any) => String(r.user_id)));
  const ownerId = project.rowCount ? String(project.rows[0].user_id) : null;

  const available = allProfiles.rows.filter((p: any) => {
    if (String(p.id) === ownerId) return false;
    if (linkedIds.has(String(p.id))) return false;
    return true;
  });

  return c.json({ success: true, users: available, count: available.length });
});

app.post('/api/projects/:projectId/users', async (c) => {
  const projectId = c.req.param('projectId');
  const requester = await assertProjectManage(c, projectId);
  const body = await c.req.json();
  const { user_id, role } = body;

  if (!user_id || !role) {
    return c.json({ error: 'user_id and role are required' }, 400);
  }

  const existing = await query(
    'SELECT id FROM project_users WHERE project_id = $1 AND user_id = $2 LIMIT 1',
    [projectId, user_id]
  );
  if ((existing.rowCount ?? 0) > 0) {
    return c.json({ error: 'Usuário já está vinculado a este projeto' }, 400);
  }

  const res = await query(
    `INSERT INTO project_users (project_id, user_id, role, linked_by, created_at)
     VALUES ($1, $2, $3, $4, NOW()) RETURNING *`,
    [projectId, user_id, role, requester.id]
  );
  return c.json({ success: true, projectUser: res.rows[0] });
});

app.put('/api/projects/:projectId/users/:linkId', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectManage(c, projectId);
  const linkId = c.req.param('linkId');
  const body = await c.req.json();

  const res = await query(
    'UPDATE project_users SET role = $1 WHERE id = $2 AND project_id = $3 RETURNING *',
    [body.role, linkId, projectId]
  );
  if (res.rowCount === 0) return c.json({ error: 'Vínculo não encontrado' }, 404);
  return c.json({ success: true, projectUser: res.rows[0] });
});

app.delete('/api/projects/:projectId/users/:linkId', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectManage(c, projectId);
  const linkId = c.req.param('linkId');
  await query('DELETE FROM project_users WHERE id = $1 AND project_id = $2', [linkId, projectId]);
  return c.json({ success: true });
});


// ==================== MAP FRONTS (índice dinâmico) ====================

const DEFAULT_MAP_FRONTS = [
  { slug: 'politicos', label: 'Políticos', short_label: 'Políticos', description: 'Deputados, senadores e atores políticos', color: '#10B981', icon: 'users', sort_order: 1, critical: false },
  { slug: 'policia', label: 'Polícia / Segurança', short_label: 'Polícia', description: 'Forças de segurança e postos militares', color: '#3B82F6', icon: 'shield', sort_order: 2, critical: false },
  { slug: 'fazendeiros', label: 'Fazendeiros', short_label: 'Fazendas', description: 'Propriedades e produtores rurais', color: '#F59E0B', icon: 'farm', sort_order: 3, critical: false },
  { slug: 'eventos', label: 'Eventos / Ações', short_label: 'Eventos', description: 'Atividades, ocorrências e ações', color: '#EF4444', icon: 'alert', sort_order: 4, critical: true },
  { slug: 'lcp_acampamentos', label: 'LCP / Acampamentos', short_label: 'LCP', description: 'Acampamentos, LCP e movimentos', color: '#84CC16', icon: 'tent', sort_order: 5, critical: false },
  { slug: 'governo_justica', label: 'Governo / Justiça', short_label: 'Governo', description: 'Órgãos públicos, MPF, tribunais', color: '#8B5CF6', icon: 'building', sort_order: 6, critical: false },
  { slug: 'outros', label: 'Outros', short_label: 'Outros', description: 'Demais atores do projeto', color: '#64748B', icon: 'more', sort_order: 99, critical: false },
];

async function ensureDefaultMapFronts(projectId: string) {
  const existing = await query(
    'SELECT id FROM map_fronts WHERE project_id = $1 LIMIT 1',
    [projectId]
  );
  if ((existing.rowCount ?? 0) > 0) return;

  for (const f of DEFAULT_MAP_FRONTS) {
    const id = `front-${projectId}-${f.slug}`;
    await query(
      `INSERT INTO map_fronts (id, project_id, slug, label, short_label, description, color, icon, sort_order, critical, is_active, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true, NOW(), NOW())
       ON CONFLICT (project_id, slug) DO NOTHING`,
      [id, projectId, f.slug, f.label, f.short_label, f.description, f.color, f.icon, f.sort_order, f.critical]
    );
  }
}

app.get('/api/projects/:projectId/map-fronts', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);
  await ensureDefaultMapFronts(projectId);
  const res = await query(
    `SELECT * FROM map_fronts WHERE project_id = $1 AND is_active = true ORDER BY sort_order ASC, label ASC`,
    [projectId]
  );
  return c.json(res.rows);
});

app.post('/api/projects/:projectId/map-fronts', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectManage(c, projectId);
  const body = await c.req.json();
  const label = String(body.label || '').trim();
  if (!label) return c.json({ error: 'label is required' }, 400);

  const slugBase = String(body.slug || label)
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_|_$/g, '')
    .slice(0, 60) || `frente_${Date.now()}`;

  const id = body.id || `front-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const res = await query(
    `INSERT INTO map_fronts (id, project_id, slug, label, short_label, description, color, icon, sort_order, critical, is_active, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true, NOW(), NOW()) RETURNING *`,
    [
      id,
      projectId,
      slugBase,
      label,
      body.short_label || label,
      body.description || '',
      body.color || '#64748B',
      body.icon || 'more',
      body.sort_order ?? 50,
      Boolean(body.critical),
    ]
  );
  return c.json(res.rows[0]);
});

app.put('/api/projects/:projectId/map-fronts/:id', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectManage(c, projectId);
  const id = c.req.param('id');
  const body = await c.req.json();
  const res = await query(
    `UPDATE map_fronts SET
       label = COALESCE($1, label),
       short_label = COALESCE($2, short_label),
       description = COALESCE($3, description),
       color = COALESCE($4, color),
       icon = COALESCE($5, icon),
       sort_order = COALESCE($6, sort_order),
       critical = COALESCE($7, critical),
       is_active = COALESCE($8, is_active),
       updated_at = NOW()
     WHERE id = $9 AND project_id = $10 RETURNING *`,
    [
      body.label ?? null,
      body.short_label ?? null,
      body.description ?? null,
      body.color ?? null,
      body.icon ?? null,
      body.sort_order ?? null,
      typeof body.critical === 'boolean' ? body.critical : null,
      typeof body.is_active === 'boolean' ? body.is_active : null,
      id,
      projectId,
    ]
  );
  if (res.rowCount === 0) return c.json({ error: 'Frente não encontrada' }, 404);
  return c.json(res.rows[0]);
});

app.delete('/api/projects/:projectId/map-fronts/:id', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectManage(c, projectId);
  const id = c.req.param('id');
  // Soft-delete keeps FK history; ON DELETE SET NULL also handles hard delete.
  await query(
    'UPDATE map_fronts SET is_active = false, updated_at = NOW() WHERE id = $1 AND project_id = $2',
    [id, projectId]
  );
  return c.json({ success: true });
});

// ==================== PEOPLE ====================

app.get('/api/projects/:projectId/people', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);
  const res = await query('SELECT * FROM people WHERE project_id = $1 ORDER BY name ASC', [projectId]);
  return c.json(res.rows);
});

app.post('/api/projects/:projectId/people', async (c) => {
  const projectId = c.req.param('projectId');
  const actor = await assertProjectCreate(c, projectId);
  const body = await c.req.json();
  const id = body.id || `person-${Date.now()}`;

  const res = await query(
    `INSERT INTO people (id, project_id, name, role, institution, email, phone, notes, image_url, instagram, facebook, tiktok, linkedin, website, x, y, latitude, longitude, map_front_id, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, NOW(), NOW()) RETURNING *`,
    [id, projectId, body.name, body.role || '', body.institution || '', body.email || '', body.phone || '', body.notes || '', body.image_url || '', body.instagram || '', body.facebook || '', body.tiktok || '', body.linkedin || '', body.website || '', body.x || 0, body.y || 0, body.latitude ?? null, body.longitude ?? null, body.map_front_id || null]
  );
  await writeAuditLog({
    projectId,
    userId: actor.id,
    userEmail: actor.email,
    action: 'create',
    entityType: 'person',
    entityId: res.rows[0].id,
    entityName: res.rows[0].name,
    summary: `Pessoa criada: ${res.rows[0].name}`,
    afterData: { id: res.rows[0].id, name: res.rows[0].name },
    ip: clientIp(c),
  });
  return c.json(res.rows[0]);
});

app.put('/api/projects/:projectId/people/:id', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectWrite(c, projectId);
  const id = c.req.param('id');
  const body = await c.req.json();

  const res = await query(
    `UPDATE people SET name = $1, role = $2, institution = $3, email = $4, phone = $5, notes = $6, image_url = $7, instagram = $8, facebook = $9, tiktok = $10, linkedin = $11, website = $12, x = $13, y = $14, latitude = $15, longitude = $16, map_front_id = $17, updated_at = NOW()
     WHERE id = $18 AND project_id = $19 RETURNING *`,
    [body.name, body.role || '', body.institution || '', body.email || '', body.phone || '', body.notes || '', body.image_url || '', body.instagram || '', body.facebook || '', body.tiktok || '', body.linkedin || '', body.website || '', body.x || 0, body.y || 0, body.latitude ?? null, body.longitude ?? null, body.map_front_id || null, id, projectId]
  );
  return c.json(res.rows[0]);
});

app.delete('/api/projects/:projectId/people/:id', async (c) => {
  const projectId = c.req.param('projectId');
  const actor = await assertProjectDelete(c, projectId);
  const id = c.req.param('id');
  const before = await query('SELECT id, name FROM people WHERE id = $1 AND project_id = $2', [id, projectId]);
  await query('DELETE FROM relationships WHERE project_id = $1 AND (source_id = $2 OR target_id = $2)', [projectId, id]);
  await query('DELETE FROM people WHERE id = $1 AND project_id = $2', [id, projectId]);
  if (before.rows[0]) {
    await writeAuditLog({
      projectId,
      userId: actor.id,
      userEmail: actor.email,
      action: 'delete',
      entityType: 'person',
      entityId: id,
      entityName: before.rows[0].name,
      summary: `Pessoa removida: ${before.rows[0].name}`,
      beforeData: before.rows[0],
      ip: clientIp(c),
    });
  }
  return c.json({ success: true });
});

// ==================== INSTITUTIONS ====================

app.get('/api/projects/:projectId/institutions', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);
  const res = await query('SELECT * FROM institutions WHERE project_id = $1 ORDER BY name ASC', [projectId]);
  return c.json(res.rows);
});

app.post('/api/projects/:projectId/institutions', async (c) => {
  const projectId = c.req.param('projectId');
  const actor = await assertProjectCreate(c, projectId);
  const body = await c.req.json();
  const id = body.id || `institution-${Date.now()}`;

  const res = await query(
    `INSERT INTO institutions (id, project_id, name, type, description, contact, address, cnpj, fantasy_name, instagram, facebook, tiktok, linkedin, website, image_url, x, y, latitude, longitude, map_front_id, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, NOW(), NOW()) RETURNING *`,
    [id, projectId, body.name, body.type || '', body.description || '', body.contact || '', body.address || '', body.cnpj || '', body.fantasy_name || '', body.instagram || '', body.facebook || '', body.tiktok || '', body.linkedin || '', body.website || '', body.image_url || '', body.x || 0, body.y || 0, body.latitude ?? null, body.longitude ?? null, body.map_front_id || null]
  );
  await writeAuditLog({
    projectId,
    userId: actor.id,
    userEmail: actor.email,
    action: 'create',
    entityType: 'institution',
    entityId: res.rows[0].id,
    entityName: res.rows[0].name,
    summary: `Organização criada: ${res.rows[0].name}`,
    afterData: { id: res.rows[0].id, name: res.rows[0].name },
    ip: clientIp(c),
  });
  return c.json(res.rows[0]);
});

app.put('/api/projects/:projectId/institutions/:id', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectWrite(c, projectId);
  const id = c.req.param('id');
  const body = await c.req.json();

  const res = await query(
    `UPDATE institutions SET name = $1, type = $2, description = $3, contact = $4, address = $5, cnpj = $6, fantasy_name = $7, instagram = $8, facebook = $9, tiktok = $10, linkedin = $11, website = $12, image_url = $13, x = $14, y = $15, latitude = $16, longitude = $17, map_front_id = $18, updated_at = NOW()
     WHERE id = $19 AND project_id = $20 RETURNING *`,
    [body.name, body.type || '', body.description || '', body.contact || '', body.address || '', body.cnpj || '', body.fantasy_name || '', body.instagram || '', body.facebook || '', body.tiktok || '', body.linkedin || '', body.website || '', body.image_url || '', body.x || 0, body.y || 0, body.latitude ?? null, body.longitude ?? null, body.map_front_id || null, id, projectId]
  );
  return c.json(res.rows[0]);
});

app.delete('/api/projects/:projectId/institutions/:id', async (c) => {
  const projectId = c.req.param('projectId');
  const actor = await assertProjectDelete(c, projectId);
  const id = c.req.param('id');
  const before = await query('SELECT id, name FROM institutions WHERE id = $1 AND project_id = $2', [id, projectId]);
  await query('DELETE FROM relationships WHERE project_id = $1 AND (source_id = $2 OR target_id = $2)', [projectId, id]);
  await query('DELETE FROM institutions WHERE id = $1 AND project_id = $2', [id, projectId]);
  if (before.rows[0]) {
    await writeAuditLog({
      projectId,
      userId: actor.id,
      userEmail: actor.email,
      action: 'delete',
      entityType: 'institution',
      entityId: id,
      entityName: before.rows[0].name,
      summary: `Organização removida: ${before.rows[0].name}`,
      beforeData: before.rows[0],
      ip: clientIp(c),
    });
  }
  return c.json({ success: true });
});

// ==================== ACTIVITIES ====================

app.get('/api/projects/:projectId/activities', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);
  const res = await query('SELECT * FROM activities WHERE project_id = $1 ORDER BY name ASC', [projectId]);
  return c.json(res.rows);
});

app.post('/api/projects/:projectId/activities', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectCreate(c, projectId);
  const body = await c.req.json();
  const id = body.id || `activity-${Date.now()}`;

  const res = await query(
    `INSERT INTO activities (id, project_id, name, description, start_date, end_date, status, location, image_url, latitude, longitude, map_front_id, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW()) RETURNING *`,
    [id, projectId, body.name, body.description || '', body.start_date || null, body.end_date || null, body.status || '', body.location || '', body.image_url || '', body.latitude ?? null, body.longitude ?? null, body.map_front_id || null]
  );
  return c.json(res.rows[0]);
});

app.put('/api/projects/:projectId/activities/:id', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectWrite(c, projectId);
  const id = c.req.param('id');
  const body = await c.req.json();

  const res = await query(
    `UPDATE activities SET name = $1, description = $2, start_date = $3, end_date = $4, status = $5, location = $6, image_url = $7, latitude = $8, longitude = $9, map_front_id = $10, updated_at = NOW()
     WHERE id = $11 AND project_id = $12 RETURNING *`,
    [body.name, body.description || '', body.start_date || null, body.end_date || null, body.status || '', body.location || '', body.image_url || '', body.latitude ?? null, body.longitude ?? null, body.map_front_id || null, id, projectId]
  );
  return c.json(res.rows[0]);
});

app.delete('/api/projects/:projectId/activities/:id', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectDelete(c, projectId);
  const id = c.req.param('id');
  await query('DELETE FROM relationships WHERE project_id = $1 AND (source_id = $2 OR target_id = $2)', [projectId, id]);
  await query('DELETE FROM activities WHERE id = $1 AND project_id = $2', [id, projectId]);
  return c.json({ success: true });
});

// ==================== LOCATIONS ====================

app.get('/api/projects/:projectId/locations', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);
  const res = await query('SELECT * FROM locations WHERE project_id = $1 ORDER BY name ASC', [projectId]);
  return c.json(res.rows);
});

app.post('/api/projects/:projectId/locations', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectCreate(c, projectId);
  const body = await c.req.json();
  const id = body.id || `location-${Date.now()}`;

  const res = await query(
    `INSERT INTO locations (id, project_id, name, address, latitude, longitude, google_maps_url, image_url, x, y, map_front_id, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW()) RETURNING *`,
    [id, projectId, body.name, body.address || '', body.latitude || null, body.longitude || null, body.google_maps_url || '', body.image_url || '', body.x || 0, body.y || 0, body.map_front_id || null]
  );
  return c.json(res.rows[0]);
});

app.put('/api/projects/:projectId/locations/:id', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectWrite(c, projectId);
  const id = c.req.param('id');
  const body = await c.req.json();

  const res = await query(
    `UPDATE locations SET name = $1, address = $2, latitude = $3, longitude = $4, google_maps_url = $5, image_url = $6, x = $7, y = $8, map_front_id = $9, updated_at = NOW()
     WHERE id = $10 AND project_id = $11 RETURNING *`,
    [body.name, body.address || '', body.latitude || null, body.longitude || null, body.google_maps_url || '', body.image_url || '', body.x || 0, body.y || 0, body.map_front_id || null, id, projectId]
  );
  return c.json(res.rows[0]);
});

app.delete('/api/projects/:projectId/locations/:id', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectDelete(c, projectId);
  const id = c.req.param('id');
  await query('DELETE FROM relationships WHERE project_id = $1 AND (source_id = $2 OR target_id = $2)', [projectId, id]);
  await query('DELETE FROM locations WHERE id = $1 AND project_id = $2', [id, projectId]);
  return c.json({ success: true });
});

// ==================== RELATIONSHIPS ====================

app.get('/api/projects/:projectId/relationships', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);
  const res = await query('SELECT * FROM relationships WHERE project_id = $1', [projectId]);
  return c.json(res.rows);
});

app.post('/api/projects/:projectId/relationships', async (c) => {
  const projectId = c.req.param('projectId');
  const actor = await assertProjectCreate(c, projectId);
  const body = await c.req.json();
  const id = body.id || `relationship-${Date.now()}`;

  const res = await query(
    `INSERT INTO relationships (id, project_id, source_id, target_id, source_type, target_type, type, level, description, strength, image_url, source, confidence, start_date, end_date, documents, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW(), NOW()) RETURNING *`,
    [id, projectId, body.source_id, body.target_id, body.source_type, body.target_type, body.type, body.level || '', body.description || '', body.strength || 1, body.image_url || '', body.source || '', body.confidence || '', body.start_date || null, body.end_date || null, JSON.stringify(body.documents ?? [])]
  );
  await writeAuditLog({
    projectId,
    userId: actor.id,
    userEmail: actor.email,
    action: 'create',
    entityType: 'relationship',
    entityId: res.rows[0].id,
    entityName: `${body.source_id}→${body.target_id}`,
    summary: `Vínculo criado (${body.type || 'NEUTRO'})`,
    afterData: { id: res.rows[0].id, type: body.type, source_id: body.source_id, target_id: body.target_id },
    ip: clientIp(c),
  });
  return c.json(res.rows[0]);
});

app.put('/api/projects/:projectId/relationships/:id', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectWrite(c, projectId);
  const id = c.req.param('id');
  const body = await c.req.json();

  const res = await query(
    `UPDATE relationships SET source_id = $1, target_id = $2, source_type = $3, target_type = $4, type = $5, level = $6, description = $7, strength = $8, image_url = $9, source = $10, confidence = $11, start_date = $12, end_date = $13, documents = $14, updated_at = NOW()
     WHERE id = $15 AND project_id = $16 RETURNING *`,
    [body.source_id, body.target_id, body.source_type, body.target_type, body.type, body.level || '', body.description || '', body.strength || 1, body.image_url || '', body.source || '', body.confidence || '', body.start_date || null, body.end_date || null, JSON.stringify(body.documents ?? []), id, projectId]
  );
  return c.json(res.rows[0]);
});

app.delete('/api/projects/:projectId/relationships/:id', async (c) => {
  const projectId = c.req.param('projectId');
  const actor = await assertProjectDelete(c, projectId);
  const id = c.req.param('id');
  const before = await query(
    'SELECT id, source_id, target_id, type FROM relationships WHERE id = $1 AND project_id = $2',
    [id, projectId]
  );
  await query('DELETE FROM relationships WHERE id = $1 AND project_id = $2', [id, projectId]);
  if (before.rows[0]) {
    await writeAuditLog({
      projectId,
      userId: actor.id,
      userEmail: actor.email,
      action: 'delete',
      entityType: 'relationship',
      entityId: id,
      entityName: `${before.rows[0].source_id}→${before.rows[0].target_id}`,
      summary: `Vínculo removido (${before.rows[0].type || ''})`,
      beforeData: before.rows[0],
      ip: clientIp(c),
    });
  }
  return c.json({ success: true });
});

// Fix relationships typed "POSITIVA" -> "POSITIVO".
app.post('/api/projects/:projectId/relationships/fix-types', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectWrite(c, projectId);
  const res = await query(
    `UPDATE relationships SET type = 'POSITIVO', updated_at = NOW()
     WHERE project_id = $1 AND type ILIKE 'POSITIVA' RETURNING id`,
    [projectId]
  );
  const corrected = res.rowCount ?? 0;
  return c.json({ success: true, corrected, message: `Corrigidos ${corrected} relacionamento(s) de "POSITIVA" para "POSITIVO"` });
});

// ==================== MAP CONFIGURATIONS ====================

app.get('/api/map-configurations', async (c) => {
  const projectId = c.req.query('projectId');
  if (!projectId) return c.json({ error: 'projectId is required' }, 400);
  const user = await assertProjectAccess(c, projectId);
  const res = await query(
    'SELECT * FROM map_configurations WHERE user_id = $1 AND project_id = $2 ORDER BY updated_at DESC',
    [user.id, projectId]
  );
  return c.json({ data: res.rows });
});

app.get('/api/map-configurations/default', async (c) => {
  const projectId = c.req.query('projectId');
  if (!projectId) return c.json({ error: 'projectId is required' }, 400);
  const user = await assertProjectAccess(c, projectId);
  const res = await query(
    'SELECT * FROM map_configurations WHERE user_id = $1 AND project_id = $2 AND is_default = true LIMIT 1',
    [user.id, projectId]
  );
  return c.json({ data: res.rowCount ? res.rows[0] : null });
});

app.post('/api/map-configurations', async (c) => {
  const body = await c.req.json();
  if (!body.project_id && !body.id) {
    return c.json({ error: 'project_id is required' }, 400);
  }

  const common = {
    template_name: body.template_name,
    is_template: body.is_template || false,
    is_default: body.is_default || false,
    view_state: JSON.stringify(body.view_state ?? {}),
    settings: JSON.stringify(body.settings ?? {}),
    entity_positions: JSON.stringify(body.entity_positions ?? []),
    filter_settings: body.filter_settings ? JSON.stringify(body.filter_settings) : null,
  };

  if (body.id) {
    const existing = await query(
      'SELECT project_id FROM map_configurations WHERE id = $1 LIMIT 1',
      [body.id]
    );
    if ((existing.rowCount ?? 0) === 0) {
      return c.json({ error: 'Configuração não encontrada' }, 404);
    }
    const user = await assertProjectWrite(c, existing.rows[0].project_id);
    const res = await query(
      `UPDATE map_configurations SET template_name = $1, is_template = $2, is_default = $3,
        view_state = $4, settings = $5, entity_positions = $6, filter_settings = $7, updated_at = NOW()
       WHERE id = $8 AND user_id = $9 RETURNING *`,
      [common.template_name, common.is_template, common.is_default, common.view_state, common.settings, common.entity_positions, common.filter_settings, body.id, user.id]
    );
    if (res.rowCount === 0) return c.json({ error: 'Configuração não encontrada' }, 404);
    return c.json({ data: res.rows[0] });
  }

  const user = await assertProjectWrite(c, body.project_id);
  const res = await query(
    `INSERT INTO map_configurations (user_id, project_id, template_name, is_template, is_default, view_state, settings, entity_positions, filter_settings, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW()) RETURNING *`,
    [user.id, body.project_id, common.template_name, common.is_template, common.is_default, common.view_state, common.settings, common.entity_positions, common.filter_settings]
  );
  return c.json({ data: res.rows[0] });
});

app.post('/api/map-configurations/set-default', async (c) => {
  const body = await c.req.json();
  const { configId, projectId } = body;
  if (!projectId || !configId) {
    return c.json({ error: 'configId and projectId are required' }, 400);
  }
  const user = await assertProjectWrite(c, projectId);
  await query('UPDATE map_configurations SET is_default = false WHERE user_id = $1 AND project_id = $2', [user.id, projectId]);
  await query('UPDATE map_configurations SET is_default = true WHERE id = $1 AND user_id = $2 AND project_id = $3', [configId, user.id, projectId]);
  return c.json({ success: true });
});

app.put('/api/map-configurations/:id/positions', async (c) => {
  const id = c.req.param('id');
  const body = await c.req.json();
  const existing = await query(
    'SELECT project_id, user_id FROM map_configurations WHERE id = $1 LIMIT 1',
    [id]
  );
  if ((existing.rowCount ?? 0) === 0) {
    return c.json({ error: 'Configuração não encontrada' }, 404);
  }
  const user = await assertProjectWrite(c, existing.rows[0].project_id);
  if (String(existing.rows[0].user_id) !== user.id && user.user_type !== 'super_admin') {
    // Positions are per-user configs; only owner of the row (or super_admin) may update.
    return c.json({ error: 'Forbidden' }, 403);
  }
  await query(
    'UPDATE map_configurations SET entity_positions = $1, updated_at = NOW() WHERE id = $2 AND user_id = $3',
    [JSON.stringify(body.positions ?? []), id, user.id]
  );
  return c.json({ success: true });
});

app.delete('/api/map-configurations/:id', async (c) => {
  const id = c.req.param('id');
  const existing = await query(
    'SELECT project_id, user_id FROM map_configurations WHERE id = $1 LIMIT 1',
    [id]
  );
  if ((existing.rowCount ?? 0) === 0) {
    return c.json({ success: true });
  }
  const user = await assertProjectWrite(c, existing.rows[0].project_id);
  await query('DELETE FROM map_configurations WHERE id = $1 AND user_id = $2', [id, user.id]);
  return c.json({ success: true });
});


// ==================== GEOGRAPHIC / TERRITÓRIO ====================

function isValidGeoCoord(lat: any, lng: any): boolean {
  const la = Number(lat);
  const lo = Number(lng);
  if (!Number.isFinite(la) || !Number.isFinite(lo)) return false;
  if (la < -90 || la > 90 || lo < -180 || lo > 180) return false;
  return true;
}

function haversineMeters(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371000;
  const toRad = (d: number) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}

app.get('/api/projects/:projectId/geographic/entities', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);

  const [people, institutions, activities, locations, assets] = await Promise.all([
    query('SELECT * FROM people WHERE project_id = $1', [projectId]),
    query('SELECT * FROM institutions WHERE project_id = $1', [projectId]),
    query('SELECT * FROM activities WHERE project_id = $1', [projectId]),
    query('SELECT * FROM locations WHERE project_id = $1', [projectId]),
    query('SELECT * FROM project_assets WHERE project_id = $1', [projectId]).catch(() => ({ rows: [] as any[] })),
  ]);

  const mapRow = (type: string, row: any) => ({
    id: row.id,
    type,
    name: row.name,
    latitude: row.latitude != null ? Number(row.latitude) : null,
    longitude: row.longitude != null ? Number(row.longitude) : null,
    address: row.address || row.location || null,
    meta: row,
  });

  const entities = [
    ...people.rows.map((r: any) => mapRow('person', r)),
    ...institutions.rows.map((r: any) => mapRow('institution', r)),
    ...activities.rows.map((r: any) => mapRow('activity', r)),
    ...locations.rows.map((r: any) => mapRow('location', r)),
    ...(assets.rows || []).map((r: any) => mapRow('asset', r)),
  ];

  return c.json({
    entities,
    geolocated: entities.filter((e) => isValidGeoCoord(e.latitude, e.longitude)),
  });
});

app.get('/api/projects/:projectId/geographic/summary', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);

  const [people, institutions, activities, locations, relationships] = await Promise.all([
    query('SELECT id, name, latitude, longitude FROM people WHERE project_id = $1', [projectId]),
    query('SELECT id, name, latitude, longitude FROM institutions WHERE project_id = $1', [projectId]),
    query('SELECT id, name, latitude, longitude FROM activities WHERE project_id = $1', [projectId]),
    query('SELECT id, name, latitude, longitude FROM locations WHERE project_id = $1', [projectId]),
    query('SELECT * FROM relationships WHERE project_id = $1', [projectId]),
  ]);

  const classify = (rows: any[]) => {
    const withGeo = rows.filter((r) => isValidGeoCoord(r.latitude, r.longitude));
    const without = rows.filter((r) => !isValidGeoCoord(r.latitude, r.longitude));
    return { total: rows.length, withGeo: withGeo.length, withoutGeo: without.length, missing: without.map((r) => ({ id: r.id, name: r.name })) };
  };

  const p = classify(people.rows);
  const i = classify(institutions.rows);
  const a = classify(activities.rows);
  const l = classify(locations.rows);

  const geoIds = new Set(
    [...people.rows, ...institutions.rows, ...activities.rows, ...locations.rows]
      .filter((r) => isValidGeoCoord(r.latitude, r.longitude))
      .map((r) => r.id)
  );

  const relationshipsGeolocated = relationships.rows.filter(
    (r: any) => geoIds.has(r.source_id) && geoIds.has(r.target_id)
  ).length;

  return c.json({
    people: p,
    institutions: i,
    activities: a,
    locations: l,
    totals: {
      entities: p.total + i.total + a.total + l.total,
      geolocated: p.withGeo + i.withGeo + a.withGeo + l.withGeo,
      missing: p.withoutGeo + i.withoutGeo + a.withoutGeo + l.withoutGeo,
      relationships: relationships.rows.length,
      relationshipsGeolocated,
    },
  });
});

app.get('/api/projects/:projectId/geographic/relationships', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);

  const [rels, people, institutions, activities, locations] = await Promise.all([
    query('SELECT * FROM relationships WHERE project_id = $1', [projectId]),
    query('SELECT id, name, latitude, longitude FROM people WHERE project_id = $1', [projectId]),
    query('SELECT id, name, latitude, longitude FROM institutions WHERE project_id = $1', [projectId]),
    query('SELECT id, name, latitude, longitude FROM activities WHERE project_id = $1', [projectId]),
    query('SELECT id, name, latitude, longitude FROM locations WHERE project_id = $1', [projectId]),
  ]);

  const byId = new Map<string, any>();
  for (const row of [...people.rows, ...institutions.rows, ...activities.rows, ...locations.rows]) {
    byId.set(row.id, row);
  }

  const edges = rels.rows
    .map((r: any) => {
      const s = byId.get(r.source_id);
      const t = byId.get(r.target_id);
      if (!s || !t) return null;
      if (!isValidGeoCoord(s.latitude, s.longitude) || !isValidGeoCoord(t.latitude, t.longitude)) return null;
      return {
        id: r.id,
        type: r.type,
        level: r.level,
        confidence: r.confidence,
        source: r.source,
        start_date: r.start_date,
        end_date: r.end_date,
        from: { id: s.id, name: s.name, latitude: Number(s.latitude), longitude: Number(s.longitude) },
        to: { id: t.id, name: t.name, latitude: Number(t.latitude), longitude: Number(t.longitude) },
      };
    })
    .filter(Boolean);

  return c.json({ relationships: edges });
});

app.get('/api/projects/:projectId/geographic/nearby', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);

  const lat = Number(c.req.query('lat'));
  const lng = Number(c.req.query('lng'));
  const radiusMeters = Number(c.req.query('radiusMeters') || 5000);

  if (!isValidGeoCoord(lat, lng)) {
    return c.json({ error: 'lat/lng inválidos' }, 400);
  }
  if (!Number.isFinite(radiusMeters) || radiusMeters <= 0 || radiusMeters > 100000) {
    return c.json({ error: 'radiusMeters inválido' }, 400);
  }

  const [people, institutions, activities, locations] = await Promise.all([
    query('SELECT id, name, role, institution, latitude, longitude FROM people WHERE project_id = $1', [projectId]),
    query('SELECT id, name, type, address, latitude, longitude FROM institutions WHERE project_id = $1', [projectId]),
    query('SELECT id, name, status, location, latitude, longitude FROM activities WHERE project_id = $1', [projectId]),
    query('SELECT id, name, address, latitude, longitude FROM locations WHERE project_id = $1', [projectId]),
  ]);

  const collect = (type: string, rows: any[]) =>
    rows
      .filter((r) => isValidGeoCoord(r.latitude, r.longitude))
      .map((r) => {
        const distanceMeters = haversineMeters(lat, lng, Number(r.latitude), Number(r.longitude));
        return { type, id: r.id, name: r.name, latitude: Number(r.latitude), longitude: Number(r.longitude), distanceMeters, meta: r };
      })
      .filter((r) => r.distanceMeters <= radiusMeters)
      .sort((a, b) => a.distanceMeters - b.distanceMeters);

  const results = [
    ...collect('person', people.rows),
    ...collect('institution', institutions.rows),
    ...collect('activity', activities.rows),
    ...collect('location', locations.rows),
  ].sort((a, b) => a.distanceMeters - b.distanceMeters);

  return c.json({
    center: { lat, lng },
    radiusMeters,
    count: results.length,
    results,
  });
});

app.patch('/api/projects/:projectId/geographic/:entityType/:id', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectWrite(c, projectId);
  const entityType = c.req.param('entityType');
  const id = c.req.param('id');
  const body = await c.req.json();

  const tableByType: Record<string, string> = {
    person: 'people',
    people: 'people',
    institution: 'institutions',
    institutions: 'institutions',
    activity: 'activities',
    activities: 'activities',
    location: 'locations',
    locations: 'locations',
  };
  const table = tableByType[entityType];
  if (!table) return c.json({ error: 'entityType inválido' }, 400);

  let latitude = body.latitude;
  let longitude = body.longitude;

  if (latitude === '' || latitude === undefined) latitude = null;
  if (longitude === '' || longitude === undefined) longitude = null;

  if (latitude != null || longitude != null) {
    if (!isValidGeoCoord(latitude, longitude)) {
      return c.json({ error: 'Coordenadas geográficas inválidas' }, 400);
    }
  }

  const res = await query(
    `UPDATE ${table} SET latitude = $1, longitude = $2, updated_at = NOW() WHERE id = $3 AND project_id = $4 RETURNING *`,
    [latitude, longitude, id, projectId]
  );
  if (!res.rows[0]) return c.json({ error: 'Entidade não encontrada' }, 404);
  return c.json(res.rows[0]);
});


// ==================== FASE D — ASSETS / EVIDENCES / COMMUNICATIONS / AUDIT ====================

app.get('/api/projects/:projectId/assets', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);
  const res = await query(
    'SELECT * FROM project_assets WHERE project_id = $1 ORDER BY name ASC',
    [projectId]
  );
  return c.json(res.rows);
});

app.post('/api/projects/:projectId/assets', async (c) => {
  const projectId = c.req.param('projectId');
  const actor = await assertProjectCreate(c, projectId);
  const body = await c.req.json();
  if (!body?.name || typeof body.name !== 'string') {
    return c.json({ error: 'name is required' }, 400);
  }
  const id = body.id || `asset-${Date.now()}`;
  const res = await query(
    `INSERT INTO project_assets (
       id, project_id, name, asset_type, status, description, owner_entity_id, location_id,
       latitude, longitude, image_url, metadata, created_at, updated_at
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,NOW(),NOW()) RETURNING *`,
    [
      id,
      projectId,
      body.name.trim(),
      body.asset_type || 'outro',
      body.status || 'ativo',
      body.description || '',
      body.owner_entity_id || null,
      body.location_id || null,
      body.latitude ?? null,
      body.longitude ?? null,
      body.image_url || '',
      JSON.stringify(body.metadata ?? {}),
    ]
  );
  await writeAuditLog({
    projectId,
    userId: actor.id,
    userEmail: actor.email,
    action: 'create',
    entityType: 'asset',
    entityId: res.rows[0].id,
    entityName: res.rows[0].name,
    summary: `Ativo criado: ${res.rows[0].name}`,
    afterData: { id: res.rows[0].id, name: res.rows[0].name, asset_type: res.rows[0].asset_type },
    ip: clientIp(c),
  });
  return c.json(res.rows[0]);
});

app.put('/api/projects/:projectId/assets/:id', async (c) => {
  const projectId = c.req.param('projectId');
  const actor = await assertProjectWrite(c, projectId);
  const id = c.req.param('id');
  const body = await c.req.json();
  const before = await query('SELECT * FROM project_assets WHERE id = $1 AND project_id = $2', [id, projectId]);
  if (!before.rows[0]) return c.json({ error: 'Ativo não encontrado' }, 404);
  const res = await query(
    `UPDATE project_assets SET
       name = $1, asset_type = $2, status = $3, description = $4, owner_entity_id = $5,
       location_id = $6, latitude = $7, longitude = $8, image_url = $9, metadata = $10::jsonb,
       updated_at = NOW()
     WHERE id = $11 AND project_id = $12 RETURNING *`,
    [
      body.name ?? before.rows[0].name,
      body.asset_type ?? before.rows[0].asset_type,
      body.status ?? before.rows[0].status,
      body.description ?? before.rows[0].description,
      body.owner_entity_id !== undefined ? body.owner_entity_id || null : before.rows[0].owner_entity_id,
      body.location_id !== undefined ? body.location_id || null : before.rows[0].location_id,
      body.latitude !== undefined ? body.latitude : before.rows[0].latitude,
      body.longitude !== undefined ? body.longitude : before.rows[0].longitude,
      body.image_url ?? before.rows[0].image_url,
      JSON.stringify(body.metadata ?? before.rows[0].metadata ?? {}),
      id,
      projectId,
    ]
  );
  await writeAuditLog({
    projectId,
    userId: actor.id,
    userEmail: actor.email,
    action: 'update',
    entityType: 'asset',
    entityId: id,
    entityName: res.rows[0].name,
    summary: `Ativo atualizado: ${res.rows[0].name}`,
    beforeData: { id, name: before.rows[0].name },
    afterData: { id, name: res.rows[0].name, status: res.rows[0].status },
    ip: clientIp(c),
  });
  return c.json(res.rows[0]);
});

app.delete('/api/projects/:projectId/assets/:id', async (c) => {
  const projectId = c.req.param('projectId');
  const actor = await assertProjectDelete(c, projectId);
  const id = c.req.param('id');
  const before = await query('SELECT id, name FROM project_assets WHERE id = $1 AND project_id = $2', [id, projectId]);
  await query('DELETE FROM project_assets WHERE id = $1 AND project_id = $2', [id, projectId]);
  if (before.rows[0]) {
    await writeAuditLog({
      projectId,
      userId: actor.id,
      userEmail: actor.email,
      action: 'delete',
      entityType: 'asset',
      entityId: id,
      entityName: before.rows[0].name,
      summary: `Ativo removido: ${before.rows[0].name}`,
      beforeData: before.rows[0],
      ip: clientIp(c),
    });
  }
  return c.json({ success: true });
});

app.get('/api/projects/:projectId/evidences', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);
  const res = await query(
    'SELECT * FROM project_evidences WHERE project_id = $1 ORDER BY created_at DESC',
    [projectId]
  );
  return c.json(res.rows);
});

app.post('/api/projects/:projectId/evidences', async (c) => {
  const projectId = c.req.param('projectId');
  const actor = await assertProjectCreate(c, projectId);
  const body = await c.req.json();
  if (!body?.title || typeof body.title !== 'string') {
    return c.json({ error: 'title is required' }, 400);
  }
  const id = body.id || `evidence-${Date.now()}`;
  const res = await query(
    `INSERT INTO project_evidences (
       id, project_id, title, evidence_type, url, description, source, confidence,
       validation_status, occurred_at, author_name, related_entity_id, related_entity_type,
       relationship_id, location_name, latitude, longitude, created_at, updated_at
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,NOW(),NOW()) RETURNING *`,
    [
      id,
      projectId,
      body.title.trim(),
      body.evidence_type || 'documento',
      body.url || '',
      body.description || '',
      body.source || '',
      body.confidence || '',
      body.validation_status || 'pendente',
      body.occurred_at || null,
      body.author_name || '',
      body.related_entity_id || null,
      body.related_entity_type || null,
      body.relationship_id || null,
      body.location_name || '',
      body.latitude ?? null,
      body.longitude ?? null,
    ]
  );
  await writeAuditLog({
    projectId,
    userId: actor.id,
    userEmail: actor.email,
    action: 'create',
    entityType: 'evidence',
    entityId: res.rows[0].id,
    entityName: res.rows[0].title,
    summary: `Evidência criada: ${res.rows[0].title}`,
    afterData: { id: res.rows[0].id, title: res.rows[0].title },
    ip: clientIp(c),
  });
  return c.json(res.rows[0]);
});

app.put('/api/projects/:projectId/evidences/:id', async (c) => {
  const projectId = c.req.param('projectId');
  const actor = await assertProjectWrite(c, projectId);
  const id = c.req.param('id');
  const body = await c.req.json();
  const before = await query('SELECT * FROM project_evidences WHERE id = $1 AND project_id = $2', [id, projectId]);
  if (!before.rows[0]) return c.json({ error: 'Evidência não encontrada' }, 404);
  const b = before.rows[0];
  const res = await query(
    `UPDATE project_evidences SET
       title = $1, evidence_type = $2, url = $3, description = $4, source = $5, confidence = $6,
       validation_status = $7, occurred_at = $8, author_name = $9, related_entity_id = $10,
       related_entity_type = $11, relationship_id = $12, location_name = $13, latitude = $14,
       longitude = $15, updated_at = NOW()
     WHERE id = $16 AND project_id = $17 RETURNING *`,
    [
      body.title ?? b.title,
      body.evidence_type ?? b.evidence_type,
      body.url ?? b.url,
      body.description ?? b.description,
      body.source ?? b.source,
      body.confidence ?? b.confidence,
      body.validation_status ?? b.validation_status,
      body.occurred_at !== undefined ? body.occurred_at || null : b.occurred_at,
      body.author_name ?? b.author_name,
      body.related_entity_id !== undefined ? body.related_entity_id || null : b.related_entity_id,
      body.related_entity_type !== undefined ? body.related_entity_type || null : b.related_entity_type,
      body.relationship_id !== undefined ? body.relationship_id || null : b.relationship_id,
      body.location_name ?? b.location_name,
      body.latitude !== undefined ? body.latitude : b.latitude,
      body.longitude !== undefined ? body.longitude : b.longitude,
      id,
      projectId,
    ]
  );
  await writeAuditLog({
    projectId,
    userId: actor.id,
    userEmail: actor.email,
    action: 'update',
    entityType: 'evidence',
    entityId: id,
    entityName: res.rows[0].title,
    summary: `Evidência atualizada: ${res.rows[0].title}`,
    beforeData: { id, title: b.title, validation_status: b.validation_status },
    afterData: { id, title: res.rows[0].title, validation_status: res.rows[0].validation_status },
    ip: clientIp(c),
  });
  return c.json(res.rows[0]);
});

app.delete('/api/projects/:projectId/evidences/:id', async (c) => {
  const projectId = c.req.param('projectId');
  const actor = await assertProjectDelete(c, projectId);
  const id = c.req.param('id');
  const before = await query('SELECT id, title FROM project_evidences WHERE id = $1 AND project_id = $2', [id, projectId]);
  await query('DELETE FROM project_evidences WHERE id = $1 AND project_id = $2', [id, projectId]);
  if (before.rows[0]) {
    await writeAuditLog({
      projectId,
      userId: actor.id,
      userEmail: actor.email,
      action: 'delete',
      entityType: 'evidence',
      entityId: id,
      entityName: before.rows[0].title,
      summary: `Evidência removida: ${before.rows[0].title}`,
      beforeData: before.rows[0],
      ip: clientIp(c),
    });
  }
  return c.json({ success: true });
});

app.get('/api/projects/:projectId/communications', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);
  const res = await query(
    'SELECT * FROM project_communications WHERE project_id = $1 ORDER BY COALESCE(occurred_at, created_at) DESC',
    [projectId]
  );
  return c.json(res.rows);
});

app.post('/api/projects/:projectId/communications', async (c) => {
  const projectId = c.req.param('projectId');
  const actor = await assertProjectCreate(c, projectId);
  const body = await c.req.json();
  if (!body?.subject || typeof body.subject !== 'string') {
    return c.json({ error: 'subject is required' }, 400);
  }
  const id = body.id || `comm-${Date.now()}`;
  const res = await query(
    `INSERT INTO project_communications (
       id, project_id, subject, channel, direction, from_entity_id, to_entity_id,
       occurred_at, summary, evidence_id, created_at, updated_at
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW(),NOW()) RETURNING *`,
    [
      id,
      projectId,
      body.subject.trim(),
      body.channel || 'outro',
      body.direction || 'internal',
      body.from_entity_id || null,
      body.to_entity_id || null,
      body.occurred_at || null,
      body.summary || '',
      body.evidence_id || null,
    ]
  );
  await writeAuditLog({
    projectId,
    userId: actor.id,
    userEmail: actor.email,
    action: 'create',
    entityType: 'communication',
    entityId: res.rows[0].id,
    entityName: res.rows[0].subject,
    summary: `Comunicação registrada: ${res.rows[0].subject}`,
    afterData: { id: res.rows[0].id, subject: res.rows[0].subject, channel: res.rows[0].channel },
    ip: clientIp(c),
  });
  return c.json(res.rows[0]);
});

app.put('/api/projects/:projectId/communications/:id', async (c) => {
  const projectId = c.req.param('projectId');
  const actor = await assertProjectWrite(c, projectId);
  const id = c.req.param('id');
  const body = await c.req.json();
  const before = await query('SELECT * FROM project_communications WHERE id = $1 AND project_id = $2', [id, projectId]);
  if (!before.rows[0]) return c.json({ error: 'Comunicação não encontrada' }, 404);
  const b = before.rows[0];
  const res = await query(
    `UPDATE project_communications SET
       subject = $1, channel = $2, direction = $3, from_entity_id = $4, to_entity_id = $5,
       occurred_at = $6, summary = $7, evidence_id = $8, updated_at = NOW()
     WHERE id = $9 AND project_id = $10 RETURNING *`,
    [
      body.subject ?? b.subject,
      body.channel ?? b.channel,
      body.direction ?? b.direction,
      body.from_entity_id !== undefined ? body.from_entity_id || null : b.from_entity_id,
      body.to_entity_id !== undefined ? body.to_entity_id || null : b.to_entity_id,
      body.occurred_at !== undefined ? body.occurred_at || null : b.occurred_at,
      body.summary ?? b.summary,
      body.evidence_id !== undefined ? body.evidence_id || null : b.evidence_id,
      id,
      projectId,
    ]
  );
  await writeAuditLog({
    projectId,
    userId: actor.id,
    userEmail: actor.email,
    action: 'update',
    entityType: 'communication',
    entityId: id,
    entityName: res.rows[0].subject,
    summary: `Comunicação atualizada: ${res.rows[0].subject}`,
    beforeData: { id, subject: b.subject },
    afterData: { id, subject: res.rows[0].subject },
    ip: clientIp(c),
  });
  return c.json(res.rows[0]);
});

app.delete('/api/projects/:projectId/communications/:id', async (c) => {
  const projectId = c.req.param('projectId');
  const actor = await assertProjectDelete(c, projectId);
  const id = c.req.param('id');
  const before = await query(
    'SELECT id, subject FROM project_communications WHERE id = $1 AND project_id = $2',
    [id, projectId]
  );
  await query('DELETE FROM project_communications WHERE id = $1 AND project_id = $2', [id, projectId]);
  if (before.rows[0]) {
    await writeAuditLog({
      projectId,
      userId: actor.id,
      userEmail: actor.email,
      action: 'delete',
      entityType: 'communication',
      entityId: id,
      entityName: before.rows[0].subject,
      summary: `Comunicação removida: ${before.rows[0].subject}`,
      beforeData: before.rows[0],
      ip: clientIp(c),
    });
  }
  return c.json({ success: true });
});

app.get('/api/projects/:projectId/audit-logs', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);
  const limit = Math.min(Math.max(parseInt(c.req.query('limit') || '100', 10) || 100, 1), 500);
  const res = await query(
    `SELECT * FROM audit_logs
     WHERE project_id = $1
     ORDER BY created_at DESC
     LIMIT $2`,
    [projectId, limit]
  );
  return c.json(res.rows);
});

// ==================== AI CHAT ====================

function cleanEnvValue(value?: string | null): string {
  if (!value) return '';
  return String(value)
    .trim()
    .replace(/^["']+|["']+$/g, '')
    .replace(/\r|\n/g, '')
    .trim();
}

app.post('/api/ai-chat', async (c) => {
  const user = await requireUser(c);
  if (!rateLimit(`ai:${user.id}`, 30, 60_000)) {
    return c.json({ error: 'Limite de uso da IA atingido. Aguarde um minuto.' }, 429);
  }

  const body = await c.req.json();
  const { question, projectId, history = [], focusEntity } = body;

  if (!question || typeof question !== 'string') {
    return c.json({ error: 'Question is required' }, 400);
  }
  if (!projectId || typeof projectId !== 'string') {
    return c.json({ error: 'projectId is required' }, 400);
  }

  await assertProjectAccess(c, projectId);

  const apiKey = cleanEnvValue(process.env.OPENAI_API_KEY).replace(/\s+/g, '');
  const orgId = cleanEnvValue(process.env.OPENAI_ORG_ID).replace(/\s+/g, '');
  if (!apiKey) {
    return c.json({ error: 'OpenAI API key not configured on server' }, 500);
  }

  const [peopleRes, institutionsRes, activitiesRes, relationshipsRes] = await Promise.all([
    query(
      'SELECT id, name, role, institution FROM people WHERE project_id = $1 ORDER BY name ASC LIMIT 500',
      [projectId]
    ),
    query(
      'SELECT id, name, type FROM institutions WHERE project_id = $1 ORDER BY name ASC LIMIT 500',
      [projectId]
    ),
    query(
      'SELECT id, name, description FROM activities WHERE project_id = $1 ORDER BY name ASC LIMIT 500',
      [projectId]
    ),
    query(
      'SELECT source_id, target_id, type, description FROM relationships WHERE project_id = $1 LIMIT 2000',
      [projectId]
    ),
  ]);

  const people = peopleRes.rows;
  const institutions = institutionsRes.rows;
  const activities = activitiesRes.rows;
  const relationships = relationshipsRes.rows;

  const { default: OpenAI } = await import('openai');
  const openai = new OpenAI({
    apiKey,
    ...(orgId ? { organization: orgId } : {}),
  });

  const context = `
DADOS DO PROJETO:
ENTIDADES:
${people.map((p: any) => `- PESSOA: ${p.name}${p.role ? ` (Cargo: ${p.role})` : ''}${p.institution ? ` - Vinculado a: ${p.institution}` : ''}`).join('\n')}
${institutions.map((i: any) => `- INSTITUIÇÃO: ${i.name}${i.type ? ` (Tipo: ${i.type})` : ''}`).join('\n')}
${activities.map((a: any) => `- ATIVIDADE: ${a.name}${a.description ? ` (${a.description})` : ''}`).join('\n')}

RELACIONAMENTOS:
${relationships.map((r: any) => {
    const source = people.find((p: any) => p.id === r.source_id)?.name ||
      institutions.find((i: any) => i.id === r.source_id)?.name ||
      activities.find((a: any) => a.id === r.source_id)?.name || 'Desconhecido';
    const target = people.find((p: any) => p.id === r.target_id)?.name ||
      institutions.find((i: any) => i.id === r.target_id)?.name ||
      activities.find((a: any) => a.id === r.target_id)?.name || 'Desconhecido';
    return `- ${source} -> ${target} [Tipo: ${r.type}]${r.description ? `: ${r.description}` : ''}`;
  }).join('\n')}
`;

  let focusContext = '';
  if (focusEntity && typeof focusEntity === 'object' && focusEntity.name) {
    const conns = Array.isArray(focusEntity.connections) ? focusEntity.connections.slice(0, 50) : [];
    focusContext = `

FOCO ATUAL (o usuário selecionou este ator no mapa - priorize-o na análise):
- ${String(focusEntity.type || 'Entidade').slice(0, 80)}: ${String(focusEntity.name).slice(0, 200)}
- Total de conexões: ${conns.length}
CONEXÕES DIRETAS DO ATOR EM FOCO:
${conns.map((cn: any) => `- ${String(cn?.name || '').slice(0, 120)} [${String(cn?.type || '').slice(0, 40)}] via vínculo ${String(cn?.relType || '').slice(0, 40)}${cn?.level ? ` (nível ${String(cn.level).slice(0, 20)})` : ''}`).join('\n')}`;
  }

  const systemPrompt = `Você é o "Assistente do Mapa de Relacionamento", um especialista em análise de redes e relacionamentos.
Sua tarefa é responder perguntas do usuário baseando-se estritamente nos dados do projeto fornecidos abaixo.
Se a informação não estiver nos dados, diga educadamente que não possui essa informação no mapeamento atual.
Mantenha um tom profissional, analítico e útil. Cite os nomes das entidades envolvidas em suas respostas.

CONTEXTO DO PROJETO:
${context}${focusContext}`;

  const safeHistory = (Array.isArray(history) ? history : [])
    .slice(-6)
    .filter(
      (m: any) =>
        m &&
        (m.role === 'user' || m.role === 'assistant') &&
        typeof m.content === 'string'
    )
    .map((m: any) => ({
      role: m.role as 'user' | 'assistant',
      content: String(m.content).slice(0, 4000),
    }));

  const messagesForAI = [
    { role: 'system' as const, content: systemPrompt },
    ...safeHistory,
    { role: 'user' as const, content: String(question).slice(0, 4000) },
  ];

  try {
    const completion = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: messagesForAI as any,
      temperature: 0.7,
      max_tokens: 1000,
    });
    return c.json({ answer: completion.choices[0].message.content });
  } catch (error: any) {
    console.error('[AI-CHAT] OpenAI error:', {
      name: error?.name,
      status: error?.status,
      code: error?.code,
      message: error?.message,
      cause: error?.cause?.message || error?.cause || null,
      keyLen: apiKey.length,
      hasOrg: Boolean(orgId),
    });

    const code = String(error?.code || '');
    const msg = String(error?.message || '');
    if (
      error?.status === 429 ||
      code === 'insufficient_quota' ||
      code === 'credit_balance_exhausted' ||
      /quota|credits? remaining|billing/i.test(msg)
    ) {
      return c.json({
        error: 'Cota de uso da OpenAI excedida ou sem créditos. Adicione créditos em platform.openai.com/settings/organization/billing',
        type: 'quota_exceeded',
      }, 429);
    }

    if (error?.status === 401 || error?.code === 'invalid_api_key') {
      return c.json({
        error: 'Chave OpenAI inválida ou sem permissão. Verifique OPENAI_API_KEY (e OPENAI_ORG_ID) no ambiente do backend.',
        type: 'invalid_api_key',
      }, 401);
    }

    if (error?.name === 'APIConnectionError' || /connection error/i.test(String(error?.message || ''))) {
      return c.json({
        error: 'Falha de conexão do servidor com a OpenAI. Verifique a chave (sem aspas/espaços/quebra de linha) e se o hosting permite saída HTTPS para api.openai.com.',
        type: 'connection_error',
      }, 502);
    }

    return c.json({ error: 'Falha ao processar a solicitação de IA', type: 'ai_error' }, 500);
  }
});

// Start Server
async function boot() {
  try {
    await ensurePhaseDSchema();
  } catch (err) {
    console.warn('⚠️ [SCHEMA] Fase D não aplicada:', (err as Error)?.message || err);
  }
  serve({ fetch: app.fetch, port: PORT });
  console.log(`🚀 Independent Hono Backend running on http://localhost:${PORT}`);
}

boot();
