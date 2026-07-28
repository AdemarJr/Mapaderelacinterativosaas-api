import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { randomUUID } from 'crypto';
import { query } from './db.js';
import dotenv from 'dotenv';
import {
  hashPassword,
  verifyPassword,
  signToken,
  getAuthenticatedUser,
  canManageUserType,
  type AuthUser,
} from './auth.js';

dotenv.config();

const app = new Hono();
const PORT = process.env.PORT ? parseInt(process.env.PORT) : 3001;

// Middleware
app.use('*', logger(console.log));
app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Client-Info'],
  exposeHeaders: ['Content-Length', 'X-JSON'],
  maxAge: 86400,
}));

app.options('*', (c) => c.text('', 204));

// Global error handler
app.onError((err, c) => {
  console.error('❌ [SERVER ERROR]', err);
  const message = err.message || 'Internal server error';
  const isAuthError = message.includes('authorization') || message.includes('token');
  return c.json({ error: message, code: isAuthError ? 401 : 500 }, isAuthError ? 401 : 500);
});

// Require an authenticated user or throw (handled by onError as 401).
async function requireUser(c: any): Promise<AuthUser> {
  return getAuthenticatedUser(c.req.header('Authorization'));
}

// Checks whether the user can access a given project (owner, collaborator or super_admin).
async function userCanAccessProject(user: AuthUser, projectId: string): Promise<boolean> {
  if (user.user_type === 'super_admin') return true;
  const res = await query(
    `SELECT 1 FROM projects WHERE id = $1 AND user_id::text = $2
     UNION
     SELECT 1 FROM project_users WHERE project_id = $1 AND user_id::text = $2
     LIMIT 1`,
    [projectId, user.id]
  );
  return (res.rowCount ?? 0) > 0;
}

async function assertProjectAccess(c: any, projectId: string): Promise<AuthUser> {
  const user = await requireUser(c);
  const ok = await userCanAccessProject(user, projectId);
  if (!ok) {
    throw new Error('Forbidden: no access to this project');
  }
  return user;
}

// Health check
app.get('/api/health', (c) => c.json({ status: 'ok', database: 'postgres' }));

// ==================== AUTH ====================

app.post('/api/auth/register', async (c) => {
  const body = await c.req.json();
  const { name, email, password } = body;

  if (!name || !email || !password) {
    return c.json({ error: 'Nome, email e senha são obrigatórios' }, 400);
  }
  if (password.length < 6) {
    return c.json({ error: 'A senha deve ter no mínimo 6 caracteres' }, 400);
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
  return c.json({ token, user });
});

app.get('/api/auth/me', async (c) => {
  const authUser = await requireUser(c);
  const res = await query('SELECT id, name, email, user_type, created_at FROM profiles WHERE id = $1 LIMIT 1', [authUser.id]);
  if (res.rowCount === 0) {
    return c.json({ id: authUser.id, email: authUser.email, name: authUser.name, user_type: authUser.user_type });
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
  if (new_password.length < 6) {
    return c.json({ error: 'New password must be at least 6 characters' }, 400);
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
    return c.json({ id: authUser.id, email: authUser.email, name: authUser.name, user_type: authUser.user_type });
  }
  return c.json(res.rows[0]);
});

// ==================== USER MANAGEMENT (admin) ====================

app.get('/api/users', async (c) => {
  await requireUser(c);
  const res = await query(
    'SELECT id, email, name, user_type, created_at, updated_at FROM profiles ORDER BY created_at DESC'
  );
  return c.json({ profiles: res.rows });
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
  if (password.length < 6) {
    return c.json({ error: 'A senha deve ter no mínimo 6 caracteres' }, 400);
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

  const targetRes = await query('SELECT id, user_type FROM profiles WHERE id = $1 LIMIT 1', [userId]);
  if (targetRes.rowCount === 0) {
    return c.json({ error: 'Usuário não encontrado', code: 404 }, 404);
  }
  const target = targetRes.rows[0];
  const isEditingSelf = requester.id === userId;

  // Users cannot change their own user_type.
  if (isEditingSelf && user_type && user_type !== target.user_type) {
    return c.json({ error: 'Você não pode alterar seu próprio tipo de usuário.', code: 403 }, 403);
  }
  // Validate hierarchy when editing others' type.
  if (!isEditingSelf && user_type && !canManageUserType(requester.user_type, user_type)) {
    return c.json({ error: `Você não tem permissão para atribuir o tipo "${user_type}".`, code: 403 }, 403);
  }

  const finalType = isEditingSelf ? target.user_type : (user_type || target.user_type);
  await query(
    'UPDATE profiles SET email = $1, name = $2, user_type = $3, updated_at = NOW() WHERE id = $4',
    [email, name, finalType, userId]
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

// List all users (SuperAdmin password manager view).
app.get('/api/auth-users', async (c) => {
  await requireUser(c);
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

  if (!new_password || new_password.length < 6) {
    return c.json({ error: 'Password must be at least 6 characters' }, 400);
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
  await assertProjectAccess(c, id);
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
  await assertProjectAccess(c, projectId);

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
  const requester = await assertProjectAccess(c, projectId);
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
  await assertProjectAccess(c, projectId);
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
  await assertProjectAccess(c, projectId);
  const linkId = c.req.param('linkId');
  await query('DELETE FROM project_users WHERE id = $1 AND project_id = $2', [linkId, projectId]);
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
  await assertProjectAccess(c, projectId);
  const body = await c.req.json();
  const id = body.id || `person-${Date.now()}`;

  const res = await query(
    `INSERT INTO people (id, project_id, name, role, institution, email, phone, notes, image_url, instagram, facebook, tiktok, linkedin, website, x, y, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW(), NOW()) RETURNING *`,
    [id, projectId, body.name, body.role || '', body.institution || '', body.email || '', body.phone || '', body.notes || '', body.image_url || '', body.instagram || '', body.facebook || '', body.tiktok || '', body.linkedin || '', body.website || '', body.x || 0, body.y || 0]
  );
  return c.json(res.rows[0]);
});

app.put('/api/projects/:projectId/people/:id', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);
  const id = c.req.param('id');
  const body = await c.req.json();

  const res = await query(
    `UPDATE people SET name = $1, role = $2, institution = $3, email = $4, phone = $5, notes = $6, image_url = $7, instagram = $8, facebook = $9, tiktok = $10, linkedin = $11, website = $12, x = $13, y = $14, updated_at = NOW()
     WHERE id = $15 AND project_id = $16 RETURNING *`,
    [body.name, body.role || '', body.institution || '', body.email || '', body.phone || '', body.notes || '', body.image_url || '', body.instagram || '', body.facebook || '', body.tiktok || '', body.linkedin || '', body.website || '', body.x || 0, body.y || 0, id, projectId]
  );
  return c.json(res.rows[0]);
});

app.delete('/api/projects/:projectId/people/:id', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);
  const id = c.req.param('id');
  await query('DELETE FROM relationships WHERE source_id = $1 OR target_id = $1', [id]);
  await query('DELETE FROM people WHERE id = $1 AND project_id = $2', [id, projectId]);
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
  await assertProjectAccess(c, projectId);
  const body = await c.req.json();
  const id = body.id || `institution-${Date.now()}`;

  const res = await query(
    `INSERT INTO institutions (id, project_id, name, type, description, contact, address, cnpj, fantasy_name, instagram, facebook, tiktok, linkedin, website, image_url, x, y, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, NOW(), NOW()) RETURNING *`,
    [id, projectId, body.name, body.type || '', body.description || '', body.contact || '', body.address || '', body.cnpj || '', body.fantasy_name || '', body.instagram || '', body.facebook || '', body.tiktok || '', body.linkedin || '', body.website || '', body.image_url || '', body.x || 0, body.y || 0]
  );
  return c.json(res.rows[0]);
});

app.put('/api/projects/:projectId/institutions/:id', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);
  const id = c.req.param('id');
  const body = await c.req.json();

  const res = await query(
    `UPDATE institutions SET name = $1, type = $2, description = $3, contact = $4, address = $5, cnpj = $6, fantasy_name = $7, instagram = $8, facebook = $9, tiktok = $10, linkedin = $11, website = $12, image_url = $13, x = $14, y = $15, updated_at = NOW()
     WHERE id = $16 AND project_id = $17 RETURNING *`,
    [body.name, body.type || '', body.description || '', body.contact || '', body.address || '', body.cnpj || '', body.fantasy_name || '', body.instagram || '', body.facebook || '', body.tiktok || '', body.linkedin || '', body.website || '', body.image_url || '', body.x || 0, body.y || 0, id, projectId]
  );
  return c.json(res.rows[0]);
});

app.delete('/api/projects/:projectId/institutions/:id', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);
  const id = c.req.param('id');
  await query('DELETE FROM relationships WHERE source_id = $1 OR target_id = $1', [id]);
  await query('DELETE FROM institutions WHERE id = $1 AND project_id = $2', [id, projectId]);
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
  await assertProjectAccess(c, projectId);
  const body = await c.req.json();
  const id = body.id || `activity-${Date.now()}`;

  const res = await query(
    `INSERT INTO activities (id, project_id, name, description, start_date, end_date, status, location, image_url, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW()) RETURNING *`,
    [id, projectId, body.name, body.description || '', body.start_date || null, body.end_date || null, body.status || '', body.location || '', body.image_url || '']
  );
  return c.json(res.rows[0]);
});

app.put('/api/projects/:projectId/activities/:id', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);
  const id = c.req.param('id');
  const body = await c.req.json();

  const res = await query(
    `UPDATE activities SET name = $1, description = $2, start_date = $3, end_date = $4, status = $5, location = $6, image_url = $7, updated_at = NOW()
     WHERE id = $8 AND project_id = $9 RETURNING *`,
    [body.name, body.description || '', body.start_date || null, body.end_date || null, body.status || '', body.location || '', body.image_url || '', id, projectId]
  );
  return c.json(res.rows[0]);
});

app.delete('/api/projects/:projectId/activities/:id', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);
  const id = c.req.param('id');
  await query('DELETE FROM relationships WHERE source_id = $1 OR target_id = $1', [id]);
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
  await assertProjectAccess(c, projectId);
  const body = await c.req.json();
  const id = body.id || `location-${Date.now()}`;

  const res = await query(
    `INSERT INTO locations (id, project_id, name, address, latitude, longitude, google_maps_url, image_url, x, y, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW()) RETURNING *`,
    [id, projectId, body.name, body.address || '', body.latitude || null, body.longitude || null, body.google_maps_url || '', body.image_url || '', body.x || 0, body.y || 0]
  );
  return c.json(res.rows[0]);
});

app.put('/api/projects/:projectId/locations/:id', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);
  const id = c.req.param('id');
  const body = await c.req.json();

  const res = await query(
    `UPDATE locations SET name = $1, address = $2, latitude = $3, longitude = $4, google_maps_url = $5, image_url = $6, x = $7, y = $8, updated_at = NOW()
     WHERE id = $9 AND project_id = $10 RETURNING *`,
    [body.name, body.address || '', body.latitude || null, body.longitude || null, body.google_maps_url || '', body.image_url || '', body.x || 0, body.y || 0, id, projectId]
  );
  return c.json(res.rows[0]);
});

app.delete('/api/projects/:projectId/locations/:id', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);
  const id = c.req.param('id');
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
  await assertProjectAccess(c, projectId);
  const body = await c.req.json();
  const id = body.id || `relationship-${Date.now()}`;

  const res = await query(
    `INSERT INTO relationships (id, project_id, source_id, target_id, source_type, target_type, type, level, description, strength, image_url, source, confidence, start_date, end_date, documents, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW(), NOW()) RETURNING *`,
    [id, projectId, body.source_id, body.target_id, body.source_type, body.target_type, body.type, body.level || '', body.description || '', body.strength || 1, body.image_url || '', body.source || '', body.confidence || '', body.start_date || null, body.end_date || null, JSON.stringify(body.documents ?? [])]
  );
  return c.json(res.rows[0]);
});

app.put('/api/projects/:projectId/relationships/:id', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);
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
  await assertProjectAccess(c, projectId);
  const id = c.req.param('id');
  await query('DELETE FROM relationships WHERE id = $1 AND project_id = $2', [id, projectId]);
  return c.json({ success: true });
});

// Fix relationships typed "POSITIVA" -> "POSITIVO".
app.post('/api/projects/:projectId/relationships/fix-types', async (c) => {
  const projectId = c.req.param('projectId');
  await assertProjectAccess(c, projectId);
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
  const user = await requireUser(c);
  const projectId = c.req.query('projectId');
  if (!projectId) return c.json({ error: 'projectId is required' }, 400);
  const res = await query(
    'SELECT * FROM map_configurations WHERE user_id = $1 AND project_id = $2 ORDER BY updated_at DESC',
    [user.id, projectId]
  );
  return c.json({ data: res.rows });
});

app.get('/api/map-configurations/default', async (c) => {
  const user = await requireUser(c);
  const projectId = c.req.query('projectId');
  if (!projectId) return c.json({ error: 'projectId is required' }, 400);
  const res = await query(
    'SELECT * FROM map_configurations WHERE user_id = $1 AND project_id = $2 AND is_default = true LIMIT 1',
    [user.id, projectId]
  );
  return c.json({ data: res.rowCount ? res.rows[0] : null });
});

app.post('/api/map-configurations', async (c) => {
  const user = await requireUser(c);
  const body = await c.req.json();

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
    const res = await query(
      `UPDATE map_configurations SET template_name = $1, is_template = $2, is_default = $3,
        view_state = $4, settings = $5, entity_positions = $6, filter_settings = $7, updated_at = NOW()
       WHERE id = $8 AND user_id = $9 RETURNING *`,
      [common.template_name, common.is_template, common.is_default, common.view_state, common.settings, common.entity_positions, common.filter_settings, body.id, user.id]
    );
    if (res.rowCount === 0) return c.json({ error: 'Configuração não encontrada' }, 404);
    return c.json({ data: res.rows[0] });
  }

  const res = await query(
    `INSERT INTO map_configurations (user_id, project_id, template_name, is_template, is_default, view_state, settings, entity_positions, filter_settings, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW()) RETURNING *`,
    [user.id, body.project_id, common.template_name, common.is_template, common.is_default, common.view_state, common.settings, common.entity_positions, common.filter_settings]
  );
  return c.json({ data: res.rows[0] });
});

app.post('/api/map-configurations/set-default', async (c) => {
  const user = await requireUser(c);
  const body = await c.req.json();
  const { configId, projectId } = body;
  await query('UPDATE map_configurations SET is_default = false WHERE user_id = $1 AND project_id = $2', [user.id, projectId]);
  await query('UPDATE map_configurations SET is_default = true WHERE id = $1 AND user_id = $2', [configId, user.id]);
  return c.json({ success: true });
});

app.put('/api/map-configurations/:id/positions', async (c) => {
  const user = await requireUser(c);
  const id = c.req.param('id');
  const body = await c.req.json();
  await query(
    'UPDATE map_configurations SET entity_positions = $1, updated_at = NOW() WHERE id = $2 AND user_id = $3',
    [JSON.stringify(body.positions ?? []), id, user.id]
  );
  return c.json({ success: true });
});

app.delete('/api/map-configurations/:id', async (c) => {
  const user = await requireUser(c);
  const id = c.req.param('id');
  await query('DELETE FROM map_configurations WHERE id = $1 AND user_id = $2', [id, user.id]);
  return c.json({ success: true });
});

// ==================== AI CHAT ====================

app.post('/api/ai-chat', async (c) => {
  await requireUser(c);
  const body = await c.req.json();
  const { question, projectData, history = [], focusEntity } = body;

  if (!question) {
    return c.json({ error: 'Question is required' }, 400);
  }

  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    return c.json({ error: 'OpenAI API key not configured on server' }, 500);
  }

  const { default: OpenAI } = await import('openai');
  const openai = new OpenAI({ apiKey });

  const { people = [], institutions = [], activities = [], relationships = [] } = projectData || {};

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
  if (focusEntity && focusEntity.name) {
    const conns = Array.isArray(focusEntity.connections) ? focusEntity.connections : [];
    focusContext = `

FOCO ATUAL (o usuário selecionou este ator no mapa - priorize-o na análise):
- ${focusEntity.type || 'Entidade'}: ${focusEntity.name}
- Total de conexões: ${conns.length}
CONEXÕES DIRETAS DO ATOR EM FOCO:
${conns.map((cn: any) => `- ${cn.name} [${cn.type || ''}] via vínculo ${cn.relType || ''}${cn.level ? ` (nível ${cn.level})` : ''}`).join('\n')}`;
  }

  const systemPrompt = `Você é o "Assistente do Mapa de Relacionamento", um especialista em análise de redes e relacionamentos.
Sua tarefa é responder perguntas do usuário baseando-se estritamente nos dados do projeto fornecidos abaixo.
Se a informação não estiver nos dados, diga educadamente que não possui essa informação no mapeamento atual.
Mantenha um tom profissional, analítico e útil. Cite os nomes das entidades envolvidas em suas respostas.

CONTEXTO DO PROJETO:
${context}${focusContext}`;

  const messagesForAI = [
    { role: 'system', content: systemPrompt },
    ...history.slice(-6).map((m: any) => ({ role: m.role, content: m.content })),
    { role: 'user', content: question },
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
    if (error.code === 'insufficient_quota' || (error.message && error.message.includes('quota'))) {
      return c.json({ error: 'Cota de uso da OpenAI excedida ou plano expirado.', type: 'quota_exceeded' }, 429);
    }
    return c.json({ error: error.message || 'Erro ao processar chat com IA' }, 500);
  }
});

// Start Server
serve({ fetch: app.fetch, port: PORT });
console.log(`🚀 Independent Hono Backend running on http://localhost:${PORT}`);
