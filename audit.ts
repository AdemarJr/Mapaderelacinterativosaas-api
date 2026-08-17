import { randomUUID } from 'crypto';
import { query } from './db.js';

export type AuditAction = 'create' | 'update' | 'delete' | 'reset_password' | 'login' | 'other';

export interface AuditEntry {
  projectId?: string | null;
  userId?: string | null;
  userEmail?: string | null;
  action: AuditAction | string;
  entityType: string;
  entityId?: string | null;
  entityName?: string | null;
  summary?: string | null;
  beforeData?: unknown;
  afterData?: unknown;
  ip?: string | null;
}

export async function writeAuditLog(entry: AuditEntry): Promise<void> {
  try {
    const id = randomUUID();
    await query(
      `INSERT INTO audit_logs (
         id, project_id, user_id, user_email, action, entity_type, entity_id, entity_name,
         summary, before_data, after_data, ip, created_at
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,$12,NOW())`,
      [
        id,
        entry.projectId || null,
        entry.userId || null,
        entry.userEmail || null,
        entry.action,
        entry.entityType,
        entry.entityId || null,
        entry.entityName || null,
        entry.summary || null,
        entry.beforeData != null ? JSON.stringify(entry.beforeData) : null,
        entry.afterData != null ? JSON.stringify(entry.afterData) : null,
        entry.ip || null,
      ]
    );
  } catch (err) {
    // Auditoria nunca deve derrubar a operação principal
    console.warn('⚠️ [AUDIT] falha ao gravar log:', (err as Error)?.message || err);
  }
}
