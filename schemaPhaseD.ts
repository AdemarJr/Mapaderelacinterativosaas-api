/**
 * Fase D — tabelas aditivas (CREATE IF NOT EXISTS).
 * Seguro rodar a cada boot do backend.
 */
import { query } from './db.js';

export async function ensurePhaseDSchema(): Promise<void> {
  await query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      project_id TEXT,
      user_id TEXT,
      user_email TEXT,
      action TEXT NOT NULL,
      entity_type TEXT NOT NULL,
      entity_id TEXT,
      entity_name TEXT,
      summary TEXT,
      before_data JSONB,
      after_data JSONB,
      ip TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await query(`CREATE INDEX IF NOT EXISTS idx_audit_logs_project_created ON audit_logs (project_id, created_at DESC)`);
  await query(`CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit_logs (entity_type, entity_id)`);

  await query(`
    CREATE TABLE IF NOT EXISTS project_assets (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL,
      name TEXT NOT NULL,
      asset_type TEXT DEFAULT 'outro',
      status TEXT DEFAULT 'ativo',
      description TEXT DEFAULT '',
      owner_entity_id TEXT,
      location_id TEXT,
      latitude DOUBLE PRECISION,
      longitude DOUBLE PRECISION,
      image_url TEXT DEFAULT '',
      metadata JSONB DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await query(`CREATE INDEX IF NOT EXISTS idx_project_assets_project ON project_assets (project_id)`);

  await query(`
    CREATE TABLE IF NOT EXISTS project_evidences (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL,
      title TEXT NOT NULL,
      evidence_type TEXT DEFAULT 'documento',
      url TEXT DEFAULT '',
      description TEXT DEFAULT '',
      source TEXT DEFAULT '',
      confidence TEXT DEFAULT '',
      validation_status TEXT DEFAULT 'pendente',
      occurred_at DATE,
      author_name TEXT DEFAULT '',
      related_entity_id TEXT,
      related_entity_type TEXT,
      relationship_id TEXT,
      location_name TEXT DEFAULT '',
      latitude DOUBLE PRECISION,
      longitude DOUBLE PRECISION,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await query(`CREATE INDEX IF NOT EXISTS idx_project_evidences_project ON project_evidences (project_id)`);

  await query(`
    CREATE TABLE IF NOT EXISTS project_communications (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL,
      subject TEXT NOT NULL,
      channel TEXT DEFAULT 'outro',
      direction TEXT DEFAULT 'internal',
      from_entity_id TEXT,
      to_entity_id TEXT,
      occurred_at TIMESTAMPTZ,
      summary TEXT DEFAULT '',
      evidence_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await query(`CREATE INDEX IF NOT EXISTS idx_project_communications_project ON project_communications (project_id)`);

  console.log('✅ [SCHEMA] Fase D pronta (audit_logs, assets, evidences, communications)');
}
