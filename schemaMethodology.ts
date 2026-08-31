/**
 * Metodologia IRR/IRE/IC — schema aditivo (CREATE IF NOT EXISTS).
 */
import { query } from './db.js';

const POP_VERSION_ID = 'methodology-pop-2.0';
const POP_LABEL = 'POP-2.0';

const POP_CATEGORIES = [
  { code: 'ambiental', label: 'Ambientais', sort: 1 },
  { code: 'politico_regulatorio', label: 'Políticos / Regulatórios', sort: 2 },
  { code: 'social_juridico', label: 'Sociais / Jurídicos', sort: 3 },
  { code: 'mercado', label: 'Mercado', sort: 4 },
  { code: 'reputacional', label: 'Reputacional', sort: 5 },
  { code: 'tecnico', label: 'Técnicos', sort: 6 },
  { code: 'criminal_ilicito', label: 'Criminal / Ilícito', sort: 7 },
];

/** Subtipos REDD+ Rio Madeira (parametrizáveis por macro categoria). */
const POP_SUBTYPES: Record<string, string[]> = {
  ambiental: ['Queimadas (jun–nov)', 'Desmatamento', 'Degradação florestal'],
  politico_regulatorio: ['Falta de apoio institucional', 'Mudança de legislação', 'Insegurança regulatória'],
  social_juridico: ['Invasão / reintegração', 'Salvaguardas', 'Segurança de pessoal', 'Insegurança fundiária'],
  mercado: ['Volatilidade de preços', 'Demanda internacional', 'Dupla contagem'],
  reputacional: ['Exposição midiática', 'Narrativas contrárias', 'Direitos humanos', 'Transparência'],
  tecnico: ['Falha no MRV', 'Monitoramento inadequado', 'Certificação'],
  criminal_ilicito: ['Grilagem', 'Tráfico / ilícitos associados', 'Outro (aprovação Projeto)'],
};

export async function ensureMethodologySchema(): Promise<void> {
  await query(`
    CREATE TABLE IF NOT EXISTS methodology_versions (
      id TEXT PRIMARY KEY,
      version_label TEXT NOT NULL,
      description TEXT DEFAULT '',
      effective_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      effective_to TIMESTAMPTZ,
      weights JSONB DEFAULT '{}'::jsonb,
      bands JSONB DEFAULT '{}'::jsonb,
      factor_definitions JSONB DEFAULT '{}'::jsonb,
      author_id TEXT,
      approver_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS risk_category_catalog (
      id TEXT PRIMARY KEY,
      project_id TEXT,
      methodology_version_id TEXT NOT NULL,
      code TEXT NOT NULL,
      label TEXT NOT NULL,
      sort_order INT DEFAULT 0,
      is_active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await query(`CREATE INDEX IF NOT EXISTS idx_risk_categories_project ON risk_category_catalog (project_id, methodology_version_id)`);

  await query(`
    CREATE TABLE IF NOT EXISTS project_risks (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      status TEXT DEFAULT 'ativo',
      scope TEXT DEFAULT 'pontual',
      related_entity_id TEXT,
      related_entity_type TEXT,
      relationship_id TEXT,
      evidence_id TEXT,
      occurred_at DATE,
      review_due_at DATE,
      factor_overrides JSONB DEFAULT '{}'::jsonb,
      created_by TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await query(`CREATE INDEX IF NOT EXISTS idx_risks_entity ON project_risks (project_id, related_entity_id, status)`);

  await query(`
    CREATE TABLE IF NOT EXISTS project_risk_category_links (
      risk_id TEXT NOT NULL,
      category_id TEXT NOT NULL,
      PRIMARY KEY (risk_id, category_id)
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS index_assessments (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL,
      methodology_version_id TEXT NOT NULL,
      index_type TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target_id TEXT NOT NULL,
      value NUMERIC,
      band TEXT DEFAULT '',
      status TEXT DEFAULT 'PRELIMINAR',
      insufficient_reason TEXT,
      computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      validated_at TIMESTAMPTZ,
      validated_by TEXT,
      superseded_by TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await query(`CREATE INDEX IF NOT EXISTS idx_assessments_project_target ON index_assessments (project_id, target_type, target_id, index_type)`);
  await query(`CREATE INDEX IF NOT EXISTS idx_assessments_status ON index_assessments (project_id, status, index_type)`);

  await query(`
    CREATE TABLE IF NOT EXISTS index_factor_scores (
      id TEXT PRIMARY KEY,
      assessment_id TEXT NOT NULL,
      factor_code TEXT NOT NULL,
      is_applicable BOOLEAN DEFAULT TRUE,
      auto_value NUMERIC,
      validated_value NUMERIC,
      effective_value NUMERIC,
      weight NUMERIC DEFAULT 1,
      origin TEXT DEFAULT 'automatic',
      justification TEXT,
      evidence_refs JSONB DEFAULT '[]'::jsonb,
      computed_by TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await query(`CREATE INDEX IF NOT EXISTS idx_factor_scores_assessment ON index_factor_scores (assessment_id)`);

  await query(`
    CREATE TABLE IF NOT EXISTS risk_subtype_catalog (
      id TEXT PRIMARY KEY,
      category_id TEXT NOT NULL,
      code TEXT NOT NULL,
      label TEXT NOT NULL,
      sort_order INT DEFAULT 0,
      is_active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await query(`CREATE INDEX IF NOT EXISTS idx_risk_subtypes_category ON risk_subtype_catalog (category_id)`);

  await query(`
    CREATE TABLE IF NOT EXISTS project_assertions (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL,
      text TEXT NOT NULL,
      assertion_type TEXT DEFAULT 'avaliacao',
      status TEXT DEFAULT 'ativo',
      related_entity_id TEXT,
      related_entity_type TEXT,
      relationship_id TEXT,
      evidence_ids JSONB DEFAULT '[]'::jsonb,
      created_by TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await query(`CREATE INDEX IF NOT EXISTS idx_assertions_project ON project_assertions (project_id, status)`);
  await query(`CREATE INDEX IF NOT EXISTS idx_assertions_entity ON project_assertions (project_id, related_entity_id)`);

  // Additive columns on existing tables
  await query(`ALTER TABLE projects ADD COLUMN IF NOT EXISTS anchor_entity_id TEXT`);
  await query(`ALTER TABLE projects ADD COLUMN IF NOT EXISTS active_methodology_version_id TEXT`);
  await query(`ALTER TABLE relationships ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE`);
  await query(`ALTER TABLE project_evidences ADD COLUMN IF NOT EXISTS source_independence TEXT`);
  await query(`ALTER TABLE project_evidences ADD COLUMN IF NOT EXISTS content_hash TEXT`);
  await query(`ALTER TABLE project_risks ADD COLUMN IF NOT EXISTS subtype_id TEXT`);
  await query(`ALTER TABLE project_risks ADD COLUMN IF NOT EXISTS assertion_id TEXT`);
  await query(`ALTER TABLE project_risks ADD COLUMN IF NOT EXISTS risk_level TEXT DEFAULT 'entity'`);

  // Seed POP-2.0
  const existing = await query('SELECT id FROM methodology_versions WHERE id = $1 LIMIT 1', [POP_VERSION_ID]);
  if ((existing.rowCount ?? 0) === 0) {
    await query(
      `INSERT INTO methodology_versions (id, version_label, description, weights, bands, factor_definitions)
       VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6::jsonb)`,
      [
        POP_VERSION_ID,
        POP_LABEL,
        'POP — Aplicação dos Índices IRR, IRE e IC — Versão 2.0',
        JSON.stringify({ 'IRR-1': 1, 'IRR-2': 1, 'IRR-3': 1, 'IRR-4': 1, 'IRR-5': 1, 'IRE-1': 1, 'IRE-2': 1, 'IRE-3': 1, 'IRE-4': 1, 'IRE-5': 1, 'IC-1': 1, 'IC-2': 1, 'IC-3': 1, 'IC-4': 1 }),
        JSON.stringify({ bands: [0, 20, 40, 60, 80, 100] }),
        JSON.stringify({ irr: 5, ire: 5, ic: 4 }),
      ]
    );

    for (const cat of POP_CATEGORIES) {
      const catId = `cat-${POP_VERSION_ID}-${cat.code}`;
      await query(
        `INSERT INTO risk_category_catalog (id, project_id, methodology_version_id, code, label, sort_order)
         VALUES ($1, NULL, $2, $3, $4, $5)`,
        [catId, POP_VERSION_ID, cat.code, cat.label, cat.sort]
      );
      const subtypes = POP_SUBTYPES[cat.code] || [];
      for (let i = 0; i < subtypes.length; i++) {
        const subId = `sub-${POP_VERSION_ID}-${cat.code}-${i}`;
        const subCode = subtypes[i].toLowerCase().replace(/[^a-z0-9]+/g, '_').slice(0, 48);
        await query(
          `INSERT INTO risk_subtype_catalog (id, category_id, code, label, sort_order)
           VALUES ($1, $2, $3, $4, $5)`,
          [subId, catId, subCode, subtypes[i], i + 1]
        );
      }
    }
  }

  // Seed subtypes for existing POP install (idempotent)
  for (const cat of POP_CATEGORIES) {
    const catId = `cat-${POP_VERSION_ID}-${cat.code}`;
    const subtypes = POP_SUBTYPES[cat.code] || [];
    for (let i = 0; i < subtypes.length; i++) {
      const subId = `sub-${POP_VERSION_ID}-${cat.code}-${i}`;
      const subCode = subtypes[i].toLowerCase().replace(/[^a-z0-9]+/g, '_').slice(0, 48);
      await query(
        `INSERT INTO risk_subtype_catalog (id, category_id, code, label, sort_order)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (id) DO NOTHING`,
        [subId, catId, subCode, subtypes[i], i + 1]
      );
    }
  }

  console.log('✅ [SCHEMA] Metodologia IRR/IRE/IC pronta (methodology_versions, risks, assessments)');
}

export { POP_VERSION_ID, POP_LABEL };
