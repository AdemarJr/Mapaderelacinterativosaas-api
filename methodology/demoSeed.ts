/**
 * POP demo seeds — exemplos 13.1–13.3 (REDD+ Rio Madeira).
 * Idempotente: não duplica se IDs demo já existirem.
 */
import { randomUUID } from 'crypto';
import { query } from '../db.js';
import { POP_VERSION_ID } from '../schemaMethodology.js';

const DEMO_PREFIX = 'pop-demo-';

export async function seedPopMethodologyExamples(
  projectId: string,
  actorId: string
): Promise<{ created: string[]; skipped: string[] }> {
  const created: string[] = [];
  const skipped: string[] = [];

  const existing = await query(
    `SELECT id FROM project_risks WHERE project_id = $1 AND id LIKE $2 LIMIT 1`,
    [projectId, `${DEMO_PREFIX}%`]
  );
  if ((existing.rowCount ?? 0) > 0) {
    skipped.push('demo-already-seeded');
    return { created, skipped };
  }

  const [people, locations, ambientCat, burnSubtype] = await Promise.all([
    query('SELECT id, name FROM people WHERE project_id = $1 ORDER BY created_at LIMIT 1', [projectId]),
    query(
      'SELECT id, name, latitude, longitude FROM locations WHERE project_id = $1 ORDER BY created_at LIMIT 3',
      [projectId]
    ),
    query(
      `SELECT id FROM risk_category_catalog WHERE methodology_version_id = $1 AND code = 'ambiental' LIMIT 1`,
      [POP_VERSION_ID]
    ),
    query(
      `SELECT s.id FROM risk_subtype_catalog s
       JOIN risk_category_catalog c ON c.id = s.category_id
       WHERE c.code = 'ambiental' AND s.label ILIKE '%queimada%' LIMIT 1`
    ),
  ]);

  const entityId = people.rows[0]?.id || locations.rows[0]?.id;
  if (!entityId) {
    throw new Error('Cadastre ao menos uma pessoa ou local no projeto antes de carregar o demo POP.');
  }

  const entityType = people.rows[0]?.id ? 'person' : 'location';
  const ambientCatId = ambientCat.rows[0]?.id;
  const burnSubtypeId = burnSubtype.rows[0]?.id;

  // 13.1 — Risco ambiental queimadas (IRE alto em safra)
  const risk131Id = `${DEMO_PREFIX}13-1`;
  const now = new Date();
  const occurredAt = new Date(now.getFullYear(), 6, 15).toISOString().slice(0, 10);
  const reviewDue = new Date(now.getTime() + 45 * 86400000).toISOString().slice(0, 10);

  await query(
    `INSERT INTO project_risks (
       id, project_id, title, description, status, scope,
       related_entity_id, related_entity_type, occurred_at, review_due_at,
       subtype_id, risk_level, factor_overrides, created_by, created_at, updated_at
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,NOW(),NOW())`,
    [
      risk131Id,
      projectId,
      'Pressão de queimadas na área do projeto',
      'Exemplo POP 13.1 — risco ambiental sazonal (jun–nov) com imediatismo elevado.',
      'ativo',
      'localizado',
      entityId,
      entityType,
      occurredAt,
      reviewDue,
      burnSubtypeId || null,
      'entity',
      JSON.stringify({
        'IRE-2': { value: 75, justification: 'Demo POP 13.1 — impacto regional' },
        'IRE-5': { value: 55, justification: 'Demo POP 13.1 — escalada moderada' },
      }),
      actorId,
    ]
  );
  if (ambientCatId) {
    await query(
      'INSERT INTO project_risk_category_links (risk_id, category_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [risk131Id, ambientCatId]
    );
  }
  created.push('13.1-risco-queimadas');

  // 13.2 — Afirmação analítica vinculada a risco formal
  const assertion132Id = `${DEMO_PREFIX}13-2-assertion`;
  await query(
    `INSERT INTO project_assertions (
       id, project_id, text, assertion_type, status,
       related_entity_id, related_entity_type, created_by, created_at, updated_at
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW(),NOW())`,
    [
      assertion132Id,
      projectId,
      'Há indícios de uso do vínculo para articular nova pressão territorial na região.',
      'avaliacao',
      'ativo',
      entityId,
      entityType,
      actorId,
    ]
  );
  created.push('13.2-afirmacao');

  const risk132Id = `${DEMO_PREFIX}13-2-risk`;
  await query(
    `INSERT INTO project_risks (
       id, project_id, title, description, status, scope,
       related_entity_id, related_entity_type, assertion_id, risk_level,
       factor_overrides, created_by, created_at, updated_at
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,NOW(),NOW())`,
    [
      risk132Id,
      projectId,
      'Articulação territorial derivada de afirmação analítica',
      'Exemplo POP 13.2 — risco formal derivado de IC-A (assertion_id vinculado).',
      'monitorando',
      'localizado',
      entityId,
      entityType,
      assertion132Id,
      'entity',
      JSON.stringify({
        'IRE-2': { value: 65, justification: 'Demo POP 13.2 — impacto moderado-alto' },
      }),
      actorId,
    ]
  );
  if (ambientCatId) {
    await query(
      'INSERT INTO project_risk_category_links (risk_id, category_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [risk132Id, ambientCatId]
    );
  }
  created.push('13.2-risco-afirmacao');

  // 13.3 — Abrangência multiterritorial (geo spread)
  const locRows = locations.rows;
  const multiEntityId = locRows[0]?.id || entityId;
  const risk133Id = `${DEMO_PREFIX}13-3`;
  await query(
    `INSERT INTO project_risks (
       id, project_id, title, description, status, scope,
       related_entity_id, related_entity_type, risk_level,
       factor_overrides, created_by, created_at, updated_at
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,NOW(),NOW())`,
    [
      risk133Id,
      projectId,
      'Pressão multiterritorial em múltiplos focos geográficos',
      `Exemplo POP 13.3 — abrangência multiterritorial${locRows.length >= 2 ? ` (${locRows.length} locais georreferenciados)` : ''}.`,
      'ativo',
      'multiterritorial',
      multiEntityId,
      'location',
      'entity',
      JSON.stringify({
        'IRE-2': { value: 80, justification: 'Demo POP 13.3 — impacto amplo' },
        'IRE-4': { value: 60, justification: 'Demo POP 13.3 — multiterritorial' },
      }),
      actorId,
    ]
  );
  const socialCat = await query(
    `SELECT id FROM risk_category_catalog WHERE methodology_version_id = $1 AND code = 'social_juridico' LIMIT 1`,
    [POP_VERSION_ID]
  );
  if (socialCat.rows[0]?.id) {
    await query(
      'INSERT INTO project_risk_category_links (risk_id, category_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [risk133Id, socialCat.rows[0].id]
    );
  }
  created.push('13.3-risco-multiterritorial');

  // Evidência demo para IC-E
  const evId = `${DEMO_PREFIX}13-evidence`;
  await query(
    `INSERT INTO project_evidences (
       id, project_id, title, evidence_type, description, source, confidence,
       validation_status, related_entity_id, related_entity_type, created_at, updated_at
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW(),NOW())`,
    [
      evId,
      projectId,
      'Relatório de monitoramento — focos de calor',
      'documento',
      'Demo POP — evidência para IC-E vinculada à entidade.',
      'Monitoramento satelital (demo)',
      'provavel',
      'pendente',
      entityId,
      entityType,
    ]
  );
  created.push('13-evidencia');

  // Focos de calor demo (IRE-3 fase 3)
  if (locations.rows[0]?.latitude != null) {
    const lat = Number(locations.rows[0].latitude);
    const lon = Number(locations.rows[0].longitude);
    await query('DELETE FROM fire_hotspot_signals WHERE project_id = $1 AND source = $2', [projectId, 'DEMO']);
    const demoFires = [
      { lat: lat + 0.02, lon: lon + 0.01, frp: 55 },
      { lat: lat - 0.01, lon: lon - 0.015, frp: 80 },
    ];
    for (const f of demoFires) {
      await query(
        `INSERT INTO fire_hotspot_signals (id, project_id, latitude, longitude, detected_at, source, frp, synced_at)
         VALUES ($1,$2,$3,$4,NOW(),'DEMO',$5,NOW())`,
        [`${DEMO_PREFIX}fire-${f.lat}`, projectId, f.lat, f.lon, f.frp]
      );
    }
    created.push('13-focos-calor');
  }

  return { created, skipped };
}
