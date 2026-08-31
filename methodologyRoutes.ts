import { Hono } from 'hono';
import { randomUUID } from 'crypto';
import { query } from './db.js';
import { writeAuditLog } from './audit.js';
import { POP_VERSION_ID } from './schemaMethodology.js';
import {
  buildEntitiesFromProject,
  computeIc,
  computeIrr,
  computeIre,
} from './methodology/compute.js';
import type { ComputeContext, FactorScoreResult, IndexAssessmentResult } from './methodology/types.js';
import {
  consolidateIreByCategory,
  consolidateIreForEntity,
  maxIcAmongAssessments,
} from './methodology/consolidate.js';
import { computeDecisionAlerts } from './methodology/alerts.js';
import { seedPopMethodologyExamples } from './methodology/demoSeed.js';

type AuthUser = { id: string; email: string; name?: string; user_type?: string };

export interface MethodologyRouteDeps {
  assertProjectAccess: (c: any, projectId: string) => Promise<AuthUser>;
  assertProjectWrite: (c: any, projectId: string) => Promise<AuthUser>;
  assertProjectCreate: (c: any, projectId: string) => Promise<AuthUser>;
  assertProjectManage: (c: any, projectId: string) => Promise<AuthUser>;
  clientIp: (c: any) => string;
}

async function getActiveVersionId(projectId: string): Promise<string> {
  const proj = await query(
    'SELECT active_methodology_version_id, anchor_entity_id FROM projects WHERE id = $1 LIMIT 1',
    [projectId]
  );
  return proj.rows[0]?.active_methodology_version_id || POP_VERSION_ID;
}

async function loadProjectContext(projectId: string): Promise<ComputeContext> {
  const [proj, people, institutions, activities, locations, relationships, evidences, assertionsRes, fireRes] =
    await Promise.all([
      query('SELECT anchor_entity_id, biome_code FROM projects WHERE id = $1 LIMIT 1', [projectId]),
      query('SELECT id, name, latitude, longitude FROM people WHERE project_id = $1', [projectId]),
      query('SELECT id, name, latitude, longitude FROM institutions WHERE project_id = $1', [projectId]),
      query('SELECT id, name, latitude, longitude FROM activities WHERE project_id = $1', [projectId]),
      query(
        'SELECT id, name, latitude, longitude, territory_geojson, territory_radius_km FROM locations WHERE project_id = $1',
        [projectId]
      ),
      query('SELECT * FROM relationships WHERE project_id = $1', [projectId]),
      query('SELECT * FROM project_evidences WHERE project_id = $1', [projectId]),
      query('SELECT * FROM project_assertions WHERE project_id = $1 AND status = $2', [
        projectId,
        'ativo',
      ]),
      query(
        `SELECT id, latitude, longitude, detected_at, source, frp, confidence
         FROM fire_hotspot_signals
         WHERE project_id = $1 AND detected_at >= NOW() - INTERVAL '30 days'
         ORDER BY detected_at DESC LIMIT 500`,
        [projectId]
      ),
    ]);

  const methodologyVersionId = await getActiveVersionId(projectId);
  const entities = buildEntitiesFromProject({
    people: people.rows,
    institutions: institutions.rows,
    activities: activities.rows,
    locations: locations.rows,
  });

  return {
    projectId,
    methodologyVersionId,
    anchorEntityId: proj.rows[0]?.anchor_entity_id ?? null,
    projectBiome: proj.rows[0]?.biome_code ?? null,
    entities,
    relationships: relationships.rows.map((r: any) => ({
      id: r.id,
      source_id: r.source_id,
      target_id: r.target_id,
      source_type: r.source_type,
      target_type: r.target_type,
      type: r.type,
      level: r.level,
      source: r.source,
      confidence: r.confidence,
      start_date: r.start_date,
      end_date: r.end_date,
      created_at: r.created_at,
      is_active: r.is_active !== false,
      documents: r.documents,
    })),
    evidences: evidences.rows,
    assertions: assertionsRes.rows.map((a: any) => ({
      ...a,
      evidence_ids: Array.isArray(a.evidence_ids) ? a.evidence_ids : [],
    })),
    fireHotspots: fireRes.rows.map((h: any) => ({
      id: h.id,
      latitude: Number(h.latitude),
      longitude: Number(h.longitude),
      detected_at: h.detected_at,
      source: h.source,
      frp: h.frp != null ? Number(h.frp) : null,
      confidence: h.confidence != null ? Number(h.confidence) : null,
    })),
  };
}

async function persistAssessment(
  projectId: string,
  targetType: string,
  targetId: string,
  result: IndexAssessmentResult
): Promise<string> {
  const assessmentId = randomUUID();

  // Supersede previous active assessment for same target+index
  const prev = await query(
    `SELECT id, status FROM index_assessments
     WHERE project_id = $1 AND target_type = $2 AND target_id = $3 AND index_type = $4 AND superseded_by IS NULL
     ORDER BY computed_at DESC LIMIT 1`,
    [projectId, targetType, targetId, result.indexType]
  );
  if (prev.rows[0]) {
    const prevStatus = prev.rows[0].status;
    if (prevStatus === 'VALIDADO') {
      await query(
        `UPDATE index_assessments SET status = 'REVISAR', superseded_by = $1 WHERE id = $2`,
        [assessmentId, prev.rows[0].id]
      );
    } else {
      await query('UPDATE index_assessments SET superseded_by = $1 WHERE id = $2', [
        assessmentId,
        prev.rows[0].id,
      ]);
    }
  }

  await query(
    `INSERT INTO index_assessments (
       id, project_id, methodology_version_id, index_type, target_type, target_id,
       value, band, status, insufficient_reason, computed_at
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())`,
    [
      assessmentId,
      projectId,
      result.methodologyVersionId,
      result.indexType,
      targetType,
      targetId,
      result.value,
      result.band,
      result.status,
      result.insufficientReason ?? null,
    ]
  );

  for (const f of result.factors) {
    await query(
      `INSERT INTO index_factor_scores (
         id, assessment_id, factor_code, is_applicable, auto_value, validated_value,
         effective_value, weight, origin, justification, evidence_refs
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)`,
      [
        randomUUID(),
        assessmentId,
        f.factorCode,
        f.isApplicable,
        f.autoValue,
        f.validatedValue,
        f.effectiveValue,
        f.weight,
        f.origin,
        f.justification ?? null,
        JSON.stringify(f.evidenceRefs ?? []),
      ]
    );
  }

  return assessmentId;
}

async function loadAssessmentDetail(assessmentId: string, projectId: string) {
  const res = await query(
    'SELECT * FROM index_assessments WHERE id = $1 AND project_id = $2 LIMIT 1',
    [assessmentId, projectId]
  );
  if (!res.rows[0]) return null;
  const factors = await query(
    'SELECT * FROM index_factor_scores WHERE assessment_id = $1 ORDER BY factor_code',
    [assessmentId]
  );
  return { ...res.rows[0], factors: factors.rows };
}

export function registerMethodologyRoutes(app: Hono, deps: MethodologyRouteDeps) {
  const { assertProjectAccess, assertProjectWrite, assertProjectCreate, assertProjectManage, clientIp } =
    deps;
  const base = '/api/projects/:projectId/methodology';

  app.get(`${base}/versions`, async (c) => {
    const projectId = c.req.param('projectId');
    await assertProjectAccess(c, projectId);
    const res = await query(
      'SELECT * FROM methodology_versions ORDER BY effective_from DESC'
    );
    return c.json(res.rows);
  });

  app.get(`${base}/versions/active`, async (c) => {
    const projectId = c.req.param('projectId');
    await assertProjectAccess(c, projectId);
    const versionId = await getActiveVersionId(projectId);
    const res = await query('SELECT * FROM methodology_versions WHERE id = $1 LIMIT 1', [versionId]);
    return c.json(res.rows[0] || null);
  });

  app.post(`${base}/versions`, async (c) => {
    const projectId = c.req.param('projectId');
    const actor = await assertProjectManage(c, projectId);
    const body = await c.req.json();
    if (!body?.version_label) return c.json({ error: 'version_label is required' }, 400);

    const id = body.id || `methodology-${Date.now()}`;
    await query(
      `UPDATE methodology_versions SET effective_to = NOW()
       WHERE effective_to IS NULL AND id != $1`,
      [id]
    );
    const res = await query(
      `INSERT INTO methodology_versions (
         id, version_label, description, weights, bands, factor_definitions, author_id, effective_from
       ) VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,$6::jsonb,$7,NOW()) RETURNING *`,
      [
        id,
        body.version_label,
        body.description || '',
        JSON.stringify(body.weights ?? {}),
        JSON.stringify(body.bands ?? { bands: [0, 20, 40, 60, 80, 100] }),
        JSON.stringify(body.factor_definitions ?? {}),
        actor.id,
      ]
    );
    if (body.set_active !== false) {
      await query(
        'UPDATE projects SET active_methodology_version_id = $1, updated_at = NOW() WHERE id = $2',
        [id, projectId]
      );
    }
    await writeAuditLog({
      projectId,
      userId: actor.id,
      userEmail: actor.email,
      action: 'create',
      entityType: 'methodology_version',
      entityId: id,
      entityName: body.version_label,
      summary: `Versão metodológica criada: ${body.version_label}`,
      afterData: { id, version_label: body.version_label },
      ip: clientIp(c),
    });
    return c.json(res.rows[0]);
  });

  app.get(`${base}/risk-categories`, async (c) => {
    const projectId = c.req.param('projectId');
    await assertProjectAccess(c, projectId);
    const versionId = await getActiveVersionId(projectId);
    const res = await query(
      `SELECT * FROM risk_category_catalog
       WHERE (project_id IS NULL OR project_id = $1) AND methodology_version_id = $2 AND is_active = TRUE
       ORDER BY sort_order ASC`,
      [projectId, versionId]
    );
    return c.json(res.rows);
  });

  app.get(`${base}/risk-subtypes`, async (c) => {
    const projectId = c.req.param('projectId');
    await assertProjectAccess(c, projectId);
    const categoryId = c.req.query('categoryId');
    let sql = `SELECT s.*, c.label as category_label, c.code as category_code
               FROM risk_subtype_catalog s
               JOIN risk_category_catalog c ON c.id = s.category_id
               WHERE s.is_active = TRUE`;
    const params: any[] = [];
    if (categoryId) {
      params.push(categoryId);
      sql += ` AND s.category_id = $${params.length}`;
    }
    sql += ' ORDER BY c.sort_order, s.sort_order';
    const res = await query(sql, params);
    return c.json(res.rows);
  });

  // ==================== RISKS CRUD ====================

  app.get(`${base}/risks`, async (c) => {
    const projectId = c.req.param('projectId');
    await assertProjectAccess(c, projectId);
    const res = await query(
      'SELECT * FROM project_risks WHERE project_id = $1 ORDER BY updated_at DESC',
      [projectId]
    );
    const risks = res.rows;
    for (const risk of risks) {
      const cats = await query(
        `SELECT c.* FROM risk_category_catalog c
         JOIN project_risk_category_links l ON l.category_id = c.id
         WHERE l.risk_id = $1`,
        [risk.id]
      );
      risk.categories = cats.rows;
    }
    return c.json(risks);
  });

  app.post(`${base}/risks`, async (c) => {
    const projectId = c.req.param('projectId');
    const actor = await assertProjectCreate(c, projectId);
    const body = await c.req.json();
    if (!body?.title) return c.json({ error: 'title is required' }, 400);

    const id = body.id || `risk-${Date.now()}`;
    const res = await query(
      `INSERT INTO project_risks (
         id, project_id, title, description, status, scope,
         related_entity_id, related_entity_type, relationship_id, evidence_id,
         occurred_at, review_due_at, factor_overrides, subtype_id, assertion_id, risk_level,
         created_by, created_at, updated_at
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15,$16,$17,NOW(),NOW()) RETURNING *`,
      [
        id,
        projectId,
        body.title.trim(),
        body.description || '',
        body.status || 'ativo',
        body.scope || 'pontual',
        body.risk_level === 'project' ? null : body.related_entity_id || null,
        body.risk_level === 'project' ? null : body.related_entity_type || null,
        body.relationship_id || null,
        body.evidence_id || null,
        body.occurred_at || null,
        body.review_due_at || null,
        JSON.stringify(body.factor_overrides ?? {}),
        body.subtype_id || null,
        body.assertion_id || null,
        body.risk_level || 'entity',
        actor.id,
      ]
    );

    const categoryIds: string[] = body.category_ids || [];
    for (const catId of categoryIds) {
      await query(
        'INSERT INTO project_risk_category_links (risk_id, category_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [id, catId]
      );
    }

    await writeAuditLog({
      projectId,
      userId: actor.id,
      userEmail: actor.email,
      action: 'create',
      entityType: 'risk',
      entityId: id,
      entityName: body.title,
      summary: `Risco criado: ${body.title}`,
      afterData: { id, title: body.title, status: body.status },
      ip: clientIp(c),
    });

    return c.json(res.rows[0]);
  });

  app.put(`${base}/risks/:id`, async (c) => {
    const projectId = c.req.param('projectId');
    const actor = await assertProjectWrite(c, projectId);
    const id = c.req.param('id');
    const body = await c.req.json();
    const before = await query('SELECT * FROM project_risks WHERE id = $1 AND project_id = $2', [
      id,
      projectId,
    ]);
    if (!before.rows[0]) return c.json({ error: 'Risco não encontrado' }, 404);

    const res = await query(
      `UPDATE project_risks SET
         title = $1, description = $2, status = $3, scope = $4,
         related_entity_id = $5, related_entity_type = $6, relationship_id = $7,
         evidence_id = $8, occurred_at = $9, review_due_at = $10,
         factor_overrides = $11::jsonb, subtype_id = $12, assertion_id = $13, risk_level = $14,
         updated_at = NOW()
       WHERE id = $15 AND project_id = $16 RETURNING *`,
      [
        body.title ?? before.rows[0].title,
        body.description ?? before.rows[0].description,
        body.status ?? before.rows[0].status,
        body.scope ?? before.rows[0].scope,
        body.related_entity_id !== undefined ? body.related_entity_id : before.rows[0].related_entity_id,
        body.related_entity_type !== undefined ? body.related_entity_type : before.rows[0].related_entity_type,
        body.relationship_id !== undefined ? body.relationship_id : before.rows[0].relationship_id,
        body.evidence_id !== undefined ? body.evidence_id : before.rows[0].evidence_id,
        body.occurred_at !== undefined ? body.occurred_at : before.rows[0].occurred_at,
        body.review_due_at !== undefined ? body.review_due_at : before.rows[0].review_due_at,
        JSON.stringify(body.factor_overrides ?? before.rows[0].factor_overrides ?? {}),
        body.subtype_id !== undefined ? body.subtype_id : before.rows[0].subtype_id,
        body.assertion_id !== undefined ? body.assertion_id : before.rows[0].assertion_id,
        body.risk_level ?? before.rows[0].risk_level ?? 'entity',
        id,
        projectId,
      ]
    );

    if (Array.isArray(body.category_ids)) {
      await query('DELETE FROM project_risk_category_links WHERE risk_id = $1', [id]);
      for (const catId of body.category_ids) {
        await query(
          'INSERT INTO project_risk_category_links (risk_id, category_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [id, catId]
        );
      }
    }

    await writeAuditLog({
      projectId,
      userId: actor.id,
      userEmail: actor.email,
      action: 'update',
      entityType: 'risk',
      entityId: id,
      entityName: res.rows[0].title,
      summary: `Risco atualizado: ${res.rows[0].title}`,
      beforeData: { id, title: before.rows[0].title },
      afterData: { id, title: res.rows[0].title, status: res.rows[0].status },
      ip: clientIp(c),
    });

    return c.json(res.rows[0]);
  });

  app.delete(`${base}/risks/:id`, async (c) => {
    const projectId = c.req.param('projectId');
    const actor = await assertProjectManage(c, projectId);
    const id = c.req.param('id');
    const before = await query('SELECT id, title FROM project_risks WHERE id = $1 AND project_id = $2', [
      id,
      projectId,
    ]);
    await query('DELETE FROM project_risk_category_links WHERE risk_id = $1', [id]);
    await query('DELETE FROM project_risks WHERE id = $1 AND project_id = $2', [id, projectId]);
    if (before.rows[0]) {
      await writeAuditLog({
        projectId,
        userId: actor.id,
        userEmail: actor.email,
        action: 'delete',
        entityType: 'risk',
        entityId: id,
        entityName: before.rows[0].title,
        summary: `Risco removido: ${before.rows[0].title}`,
        ip: clientIp(c),
      });
    }
    return c.json({ ok: true });
  });

  // ==================== ASSERTIONS (IC-A) ====================

  app.get(`${base}/assertions`, async (c) => {
    const projectId = c.req.param('projectId');
    await assertProjectAccess(c, projectId);
    const entityId = c.req.query('entityId');
    let sql = 'SELECT * FROM project_assertions WHERE project_id = $1';
    const params: any[] = [projectId];
    if (entityId) {
      params.push(entityId);
      sql += ` AND related_entity_id = $${params.length}`;
    }
    sql += ' ORDER BY updated_at DESC';
    const res = await query(sql, params);
    return c.json(res.rows);
  });

  app.post(`${base}/assertions`, async (c) => {
    const projectId = c.req.param('projectId');
    const actor = await assertProjectCreate(c, projectId);
    const body = await c.req.json();
    if (!body?.text?.trim()) return c.json({ error: 'text is required' }, 400);
    const id = body.id || `assert-${Date.now()}`;
    const res = await query(
      `INSERT INTO project_assertions (
         id, project_id, text, assertion_type, status,
         related_entity_id, related_entity_type, relationship_id, evidence_ids, created_by, created_at, updated_at
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,NOW(),NOW()) RETURNING *`,
      [
        id,
        projectId,
        body.text.trim(),
        body.assertion_type || 'avaliacao',
        body.status || 'ativo',
        body.related_entity_id || null,
        body.related_entity_type || null,
        body.relationship_id || null,
        JSON.stringify(body.evidence_ids || []),
        actor.id,
      ]
    );
    await writeAuditLog({
      projectId,
      userId: actor.id,
      userEmail: actor.email,
      action: 'create',
      entityType: 'assertion',
      entityId: id,
      summary: `Afirmação criada: ${body.text.slice(0, 80)}`,
      ip: clientIp(c),
    });
    return c.json(res.rows[0]);
  });

  app.put(`${base}/assertions/:id`, async (c) => {
    const projectId = c.req.param('projectId');
    const actor = await assertProjectWrite(c, projectId);
    const id = c.req.param('id');
    const body = await c.req.json();
    const before = await query(
      'SELECT * FROM project_assertions WHERE id = $1 AND project_id = $2',
      [id, projectId]
    );
    if (!before.rows[0]) return c.json({ error: 'Afirmação não encontrada' }, 404);
    const res = await query(
      `UPDATE project_assertions SET
         text = $1, assertion_type = $2, status = $3,
         related_entity_id = $4, related_entity_type = $5, relationship_id = $6,
         evidence_ids = $7::jsonb, updated_at = NOW()
       WHERE id = $8 AND project_id = $9 RETURNING *`,
      [
        body.text ?? before.rows[0].text,
        body.assertion_type ?? before.rows[0].assertion_type,
        body.status ?? before.rows[0].status,
        body.related_entity_id !== undefined ? body.related_entity_id : before.rows[0].related_entity_id,
        body.related_entity_type !== undefined ? body.related_entity_type : before.rows[0].related_entity_type,
        body.relationship_id !== undefined ? body.relationship_id : before.rows[0].relationship_id,
        JSON.stringify(body.evidence_ids ?? before.rows[0].evidence_ids ?? []),
        id,
        projectId,
      ]
    );
    await writeAuditLog({
      projectId,
      userId: actor.id,
      userEmail: actor.email,
      action: 'update',
      entityType: 'assertion',
      entityId: id,
      summary: 'Afirmação atualizada',
      ip: clientIp(c),
    });
    return c.json(res.rows[0]);
  });

  app.delete(`${base}/assertions/:id`, async (c) => {
    const projectId = c.req.param('projectId');
    const actor = await assertProjectManage(c, projectId);
    const id = c.req.param('id');
    await query('DELETE FROM project_assertions WHERE id = $1 AND project_id = $2', [id, projectId]);
    await writeAuditLog({
      projectId,
      userId: actor.id,
      userEmail: actor.email,
      action: 'delete',
      entityType: 'assertion',
      entityId: id,
      summary: 'Afirmação removida',
      ip: clientIp(c),
    });
    return c.json({ ok: true });
  });

  // ==================== ASSESSMENTS ====================

  app.get(`${base}/assessments`, async (c) => {
    const projectId = c.req.param('projectId');
    await assertProjectAccess(c, projectId);
    const indexType = c.req.query('indexType');
    const targetType = c.req.query('targetType');
    const targetId = c.req.query('targetId');
    const status = c.req.query('status');

    let sql = `SELECT * FROM index_assessments WHERE project_id = $1 AND superseded_by IS NULL`;
    const params: any[] = [projectId];
    if (indexType) {
      params.push(indexType);
      sql += ` AND index_type = $${params.length}`;
    }
    if (targetType) {
      params.push(targetType);
      sql += ` AND target_type = $${params.length}`;
    }
    if (targetId) {
      params.push(targetId);
      sql += ` AND target_id = $${params.length}`;
    }
    if (status) {
      params.push(status);
      sql += ` AND status = $${params.length}`;
    }
    sql += ' ORDER BY computed_at DESC LIMIT 500';
    const res = await query(sql, params);
    return c.json(res.rows);
  });

  app.get(`${base}/assessments/:id`, async (c) => {
    const projectId = c.req.param('projectId');
    await assertProjectAccess(c, projectId);
    const id = c.req.param('id');
    const detail = await loadAssessmentDetail(id, projectId);
    if (!detail) return c.json({ error: 'Assessment não encontrado' }, 404);
    return c.json(detail);
  });

  app.post(`${base}/assessments/compute`, async (c) => {
    const projectId = c.req.param('projectId');
    await assertProjectWrite(c, projectId);
    const body = await c.req.json();
    const ctx = await loadProjectContext(projectId);
    const results: Array<{ assessmentId: string; result: IndexAssessmentResult; targetType: string; targetId: string }> = [];

    const scope = body.scope || 'all'; // all | entity | relationship | evidence | assertion | risk

    if (scope === 'all' || scope === 'entity') {
      const entityIds: string[] = body.entityIds || ctx.entities.map((e) => e.id);
      for (const entityId of entityIds) {
        const result = computeIrr(entityId, ctx);
        const assessmentId = await persistAssessment(projectId, 'entity', entityId, result);
        results.push({ assessmentId, result, targetType: 'entity', targetId: entityId });
      }
    }

    if (scope === 'all' || scope === 'relationship') {
      for (const rel of ctx.relationships) {
        const result = computeIc('relationship', rel, ctx);
        const assessmentId = await persistAssessment(projectId, 'relationship', rel.id, result);
        results.push({ assessmentId, result, targetType: 'relationship', targetId: rel.id });
      }
    }

    if (scope === 'all' || scope === 'evidence') {
      for (const ev of ctx.evidences) {
        const result = computeIc('evidence', ev, ctx);
        const assessmentId = await persistAssessment(projectId, 'evidence', ev.id, result);
        results.push({ assessmentId, result, targetType: 'evidence', targetId: ev.id });
      }
    }

    if (scope === 'all' || scope === 'assertion') {
      for (const assertion of ctx.assertions || []) {
        const result = computeIc('assertion', assertion, ctx);
        const assessmentId = await persistAssessment(projectId, 'assertion', assertion.id, result);
        results.push({ assessmentId, result, targetType: 'assertion', targetId: assertion.id });
      }
    }

    if (scope === 'all' || scope === 'risk') {
      const risksRes = await query(
        `SELECT r.*,
                s.label AS subtype_label,
                COALESCE(
                  (SELECT array_agg(c.label) FROM risk_category_catalog c
                   JOIN project_risk_category_links l ON l.category_id = c.id
                   WHERE l.risk_id = r.id),
                  '{}'
                ) AS category_labels
         FROM project_risks r
         LEFT JOIN risk_subtype_catalog s ON s.id = r.subtype_id
         WHERE r.project_id = $1`,
        [projectId]
      );
      for (const risk of risksRes.rows) {
        const riskRecord = {
          ...risk,
          category_labels: Array.isArray(risk.category_labels) ? risk.category_labels : [],
          factor_overrides: risk.factor_overrides || {},
        };
        const result = computeIre(riskRecord, { ...ctx, risk: riskRecord });
        const assessmentId = await persistAssessment(projectId, 'risk', risk.id, result);
        results.push({ assessmentId, result, targetType: 'risk', targetId: risk.id });
      }
    }

    return c.json({ computed: results.length, results });
  });

  app.patch(`${base}/assessments/:id/validate`, async (c) => {
    const projectId = c.req.param('projectId');
    const actor = await assertProjectManage(c, projectId);
    const id = c.req.param('id');
    const res = await query(
      `UPDATE index_assessments SET status = 'VALIDADO', validated_at = NOW(), validated_by = $1
       WHERE id = $2 AND project_id = $3 RETURNING *`,
      [actor.id, id, projectId]
    );
    if (!res.rows[0]) return c.json({ error: 'Assessment não encontrado' }, 404);
    await writeAuditLog({
      projectId,
      userId: actor.id,
      userEmail: actor.email,
      action: 'validate',
      entityType: 'assessment',
      entityId: id,
      summary: `Índice ${res.rows[0].index_type} validado para ${res.rows[0].target_id}`,
      ip: clientIp(c),
    });
    return c.json(res.rows[0]);
  });

  app.patch(`${base}/assessments/:id/analyze`, async (c) => {
    const projectId = c.req.param('projectId');
    const actor = await assertProjectWrite(c, projectId);
    const id = c.req.param('id');
    const res = await query(
      `UPDATE index_assessments SET status = 'EM_ANALISE', computed_at = NOW()
       WHERE id = $1 AND project_id = $2 RETURNING *`,
      [id, projectId]
    );
    if (!res.rows[0]) return c.json({ error: 'Assessment não encontrado' }, 404);
    await writeAuditLog({
      projectId,
      userId: actor.id,
      userEmail: actor.email,
      action: 'update',
      entityType: 'assessment',
      entityId: id,
      summary: `Índice ${res.rows[0].index_type} em análise`,
      ip: clientIp(c),
    });
    return c.json(res.rows[0]);
  });

  app.patch(`${base}/assessments/:id/expire`, async (c) => {
    const projectId = c.req.param('projectId');
    const actor = await assertProjectManage(c, projectId);
    const id = c.req.param('id');
    const res = await query(
      `UPDATE index_assessments SET status = 'EXPIRADO', computed_at = NOW()
       WHERE id = $1 AND project_id = $2 RETURNING *`,
      [id, projectId]
    );
    if (!res.rows[0]) return c.json({ error: 'Assessment não encontrado' }, 404);
    await writeAuditLog({
      projectId,
      userId: actor.id,
      userEmail: actor.email,
      action: 'expire',
      entityType: 'assessment',
      entityId: id,
      summary: `Índice ${res.rows[0].index_type} marcado EXPIRADO`,
      ip: clientIp(c),
    });
    return c.json(res.rows[0]);
  });

  app.patch(`${base}/assessments/:id/factors/:code`, async (c) => {
    const projectId = c.req.param('projectId');
    const actor = await assertProjectManage(c, projectId);
    const assessmentId = c.req.param('id');
    const factorCode = c.req.param('code');
    const body = await c.req.json();

    if (body.validated_value === undefined && body.validatedValue === undefined) {
      return c.json({ error: 'validated_value is required' }, 400);
    }
    const validatedValue = body.validated_value ?? body.validatedValue;
    const justification = body.justification;
    if (!justification || !String(justification).trim()) {
      return c.json({ error: 'justification is required for override' }, 400);
    }

    const assessment = await query(
      'SELECT * FROM index_assessments WHERE id = $1 AND project_id = $2 LIMIT 1',
      [assessmentId, projectId]
    );
    if (!assessment.rows[0]) return c.json({ error: 'Assessment não encontrado' }, 404);

    await query(
      `UPDATE index_factor_scores SET
         validated_value = $1, effective_value = $1, origin = 'override', justification = $2, computed_by = $3
       WHERE assessment_id = $4 AND factor_code = $5`,
      [validatedValue, justification, actor.id, assessmentId, factorCode]
    );

    // Recompute assessment value from factors
    const factorsRes = await query(
      'SELECT * FROM index_factor_scores WHERE assessment_id = $1',
      [assessmentId]
    );
    const factors: FactorScoreResult[] = factorsRes.rows.map((f: any) => ({
      factorCode: f.factor_code,
      isApplicable: f.is_applicable,
      autoValue: f.auto_value != null ? Number(f.auto_value) : null,
      validatedValue: f.validated_value != null ? Number(f.validated_value) : null,
      effectiveValue: f.effective_value != null ? Number(f.effective_value) : null,
      weight: Number(f.weight || 1),
      origin: f.origin,
      justification: f.justification,
    }));

    const applicable = factors.filter((f) => f.isApplicable && f.effectiveValue !== null);
    const value =
      applicable.length >= 3
        ? Math.round(
            applicable.reduce((a, f) => a + (f.effectiveValue ?? 0), 0) / applicable.length
          )
        : null;

    const { classifyBand } = await import('./methodology/scale.js');
    await query(
      `UPDATE index_assessments SET value = $1, band = $2, status = 'PRELIMINAR', computed_at = NOW()
       WHERE id = $3`,
      [value, classifyBand(value), assessmentId]
    );

    await writeAuditLog({
      projectId,
      userId: actor.id,
      userEmail: actor.email,
      action: 'override',
      entityType: 'factor',
      entityId: `${assessmentId}:${factorCode}`,
      summary: `Override ${factorCode} = ${validatedValue}`,
      afterData: { factorCode, validatedValue, justification },
      ip: clientIp(c),
    });

    return c.json({ ok: true, value, band: classifyBand(value) });
  });

  // Entity summary: IRR + IRE consolidated + alerts
  app.get(`${base}/entities/:entityId/summary`, async (c) => {
    const projectId = c.req.param('projectId');
    await assertProjectAccess(c, projectId);
    const entityId = c.req.param('entityId');
    const ctx = await loadProjectContext(projectId);
    const entity = ctx.entities.find((e) => e.id === entityId);

    const irrRes = await query(
      `SELECT * FROM index_assessments
       WHERE project_id = $1 AND target_type = 'entity' AND target_id = $2 AND index_type = 'IRR' AND superseded_by IS NULL
       ORDER BY computed_at DESC LIMIT 1`,
      [projectId, entityId]
    );

    let irr = irrRes.rows[0] || null;
    if (!irr) {
      const computed = computeIrr(entityId, ctx);
      const id = await persistAssessment(projectId, 'entity', entityId, computed);
      irr = { ...computed, id, target_id: entityId };
    }

    const risksRes = await query(
      `SELECT r.*, array_agg(c.label) FILTER (WHERE c.label IS NOT NULL) as category_labels
       FROM project_risks r
       LEFT JOIN project_risk_category_links l ON l.risk_id = r.id
       LEFT JOIN risk_category_catalog c ON c.id = l.category_id
       WHERE r.project_id = $1 AND r.related_entity_id = $2
       GROUP BY r.id`,
      [projectId, entityId]
    );

    const risksWithAssessments = [];
    const icAssessments: IndexAssessmentResult[] = [];

    async function pushIcRow(targetType: string, targetId: string) {
      const icRes = await query(
        `SELECT * FROM index_assessments
         WHERE project_id = $1 AND target_type = $2 AND target_id = $3 AND index_type = 'IC' AND superseded_by IS NULL
         ORDER BY computed_at DESC LIMIT 1`,
        [projectId, targetType, targetId]
      );
      if (icRes.rows[0]) {
        icAssessments.push({
          indexType: 'IC',
          value: icRes.rows[0].value != null ? Number(icRes.rows[0].value) : null,
          band: icRes.rows[0].band,
          status: icRes.rows[0].status,
          methodologyVersionId: icRes.rows[0].methodology_version_id,
          factors: [],
        });
      }
    }

    for (const rel of ctx.relationships.filter(
      (r) => r.source_id === entityId || r.target_id === entityId
    )) {
      await pushIcRow('relationship', rel.id);
    }
    for (const ev of ctx.evidences.filter((e) => e.related_entity_id === entityId)) {
      await pushIcRow('evidence', ev.id);
    }
    for (const assertion of (ctx.assertions || []).filter((a) => a.related_entity_id === entityId)) {
      await pushIcRow('assertion', assertion.id);
    }

    for (const risk of risksRes.rows) {
      const ireRes = await query(
        `SELECT * FROM index_assessments
         WHERE project_id = $1 AND target_type = 'risk' AND target_id = $2 AND index_type = 'IRE' AND superseded_by IS NULL
         ORDER BY computed_at DESC LIMIT 1`,
        [projectId, risk.id]
      );
      let ireAssessment: IndexAssessmentResult;
      if (ireRes.rows[0]) {
        ireAssessment = {
          indexType: 'IRE',
          value: ireRes.rows[0].value != null ? Number(ireRes.rows[0].value) : null,
          band: ireRes.rows[0].band,
          status: ireRes.rows[0].status,
          methodologyVersionId: ireRes.rows[0].methodology_version_id,
          factors: [],
        };
      } else {
        ireAssessment = computeIre({ ...risk, factor_overrides: risk.factor_overrides || {} }, ctx);
      }

      risksWithAssessments.push({
        riskId: risk.id,
        title: risk.title,
        status: risk.status,
        categories: risk.category_labels || [],
        assessment: ireAssessment,
      });
    }

    const ireConsolidated = consolidateIreForEntity(risksWithAssessments);
    const maxIc = maxIcAmongAssessments(icAssessments);

    const irrResult: IndexAssessmentResult = irr.value != null || irr.band
      ? {
          indexType: 'IRR',
          value: irr.value != null ? Number(irr.value) : null,
          band: irr.band,
          status: irr.status,
          methodologyVersionId: irr.methodology_version_id || ctx.methodologyVersionId,
          factors: [],
        }
      : computeIrr(entityId, ctx);

    const ireResult: IndexAssessmentResult | null = ireConsolidated
      ? {
          indexType: 'IRE',
          value: ireConsolidated.value,
          band: ireConsolidated.band,
          status: ireConsolidated.status,
          methodologyVersionId: ctx.methodologyVersionId,
          factors: [],
        }
      : null;

    const alerts = computeDecisionAlerts({
      entityId,
      entityName: entity?.name,
      irr: irrResult,
      ire: ireResult,
      maxIc,
    });

    return c.json({
      entityId,
      entityName: entity?.name,
      irr: irrResult,
      ire: ireResult,
      ireConsolidated,
      maxIc,
      alerts,
      risks: risksWithAssessments,
    });
  });

  // Dashboard aggregations
  app.get(`${base}/dashboard`, async (c) => {
    const projectId = c.req.param('projectId');
    await assertProjectAccess(c, projectId);

    const indexTypeFilter = c.req.query('indexType');
    const statusFilter = c.req.query('status');
    const bandFilter = c.req.query('band');

    const [irrRows, ireRows, icRows, risksRows, pendingRows, expiredRows, revisarRows] = await Promise.all([
      query(
        `SELECT value, band, status, target_id FROM index_assessments
         WHERE project_id = $1 AND index_type = 'IRR' AND target_type = 'entity' AND superseded_by IS NULL`,
        [projectId]
      ),
      query(
        `SELECT value, band, status, target_id FROM index_assessments
         WHERE project_id = $1 AND index_type = 'IRE' AND target_type = 'risk' AND superseded_by IS NULL AND target_id NOT LIKE '%:ic'`,
        [projectId]
      ),
      query(
        `SELECT value, band, status, target_id, target_type FROM index_assessments
         WHERE project_id = $1 AND index_type = 'IC' AND superseded_by IS NULL`,
        [projectId]
      ),
      query(
        `SELECT r.*, a.value as ire_value, a.band as ire_band, a.status as ire_status
         FROM project_risks r
         LEFT JOIN index_assessments a ON a.target_id = r.id AND a.index_type = 'IRE' AND a.superseded_by IS NULL
         WHERE r.project_id = $1 AND r.status = 'ativo'`,
        [projectId]
      ),
      query(
        `SELECT * FROM index_assessments
         WHERE project_id = $1 AND status IN ('PRELIMINAR', 'EM_ANALISE', 'REVISAR') AND superseded_by IS NULL
         ORDER BY computed_at DESC LIMIT 50`,
        [projectId]
      ),
      query(
        `SELECT * FROM index_assessments
         WHERE project_id = $1 AND status = 'EXPIRADO' AND superseded_by IS NULL
         ORDER BY computed_at DESC LIMIT 50`,
        [projectId]
      ),
      query(
        `SELECT * FROM index_assessments
         WHERE project_id = $1 AND status = 'REVISAR' AND superseded_by IS NULL
         ORDER BY computed_at DESC LIMIT 50`,
        [projectId]
      ),
    ]);

    const filterRows = (rows: any[], indexType: string) => {
      let out = rows;
      if (indexTypeFilter && indexTypeFilter !== indexType) return [];
      if (statusFilter) out = out.filter((r) => r.status === statusFilter);
      if (bandFilter) out = out.filter((r) => r.band === bandFilter);
      return out;
    };

    const distribution = (rows: any[]) => {
      const bands: Record<string, number> = {};
      for (const r of rows) {
        const b = r.band || 'INSUFICIENTE';
        bands[b] = (bands[b] || 0) + 1;
      }
      return bands;
    };

    const irrFiltered = filterRows(irrRows.rows, 'IRR');
    const ireFiltered = filterRows(ireRows.rows, 'IRE');
    const icFiltered = filterRows(icRows.rows, 'IC');

    const criticalRisks = risksRows.rows.filter(
      (r: any) => r.ire_value != null && Number(r.ire_value) >= 80
    );

    // IRE por categoria
    const ireByCategory: Record<string, { value: number; band: string; riskTitle: string }> = {};
    for (const risk of risksRows.rows) {
      if (!risk.ire_value) continue;
      const cats = await query(
        `SELECT c.label FROM risk_category_catalog c
         JOIN project_risk_category_links l ON l.category_id = c.id WHERE l.risk_id = $1`,
        [risk.id]
      );
      for (const cat of cats.rows) {
        const label = cat.label;
        const val = Number(risk.ire_value);
        if (!ireByCategory[label] || val > ireByCategory[label].value) {
          ireByCategory[label] = { value: val, band: risk.ire_band, riskTitle: risk.title };
        }
      }
    }

    // Decision alerts — entidades com riscos ativos
    const entityIds = new Set<string>();
    for (const r of risksRows.rows) {
      if (r.related_entity_id) entityIds.add(r.related_entity_id);
    }
    const decisionAlerts: any[] = [];
    const lowConfidenceHighIre: any[] = [];
    const highConfidenceHighIre: any[] = [];

    for (const eid of entityIds) {
      const irrRes = await query(
        `SELECT value, band, status FROM index_assessments
         WHERE project_id = $1 AND index_type = 'IRR' AND target_type = 'entity' AND target_id = $2 AND superseded_by IS NULL LIMIT 1`,
        [projectId, eid]
      );
      const entityRisks = risksRows.rows.filter((r: any) => r.related_entity_id === eid);
      const risksWithAssessments = entityRisks.map((risk: any) => ({
        riskId: risk.id,
        title: risk.title,
        status: risk.status,
        categories: [],
        assessment: {
          indexType: 'IRE' as const,
          value: risk.ire_value != null ? Number(risk.ire_value) : null,
          band: risk.ire_band || 'INSUFICIENTE',
          status: risk.ire_status || 'PRELIMINAR',
          methodologyVersionId: '',
          factors: [],
        },
      }));
      const ireConsolidated = consolidateIreForEntity(risksWithAssessments);
      const icRes = await query(
        `SELECT MAX(value) as max_ic FROM index_assessments
         WHERE project_id = $1 AND index_type = 'IC' AND superseded_by IS NULL
         AND target_id IN (SELECT id FROM project_risks WHERE related_entity_id = $2)`,
        [projectId, eid]
      );
      const maxIc = icRes.rows[0]?.max_ic != null ? Number(icRes.rows[0].max_ic) : null;

      const irrRow = irrRes.rows[0];
      const irrResult = irrRow
        ? {
            indexType: 'IRR' as const,
            value: irrRow.value != null ? Number(irrRow.value) : null,
            band: irrRow.band,
            status: irrRow.status,
            methodologyVersionId: '',
            factors: [],
          }
        : null;
      const ireResult = ireConsolidated
        ? {
            indexType: 'IRE' as const,
            value: ireConsolidated.value,
            band: ireConsolidated.band,
            status: ireConsolidated.status,
            methodologyVersionId: '',
            factors: [],
          }
        : null;

      const alerts = computeDecisionAlerts({
        entityId: eid,
        irr: irrResult,
        ire: ireResult,
        maxIc,
      });
      decisionAlerts.push(...alerts);

      if (ireResult?.value != null && ireResult.value >= 61) {
        const item = { entityId: eid, ire: ireResult.value, maxIc };
        if (maxIc == null || maxIc <= 40) lowConfidenceHighIre.push(item);
        if (maxIc != null && maxIc >= 61) highConfidenceHighIre.push(item);
      }
    }

    return c.json({
      irrDistribution: distribution(irrFiltered),
      ireDistribution: distribution(ireFiltered),
      icDistribution: distribution(icFiltered),
      criticalRisks,
      pendingValidation: pendingRows.rows,
      expiredAssessments: expiredRows.rows,
      revisarAssessments: revisarRows.rows,
      ireByCategory,
      decisionAlerts: decisionAlerts.slice(0, 30),
      lowConfidenceHighIre,
      highConfidenceHighIre,
      totals: {
        irr: irrFiltered.length,
        ire: ireFiltered.length,
        ic: icFiltered.length,
        activeRisks: risksRows.rows.length,
      },
    });
  });

  // Demo POP 13.1–13.3 (REDD+ examples)
  app.post(`${base}/demo-seed`, async (c) => {
    const projectId = c.req.param('projectId');
    const actor = await assertProjectManage(c, projectId);
    try {
      const result = await seedPopMethodologyExamples(projectId, actor.id);
      await writeAuditLog({
        projectId,
        userId: actor.id,
        userEmail: actor.email,
        action: 'create',
        entityType: 'methodology_demo',
        entityId: projectId,
        summary: `Demo POP seed: ${result.created.join(', ') || 'skipped'}`,
        afterData: result,
        ip: clientIp(c),
      });
      return c.json(result);
    } catch (e: any) {
      return c.json({ error: e.message || 'Erro ao carregar demo' }, 400);
    }
  });

  // Update project anchor
  app.patch(`${base}/project-settings`, async (c) => {
    const projectId = c.req.param('projectId');
    const actor = await assertProjectManage(c, projectId);
    const body = await c.req.json();
    const res = await query(
      `UPDATE projects SET
         anchor_entity_id = COALESCE($1, anchor_entity_id),
         active_methodology_version_id = COALESCE($2, active_methodology_version_id),
         updated_at = NOW()
       WHERE id = $3 RETURNING id, anchor_entity_id, active_methodology_version_id`,
      [body.anchor_entity_id ?? null, body.active_methodology_version_id ?? null, projectId]
    );
    await writeAuditLog({
      projectId,
      userId: actor.id,
      userEmail: actor.email,
      action: 'update',
      entityType: 'project_methodology',
      entityId: projectId,
      summary: 'Configurações metodológicas atualizadas',
      afterData: body,
      ip: clientIp(c),
    });
    return c.json(res.rows[0]);
  });
}
