import type { ComputeContext, ProjectRiskRecord } from '../types.js';
import { makeFactor } from '../formula.js';
import { recencyToScore, scopeToScore, reviewDueUrgencyScore, burnSeasonImmediacyBoost } from '../scale.js';
import { inferScopeFromGeoSpread, geoScopeToScore, fireSignalsNearEntity, resolveBiomeForEntity } from '../geo.js';
import { fireImmediacyBoost } from '../fireHotspots.js';

function overrideValue(
  overrides: Record<string, { value?: number; validatedValue?: number; justification?: string }>,
  code: string,
  auto: number | null
): { value: number | null; origin: 'automatic' | 'override'; justification?: string } {
  const o = overrides[code];
  if (o?.validatedValue != null) {
    return { value: o.validatedValue, origin: 'override', justification: o.justification };
  }
  if (o?.value != null) {
    return { value: o.value, origin: 'override', justification: o.justification };
  }
  return { value: auto, origin: 'automatic' };
}

function computeIre3Auto(risk: ProjectRiskRecord, ctx: ComputeContext): number {
  const occurred = recencyToScore(risk.occurred_at);
  const due = reviewDueUrgencyScore(risk.review_due_at);
  const base = Math.max(
    occurred ?? 0,
    due ?? 0,
    risk.status === 'ativo' ? 70 : risk.status === 'monitorando' ? 50 : 30
  );
  const entity = ctx.entities.find((e) => e.id === risk.related_entity_id);
  const biome = resolveBiomeForEntity(entity, ctx.projectBiome ?? null);
  const seasonBoost = burnSeasonImmediacyBoost(risk.subtype_label, risk.category_labels, new Date(), biome);
  const fire = fireSignalsNearEntity(risk.related_entity_id, ctx);
  const fireBoost = fireImmediacyBoost(fire.count, fire.maxFrp);
  return Math.min(100, base + seasonBoost + fireBoost);
}

function computeIre4Auto(risk: ProjectRiskRecord, ctx: ComputeContext): number {
  const manualScope = risk.risk_level === 'project' ? 'projeto' : risk.scope || 'pontual';
  const manualScore = scopeToScore(manualScope);

  const geoScope = inferScopeFromGeoSpread(
    risk.related_entity_id,
    ctx,
    risk.risk_level
  );
  const geoScore = geoScopeToScore(geoScope);

  if (risk.risk_level === 'project') return manualScore;
  if (!risk.related_entity_id) return manualScore;

  return Math.max(manualScore, geoScore);
}

export function computeIreFactors(
  risk: ProjectRiskRecord,
  ctx: ComputeContext
): ReturnType<typeof makeFactor>[] {
  const overrides = { ...ctx.existingOverrides, ...(risk.factor_overrides || {}) };

  let ire1Auto = 40;
  if (risk.status === 'ativo') ire1Auto = 70;
  if (risk.status === 'monitorando') ire1Auto = 50;
  if (risk.status === 'mitigado' || risk.status === 'encerrado') ire1Auto = 10;
  const ire1 = overrideValue(overrides, 'IRE-1', ire1Auto);

  const ire2 = overrideValue(overrides, 'IRE-2', 60);

  const ire3Auto = computeIre3Auto(risk, ctx);
  const ire3 = overrideValue(overrides, 'IRE-3', ire3Auto);

  const ire4Auto = computeIre4Auto(risk, ctx);
  const ire4 = overrideValue(overrides, 'IRE-4', ire4Auto);

  let ire5Auto = 40;
  if (risk.related_entity_id) {
    const connections = ctx.relationships.filter(
      (r) =>
        r.is_active !== false &&
        (r.source_id === risk.related_entity_id || r.target_id === risk.related_entity_id)
    ).length;
    ire5Auto = Math.min(100, 20 + connections * 5);
  }
  const ire5 = overrideValue(overrides, 'IRE-5', ire5Auto);

  return [
    makeFactor('IRE-1', ire1.value, {
      validatedValue: ire1.origin === 'override' ? ire1.value : null,
      origin: ire1.origin,
      justification: ire1.justification,
    }),
    makeFactor('IRE-2', ire2.value, {
      validatedValue: ire2.origin === 'override' ? ire2.value : null,
      origin: ire2.origin,
      justification: ire2.justification,
    }),
    makeFactor('IRE-3', ire3.value, {
      validatedValue: ire3.origin === 'override' ? ire3.value : null,
      origin: ire3.origin,
      justification: ire3.justification,
    }),
    makeFactor('IRE-4', ire4.value, {
      validatedValue: ire4.origin === 'override' ? ire4.value : null,
      origin: ire4.origin,
      justification: ire4.justification,
    }),
    makeFactor('IRE-5', ire5.value, {
      validatedValue: ire5.origin === 'override' ? ire5.value : null,
      origin: ire5.origin,
      justification: ire5.justification,
    }),
  ];
}
