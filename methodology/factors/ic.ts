import type { ComputeContext, GraphEvidence, GraphRelationship, AssertionRecord } from '../types.js';
import { makeFactor } from '../formula.js';
import { confidenceToIcScore, recencyToScore } from '../scale.js';

function hasSource(r: GraphRelationship | GraphEvidence): boolean {
  return Boolean(String((r as GraphRelationship).source || (r as GraphEvidence).source || '').trim());
}

export function computeIcFactorsForRelationship(
  relationship: GraphRelationship,
  ctx: ComputeContext
): ReturnType<typeof makeFactor>[] {
  const overrides = ctx.existingOverrides || {};
  const relEvidences = ctx.evidences.filter((e) => e.relationship_id === relationship.id);

  // IC-1 Qualidade da fonte
  let ic1: number | null = null;
  if (hasSource(relationship)) ic1 = 60;
  if ((relationship.documents || []).some((d) => (d.url || '').trim())) ic1 = 80;
  const ic1Override = overrides['IC-1'];

  // IC-2 Fontes independentes
  const sources = new Set<string>();
  if (relationship.source) sources.add(relationship.source.trim().toLowerCase());
  for (const e of relEvidences) {
    if (e.source) sources.add(e.source.trim().toLowerCase());
    if (e.source_independence) sources.add(`indep:${e.source_independence}`);
  }
  const ic2 = sources.size >= 3 ? 100 : sources.size === 2 ? 70 : sources.size === 1 ? 40 : 0;

  // IC-3 Confirmação cruzada
  const types = new Set<string>();
  if (relationship.confidence) types.add('confidence');
  if (relEvidences.length) types.add('evidence');
  if ((relationship.documents || []).length) types.add('document');
  const ic3 = types.size >= 3 ? 90 : types.size === 2 ? 65 : types.size === 1 ? 40 : 20;

  // IC-4 Atualidade
  const dates = [
    relationship.end_date,
    relationship.start_date,
    relationship.created_at,
    ...relEvidences.map((e) => e.occurred_at),
  ].filter(Boolean) as string[];
  const recency = dates.map((d) => recencyToScore(d)).filter((v) => v !== null) as number[];
  const ic4 =
    recency.length > 0
      ? Math.round(recency.reduce((a, b) => a + b, 0) / recency.length)
      : confidenceToIcScore(relationship.confidence);

  // Fallback from legacy confidence if factors sparse
  const confScore = confidenceToIcScore(relationship.confidence);

  return [
    makeFactor('IC-1', ic1 ?? confScore, {
      isApplicable: ic1 !== null || confScore !== null,
      validatedValue: ic1Override?.validatedValue ?? null,
      origin: ic1Override ? 'override' : 'automatic',
      justification: ic1Override?.justification,
    }),
    makeFactor('IC-2', ic2, { isApplicable: sources.size > 0 }),
    makeFactor('IC-3', ic3),
    makeFactor('IC-4', ic4, { isApplicable: ic4 !== null }),
  ];
}

export function computeIcFactorsForEvidence(
  evidence: GraphEvidence,
  ctx: ComputeContext
): ReturnType<typeof makeFactor>[] {
  const overrides = ctx.existingOverrides || {};

  const ic1 = hasSource(evidence) ? 70 : null;
  const ic2 = evidence.source_independence ? 80 : evidence.source ? 50 : 20;
  const ic3 =
    evidence.validation_status === 'validado'
      ? 90
      : evidence.validation_status === 'pendente'
        ? 40
        : 60;
  const ic4 = recencyToScore(evidence.occurred_at) ?? 50;

  const ic1Override = overrides['IC-1'];

  return [
    makeFactor('IC-1', ic1, {
      isApplicable: ic1 !== null,
      validatedValue: ic1Override?.validatedValue ?? null,
      origin: ic1Override ? 'override' : 'automatic',
    }),
    makeFactor('IC-2', ic2),
    makeFactor('IC-3', ic3),
    makeFactor('IC-4', ic4),
  ];
}

export function computeIcFactorsForAssertion(
  assertion: AssertionRecord,
  ctx: ComputeContext
): ReturnType<typeof makeFactor>[] {
  const overrides = ctx.existingOverrides || {};
  const evidenceIds = Array.isArray(assertion.evidence_ids) ? assertion.evidence_ids : [];
  const linkedEvidences = ctx.evidences.filter((e) => evidenceIds.includes(e.id));

  const ic1 = assertion.text?.trim().length > 20 ? 50 : 30;
  const ic1Override = overrides['IC-1'];

  const indepGroups = new Set<string>();
  for (const e of linkedEvidences) {
    if (e.source_independence) indepGroups.add(`indep:${e.source_independence}`);
    else if (e.source) indepGroups.add(e.source.trim().toLowerCase());
  }
  const ic2 = indepGroups.size >= 3 ? 100 : indepGroups.size === 2 ? 70 : indepGroups.size === 1 ? 40 : 15;

  const types = new Set<string>();
  for (const e of linkedEvidences) {
    if (e.evidence_type) types.add(e.evidence_type);
    if (e.validation_status === 'validado') types.add('validado');
  }
  const ic3 = types.size >= 3 ? 85 : types.size === 2 ? 60 : types.size === 1 ? 40 : 20;

  const dates = linkedEvidences.map((e) => e.occurred_at).filter(Boolean) as string[];
  const recency = dates.map((d) => recencyToScore(d)).filter((v) => v !== null) as number[];
  const ic4 =
    recency.length > 0
      ? Math.round(recency.reduce((a, b) => a + b, 0) / recency.length)
      : linkedEvidences.length > 0
        ? 45
        : 20;

  return [
    makeFactor('IC-1', ic1, {
      validatedValue: ic1Override?.validatedValue ?? null,
      origin: ic1Override ? 'override' : 'automatic',
      justification: ic1Override?.justification,
    }),
    makeFactor('IC-2', ic2, { isApplicable: linkedEvidences.length > 0 || indepGroups.size > 0 }),
    makeFactor('IC-3', ic3),
    makeFactor('IC-4', ic4),
  ];
}
