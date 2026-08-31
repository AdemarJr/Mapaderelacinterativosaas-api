import type {
  ComputeContext,
  GraphEntity,
  GraphEvidence,
  GraphRelationship,
  IndexAssessmentResult,
  IndexType,
  ProjectRiskRecord,
  AssertionRecord,
} from './types.js';
import { computeIndexFromFactors } from './formula.js';
import { computeIrrFactors } from './factors/irr.js';
import { computeIreFactors } from './factors/ire.js';
import {
  computeIcFactorsForEvidence,
  computeIcFactorsForRelationship,
  computeIcFactorsForAssertion,
} from './factors/ic.js';

export function computeIrr(entityId: string, ctx: ComputeContext): IndexAssessmentResult {
  const factors = computeIrrFactors(entityId, ctx);
  return computeIndexFromFactors('IRR', ctx.methodologyVersionId, factors);
}

export function computeIre(risk: ProjectRiskRecord, ctx: ComputeContext): IndexAssessmentResult {
  const factors = computeIreFactors(risk, ctx);
  return computeIndexFromFactors('IRE', ctx.methodologyVersionId, factors);
}

export function computeIc(
  targetType: 'relationship' | 'evidence' | 'assertion',
  target: GraphRelationship | GraphEvidence | AssertionRecord,
  ctx: ComputeContext
): IndexAssessmentResult {
  let factors;
  if (targetType === 'relationship') {
    factors = computeIcFactorsForRelationship(target as GraphRelationship, ctx);
  } else if (targetType === 'evidence') {
    factors = computeIcFactorsForEvidence(target as GraphEvidence, ctx);
  } else {
    factors = computeIcFactorsForAssertion(target as AssertionRecord, ctx);
  }
  return computeIndexFromFactors('IC', ctx.methodologyVersionId, factors);
}

export function buildEntitiesFromProject(data: {
  people?: Array<{ id: string; name: string; latitude?: number | null; longitude?: number | null }>;
  institutions?: Array<{ id: string; name: string; latitude?: number | null; longitude?: number | null }>;
  activities?: Array<{ id: string; name: string; latitude?: number | null; longitude?: number | null }>;
  locations?: Array<{
    id: string;
    name: string;
    latitude?: number | null;
    longitude?: number | null;
    territory_geojson?: unknown | null;
    territory_radius_km?: number | null;
  }>;
}): GraphEntity[] {
  const out: GraphEntity[] = [];
  const push = (
    rows: Array<{ id: string; name: string; latitude?: number | null; longitude?: number | null }> | undefined,
    kind: GraphEntity['kind']
  ) => {
    for (const row of rows || []) {
      out.push({
        id: row.id,
        name: row.name,
        kind,
        latitude: row.latitude ?? null,
        longitude: row.longitude ?? null,
      });
    }
  };
  push(data.people, 'person');
  push(data.institutions, 'institution');
  push(data.activities, 'activity');
  for (const row of data.locations || []) {
    out.push({
      id: row.id,
      name: row.name,
      kind: 'location',
      latitude: row.latitude ?? null,
      longitude: row.longitude ?? null,
      territory_geojson: row.territory_geojson ?? null,
      territory_radius_km: row.territory_radius_km ?? null,
    });
  }
  return out;
}

export function computeAllIrrForProject(
  ctx: ComputeContext,
  entityIds?: string[]
): Map<string, IndexAssessmentResult> {
  const ids = entityIds ?? ctx.entities.map((e) => e.id);
  const map = new Map<string, IndexAssessmentResult>();
  for (const id of ids) {
    map.set(id, computeIrr(id, ctx));
  }
  return map;
}

export type { IndexType };
