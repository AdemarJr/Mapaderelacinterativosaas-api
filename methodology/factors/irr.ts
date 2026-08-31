import type { ComputeContext, GraphEntity, GraphRelationship } from '../types.js';
import { makeFactor } from '../formula.js';
import {
  connectionCountToScore,
  diversityToScore,
  hopsToProximityScore,
  recencyToScore,
  centralityToScore,
} from '../scale.js';

function buildAdj(rels: GraphRelationship[]): Map<string, Set<string>> {
  const adj = new Map<string, Set<string>>();
  const touch = (a: string, b: string) => {
    if (!adj.has(a)) adj.set(a, new Set());
    if (!adj.has(b)) adj.set(b, new Set());
    adj.get(a)!.add(b);
    adj.get(b)!.add(a);
  };
  for (const r of rels) {
    if (r.is_active === false) continue;
    touch(r.source_id, r.target_id);
  }
  return adj;
}

function bfsHops(adj: Map<string, Set<string>>, fromId: string, toId: string): number | null {
  if (!fromId || !toId) return null;
  if (fromId === toId) return 0;
  const queue: string[] = [fromId];
  const dist = new Map<string, number>([[fromId, 0]]);
  while (queue.length) {
    const cur = queue.shift()!;
    const d = dist.get(cur)!;
    for (const nb of adj.get(cur) || []) {
      if (dist.has(nb)) continue;
      dist.set(nb, d + 1);
      if (nb === toId) return d + 1;
      queue.push(nb);
    }
  }
  return null;
}

function localBridgeScore(entityId: string, adj: Map<string, Set<string>>): number {
  const neighbors = [...(adj.get(entityId) || [])];
  if (neighbors.length < 2) return 0;
  let bridgePairs = 0;
  for (let i = 0; i < neighbors.length; i++) {
    for (let j = i + 1; j < neighbors.length; j++) {
      const a = neighbors[i];
      const b = neighbors[j];
      const aNeighbors = adj.get(a) || new Set();
      if (!aNeighbors.has(b)) bridgePairs++;
    }
  }
  const maxPairs = (neighbors.length * (neighbors.length - 1)) / 2;
  return maxPairs > 0 ? Math.round((bridgePairs / maxPairs) * 100) : 0;
}

function entityKindFromType(type?: string): string {
  const t = String(type || '').toLowerCase();
  if (t.includes('person') || t === 'people') return 'person';
  if (t.includes('institution')) return 'institution';
  if (t.includes('activ')) return 'activity';
  if (t.includes('location')) return 'location';
  return 'unknown';
}

export function computeIrrFactors(
  entityId: string,
  ctx: ComputeContext
): ReturnType<typeof makeFactor>[] {
  const activeRels = ctx.relationships.filter((r) => r.is_active !== false);
  const adj = buildAdj(activeRels);
  const overrides = ctx.existingOverrides || {};

  // IRR-1 Proximidade
  let irr1: number | null = null;
  if (ctx.anchorEntityId) {
    const hops = bfsHops(adj, entityId, ctx.anchorEntityId);
    irr1 = hopsToProximityScore(hops);
  }

  // IRR-2 Quantidade de vínculos
  const connections = activeRels.filter(
    (r) => r.source_id === entityId || r.target_id === entityId
  ).length;
  const irr2 = connectionCountToScore(connections);

  // IRR-3 Diversidade
  const neighborKinds = new Set<string>();
  for (const r of activeRels) {
    if (r.source_id === entityId) neighborKinds.add(entityKindFromType(r.target_type));
    if (r.target_id === entityId) neighborKinds.add(entityKindFromType(r.source_type));
  }
  neighborKinds.delete('unknown');
  const irr3 = diversityToScore(neighborKinds.size);

  // IRR-4 Recorrência / atualidade
  const entityRels = activeRels.filter(
    (r) => r.source_id === entityId || r.target_id === entityId
  );
  const dates = entityRels
    .map((r) => r.end_date || r.start_date || r.created_at)
    .filter(Boolean) as string[];
  const recencyScores = dates.map((d) => recencyToScore(d)).filter((v) => v !== null) as number[];
  const irr4 =
    recencyScores.length > 0
      ? Math.round(recencyScores.reduce((a, b) => a + b, 0) / recencyScores.length)
      : connections > 0
        ? 40
        : null;

  // IRR-5 Centralidade estratégica
  const bridge = localBridgeScore(entityId, adj);
  const irr5 = connections > 0 ? centralityToScore(bridge, connections) : null;

  const o5 = overrides['IRR-5'];

  return [
    makeFactor('IRR-1', irr1, { isApplicable: irr1 !== null }),
    makeFactor('IRR-2', irr2),
    makeFactor('IRR-3', irr3),
    makeFactor('IRR-4', irr4, { isApplicable: irr4 !== null }),
    makeFactor('IRR-5', irr5, {
      isApplicable: irr5 !== null,
      validatedValue: o5?.validatedValue ?? null,
      justification: o5?.justification,
      origin: o5 ? 'override' : 'automatic',
    }),
  ];
}

export function resolveAnchorEntity(
  anchorEntityId: string | null | undefined,
  entities: GraphEntity[],
  hubFrontEntityId?: string | null
): string | null {
  if (anchorEntityId && entities.some((e) => e.id === anchorEntityId)) return anchorEntityId;
  if (hubFrontEntityId && entities.some((e) => e.id === hubFrontEntityId)) return hubFrontEntityId;
  return entities[0]?.id ?? null;
}
