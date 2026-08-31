import type { ComputeContext, GraphEntity } from './types.js';
import { detectBiome, isBurnSeasonForBiome, type BiomeCode } from './biomes.js';
import {
  bboxOverlapRatio,
  circlePolygon,
  parseTerritoryGeometry,
  pointInTerritory,
  polygonAreaKm2,
  type TerritoryGeometry,
} from './polygon.js';

const EARTH_RADIUS_M = 6_371_000;

export function haversineMeters(
  lat1: number,
  lon1: number,
  lat2: number,
  lon2: number
): number {
  const toRad = (d: number) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 2 * EARTH_RADIUS_M * Math.asin(Math.sqrt(a));
}

export function isValidCoord(lat?: number | null, lon?: number | null): boolean {
  if (lat == null || lon == null) return false;
  if (Number.isNaN(lat) || Number.isNaN(lon)) return false;
  return lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180;
}

export function entityCoords(entity?: GraphEntity | null): { lat: number; lon: number } | null {
  if (!entity) return null;
  const lat = entity.latitude;
  const lon = entity.longitude;
  return isValidCoord(lat, lon) ? { lat: lat!, lon: lon! } : null;
}

/** @deprecated use isBurnSeasonForBiome — mantido para compatibilidade Amazônia. */
export function isBurnSeason(date = new Date()): boolean {
  return isBurnSeasonForBiome('amazonia', date);
}

export function resolveBiomeForEntity(
  entity?: GraphEntity | null,
  projectBiome?: BiomeCode | null
): BiomeCode {
  if (projectBiome && projectBiome !== 'unknown') return projectBiome;
  const c = entityCoords(entity);
  if (!c) return 'unknown';
  return detectBiome(c.lat, c.lon);
}

export function territoryForEntity(entity?: GraphEntity | null): TerritoryGeometry | null {
  if (!entity) return null;
  const parsed = parseTerritoryGeometry(entity.territory_geojson);
  if (parsed) return parsed;
  const c = entityCoords(entity);
  const radiusKm = entity.territory_radius_km;
  if (c && radiusKm != null && radiusKm > 0) {
    return circlePolygon(c.lat, c.lon, Number(radiusKm));
  }
  return null;
}

export function isBurnRiskSubtype(subtypeLabel?: string | null): boolean {
  const s = String(subtypeLabel || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '');
  return s.includes('queimada') || s.includes('incendio');
}

export function isAmbientRiskCategory(categoryLabels?: string[]): boolean {
  if (!categoryLabels?.length) return false;
  return categoryLabels.some((c) => {
    const n = c.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    return n.includes('ambient');
  });
}

function neighborsWithinRadius(
  entityId: string,
  ctx: ComputeContext,
  radiusMeters: number
): GraphEntity[] {
  const anchor = ctx.entities.find((e) => e.id === entityId);
  const anchorCoords = entityCoords(anchor);
  if (!anchorCoords) return [];

  const out: GraphEntity[] = [];
  for (const e of ctx.entities) {
    if (e.id === entityId) continue;
    const c = entityCoords(e);
    if (!c) continue;
    if (haversineMeters(anchorCoords.lat, anchorCoords.lon, c.lat, c.lon) <= radiusMeters) {
      out.push(e);
    }
  }
  return out;
}

/** Conta clusters geográficos distintos (> clusterGap km entre centros). */
export function countGeoClusters(
  points: Array<{ lat: number; lon: number }>,
  clusterGapMeters = 80_000
): number {
  if (!points.length) return 0;
  const clusters: Array<{ lat: number; lon: number }> = [];
  for (const p of points) {
    let merged = false;
    for (const c of clusters) {
      if (haversineMeters(p.lat, p.lon, c.lat, c.lon) <= clusterGapMeters) {
        merged = true;
        break;
      }
    }
    if (!merged) clusters.push(p);
  }
  return clusters.length;
}

export function inferScopeFromGeoSpread(
  entityId: string | null | undefined,
  ctx: ComputeContext,
  riskLevel?: string | null
): 'pontual' | 'localizado' | 'multiterritorial' | 'amplo' | 'projeto' {
  if (riskLevel === 'project') return 'projeto';
  if (!entityId) return 'pontual';

  const anchor = ctx.entities.find((e) => e.id === entityId);
  const anchorTerritory = territoryForEntity(anchor);
  const anchorCoords = entityCoords(anchor);

  if (anchorTerritory) {
    let overlapCount = 0;
    let maxOverlap = 0;
    for (const e of ctx.entities) {
      if (e.id === entityId) continue;
      const t = territoryForEntity(e);
      if (!t) continue;
      const ratio = bboxOverlapRatio(anchorTerritory, t);
      if (ratio > 0.05) overlapCount++;
      maxOverlap = Math.max(maxOverlap, ratio);
    }
    if (overlapCount >= 3 || maxOverlap >= 0.35) return 'multiterritorial';
    if (overlapCount >= 1 || maxOverlap >= 0.12) return 'localizado';
    const areaKm2 = polygonAreaKm2(anchorTerritory);
    if (areaKm2 >= 5000) return 'multiterritorial';
    if (areaKm2 >= 500) return 'localizado';
  }

  if (!anchorCoords) return 'pontual';

  const nearby25 = neighborsWithinRadius(entityId, ctx, 25_000);
  const nearby100 = neighborsWithinRadius(entityId, ctx, 100_000);

  const relLinked = new Set<string>();
  for (const r of ctx.relationships) {
    if (r.is_active === false) continue;
    if (r.source_id === entityId) relLinked.add(r.target_id);
    if (r.target_id === entityId) relLinked.add(r.source_id);
  }

  const geoPoints: Array<{ lat: number; lon: number }> = [anchorCoords];
  for (const id of relLinked) {
    const e = ctx.entities.find((x) => x.id === id);
    const c = entityCoords(e);
    if (c) geoPoints.push(c);
  }

  const clusters = countGeoClusters(geoPoints);

  if (nearby100.length >= 6 || clusters >= 4) return 'multiterritorial';
  if (nearby25.length >= 3 || clusters >= 2) return 'localizado';
  if (nearby100.length >= 1) return 'localizado';
  return 'pontual';
}

export function fireSignalsNearEntity(
  entityId: string | null | undefined,
  ctx: ComputeContext
): { count: number; maxFrp: number } {
  const hotspots = ctx.fireHotspots || [];
  if (!entityId || !hotspots.length) return { count: 0, maxFrp: 0 };

  const entity = ctx.entities.find((e) => e.id === entityId);
  const territory = territoryForEntity(entity);
  if (territory) {
    let count = 0;
    let maxFrp = 0;
    for (const h of hotspots) {
      if (pointInTerritory(h.longitude, h.latitude, territory)) {
        count++;
        maxFrp = Math.max(maxFrp, Number(h.frp) || 0);
      }
    }
    if (count > 0) return { count, maxFrp };
  }

  const c = entityCoords(entity);
  if (!c) return { count: 0, maxFrp: 0 };
  let count = 0;
  let maxFrp = 0;
  for (const h of hotspots) {
    if (haversineMeters(c.lat, c.lon, h.latitude, h.longitude) <= 50_000) {
      count++;
      maxFrp = Math.max(maxFrp, Number(h.frp) || 0);
    }
  }
  return { count, maxFrp };
}

export function geoScopeToScore(scope: string): number {
  const s = scope.toLowerCase();
  if (s.includes('multiterritorial')) return 60;
  if (s.includes('localizado')) return 40;
  if (s.includes('amplo')) return 90;
  if (s.includes('projeto') || s.includes('project')) return 85;
  return 20;
}
