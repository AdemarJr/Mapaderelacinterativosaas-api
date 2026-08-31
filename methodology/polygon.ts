export type GeoRing = Array<[number, number]>;
export type GeoPolygonCoords = GeoRing[];
export type GeoMultiPolygonCoords = GeoPolygonCoords[];

export interface GeoJsonPolygon {
  type: 'Polygon';
  coordinates: GeoPolygonCoords;
}

export interface GeoJsonMultiPolygon {
  type: 'MultiPolygon';
  coordinates: GeoMultiPolygonCoords;
}

export type TerritoryGeometry = GeoJsonPolygon | GeoJsonMultiPolygon;

export function circlePolygon(
  lat: number,
  lon: number,
  radiusKm: number,
  steps = 32
): GeoJsonPolygon {
  const ring: GeoRing = [];
  for (let i = 0; i <= steps; i++) {
    const angle = (i / steps) * 2 * Math.PI;
    const dx = radiusKm * Math.cos(angle);
    const dy = radiusKm * Math.sin(angle);
    const dLat = dy / 111.32;
    const dLon = dx / (111.32 * Math.max(0.01, Math.cos((lat * Math.PI) / 180)));
    ring.push([lon + dLon, lat + dLat]);
  }
  return { type: 'Polygon', coordinates: [ring] };
}

function ringsFromGeometry(g: TerritoryGeometry): GeoRing[] {
  if (g.type === 'Polygon') return g.coordinates;
  return g.coordinates.flat();
}

/** Ray-casting — coords [lon, lat]. */
export function pointInRing(lon: number, lat: number, ring: GeoRing): boolean {
  let inside = false;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const xi = ring[i][0];
    const yi = ring[i][1];
    const xj = ring[j][0];
    const yj = ring[j][1];
    const intersect =
      yi > lat !== yj > lat && lon < ((xj - xi) * (lat - yi)) / (yj - yi + 1e-12) + xi;
    if (intersect) inside = !inside;
  }
  return inside;
}

export function pointInTerritory(lon: number, lat: number, geometry: TerritoryGeometry): boolean {
  for (const ring of ringsFromGeometry(geometry)) {
    if (ring.length >= 3 && pointInRing(lon, lat, ring)) return true;
  }
  return false;
}

/** Área aproximada do polígono em km² (projeção equiretangular). */
export function polygonAreaKm2(geometry: TerritoryGeometry): number {
  let total = 0;
  for (const ring of ringsFromGeometry(geometry)) {
    if (ring.length < 3) continue;
    let area = 0;
    for (let i = 0; i < ring.length - 1; i++) {
      const [lon1, lat1] = ring[i];
      const [lon2, lat2] = ring[i + 1];
      area += ((lon2 - lon1) * Math.PI) / 180 * (2 + Math.sin((lat1 * Math.PI) / 180) + Math.sin((lat2 * Math.PI) / 180));
    }
    total += Math.abs(area * 6371 * 6371 / 2);
  }
  return total;
}

/** Bounding box overlap ratio (0–1) entre dois territórios. */
export function bboxOverlapRatio(a: TerritoryGeometry, b: TerritoryGeometry): number {
  const bbox = (g: TerritoryGeometry) => {
    let minLon = Infinity;
    let maxLon = -Infinity;
    let minLat = Infinity;
    let maxLat = -Infinity;
    for (const ring of ringsFromGeometry(g)) {
      for (const [lon, lat] of ring) {
        minLon = Math.min(minLon, lon);
        maxLon = Math.max(maxLon, lon);
        minLat = Math.min(minLat, lat);
        maxLat = Math.max(maxLat, lat);
      }
    }
    return { minLon, maxLon, minLat, maxLat };
  };
  const A = bbox(a);
  const B = bbox(b);
  const overlapW = Math.max(0, Math.min(A.maxLon, B.maxLon) - Math.max(A.minLon, B.minLon));
  const overlapH = Math.max(0, Math.min(A.maxLat, B.maxLat) - Math.max(A.minLat, B.minLat));
  if (overlapW <= 0 || overlapH <= 0) return 0;
  const overlap = overlapW * overlapH;
  const areaA = Math.max(1e-9, (A.maxLon - A.minLon) * (A.maxLat - A.minLat));
  return Math.min(1, overlap / areaA);
}

export function parseTerritoryGeometry(raw: unknown): TerritoryGeometry | null {
  if (!raw || typeof raw !== 'object') return null;
  const g = raw as { type?: string; coordinates?: unknown };
  if (g.type === 'Polygon' && Array.isArray(g.coordinates)) {
    return { type: 'Polygon', coordinates: g.coordinates as GeoPolygonCoords };
  }
  if (g.type === 'MultiPolygon' && Array.isArray(g.coordinates)) {
    return { type: 'MultiPolygon', coordinates: g.coordinates as GeoMultiPolygonCoords };
  }
  return null;
}
