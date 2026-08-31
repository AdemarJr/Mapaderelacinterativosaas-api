import { haversineMeters } from './geo.js';
import { pointInTerritory, type TerritoryGeometry } from './polygon.js';

export interface FireHotspotRecord {
  id?: string;
  latitude: number;
  longitude: number;
  detected_at: string;
  source?: string;
  frp?: number | null;
  confidence?: number | null;
}

export function fireImmediacyBoost(count: number, maxFrp = 0): number {
  if (count <= 0) return 0;
  let boost = Math.min(30, count * 4);
  if (maxFrp >= 100) boost += 10;
  else if (maxFrp >= 40) boost += 5;
  return Math.min(35, boost);
}

export function countHotspotsNearPoint(
  lat: number,
  lon: number,
  hotspots: FireHotspotRecord[],
  radiusMeters: number
): { count: number; maxFrp: number } {
  let count = 0;
  let maxFrp = 0;
  for (const h of hotspots) {
    const d = haversineMeters(lat, lon, h.latitude, h.longitude);
    if (d <= radiusMeters) {
      count++;
      maxFrp = Math.max(maxFrp, Number(h.frp) || 0);
    }
  }
  return { count, maxFrp };
}

export function countHotspotsInTerritory(
  geometry: TerritoryGeometry,
  hotspots: FireHotspotRecord[]
): { count: number; maxFrp: number } {
  let count = 0;
  let maxFrp = 0;
  for (const h of hotspots) {
    if (pointInTerritory(h.longitude, h.latitude, geometry)) {
      count++;
      maxFrp = Math.max(maxFrp, Number(h.frp) || 0);
    }
  }
  return { count, maxFrp };
}

/** NASA FIRMS VIIRS — requer FIRMS_API_KEY no ambiente. */
export async function fetchFirmsHotspots(
  bbox: { west: number; south: number; east: number; north: number },
  apiKey: string,
  days = 1
): Promise<FireHotspotRecord[]> {
  const dayParam = Math.min(10, Math.max(1, days));
  const url = `https://firms.modaps.eosdis.nasa.gov/api/area/csv/${apiKey}/VIIRS_SNPP_NRT/${bbox.west}/${bbox.south}/${bbox.east}/${bbox.north}/${dayParam}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`FIRMS HTTP ${res.status}`);
  const text = await res.text();
  const lines = text.trim().split('\n');
  if (lines.length < 2) return [];
  const headers = lines[0].split(',').map((h) => h.trim().toLowerCase());
  const latIdx = headers.indexOf('latitude');
  const lonIdx = headers.indexOf('longitude');
  const dateIdx = headers.findIndex((h) => h.includes('acq_date'));
  const timeIdx = headers.findIndex((h) => h.includes('acq_time'));
  const frpIdx = headers.indexOf('frp');
  if (latIdx < 0 || lonIdx < 0) return [];

  const out: FireHotspotRecord[] = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split(',');
    const latitude = Number(cols[latIdx]);
    const longitude = Number(cols[lonIdx]);
    if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) continue;
    let detected_at = new Date().toISOString();
    if (dateIdx >= 0 && cols[dateIdx]) {
      const t = timeIdx >= 0 ? String(cols[timeIdx] || '0000').padStart(4, '0') : '1200';
      detected_at = new Date(`${cols[dateIdx]}T${t.slice(0, 2)}:${t.slice(2, 4)}:00Z`).toISOString();
    }
    out.push({
      latitude,
      longitude,
      detected_at,
      source: 'FIRMS',
      frp: frpIdx >= 0 ? Number(cols[frpIdx]) || null : null,
    });
  }
  return out;
}

export function projectBboxFromCoords(
  coords: Array<{ lat: number; lon: number }>,
  paddingDeg = 0.5
): { west: number; south: number; east: number; north: number } | null {
  if (!coords.length) return null;
  let minLat = Infinity;
  let maxLat = -Infinity;
  let minLon = Infinity;
  let maxLon = -Infinity;
  for (const c of coords) {
    minLat = Math.min(minLat, c.lat);
    maxLat = Math.max(maxLat, c.lat);
    minLon = Math.min(minLon, c.lon);
    maxLon = Math.max(maxLon, c.lon);
  }
  return {
    west: minLon - paddingDeg,
    south: minLat - paddingDeg,
    east: maxLon + paddingDeg,
    north: maxLat + paddingDeg,
  };
}
