import { randomUUID } from 'crypto';
import type { Hono } from 'hono';
import { query } from './db.js';
import { writeAuditLog } from './audit.js';
import {
  fetchFirmsHotspots,
  projectBboxFromCoords,
  type FireHotspotRecord,
} from './methodology/fireHotspots.js';
import { detectBiome, biomeLabel } from './methodology/biomes.js';

export interface EnvironmentalRouteDeps {
  assertProjectAccess: (c: any, projectId: string) => Promise<any>;
  assertProjectWrite: (c: any, projectId: string) => Promise<any>;
  assertProjectManage: (c: any, projectId: string) => Promise<any>;
  clientIp: (c: any) => string;
}

async function loadProjectCoords(projectId: string): Promise<Array<{ lat: number; lon: number }>> {
  const [people, institutions, activities, locations] = await Promise.all([
    query('SELECT latitude, longitude FROM people WHERE project_id = $1', [projectId]),
    query('SELECT latitude, longitude FROM institutions WHERE project_id = $1', [projectId]),
    query('SELECT latitude, longitude FROM activities WHERE project_id = $1', [projectId]),
    query('SELECT latitude, longitude FROM locations WHERE project_id = $1', [projectId]),
  ]);
  const coords: Array<{ lat: number; lon: number }> = [];
  for (const set of [people.rows, institutions.rows, activities.rows, locations.rows]) {
    for (const r of set) {
      const lat = Number(r.latitude);
      const lon = Number(r.longitude);
      if (Number.isFinite(lat) && Number.isFinite(lon)) coords.push({ lat, lon });
    }
  }
  return coords;
}

export function registerEnvironmentalRoutes(app: Hono, deps: EnvironmentalRouteDeps): void {
  const { assertProjectAccess, assertProjectWrite, assertProjectManage, clientIp } = deps;
  const base = '/api/projects/:projectId/environmental';

  app.get(`${base}/fire-hotspots`, async (c) => {
    const projectId = c.req.param('projectId');
    await assertProjectAccess(c, projectId);
    const res = await query(
      `SELECT * FROM fire_hotspot_signals
       WHERE project_id = $1 AND detected_at >= NOW() - INTERVAL '30 days'
       ORDER BY detected_at DESC LIMIT 500`,
      [projectId]
    );
    return c.json({ hotspots: res.rows, count: res.rowCount ?? 0 });
  });

  app.post(`${base}/fire-hotspots/sync`, async (c) => {
    const projectId = c.req.param('projectId');
    const actor = await assertProjectWrite(c, projectId);
    const apiKey = process.env.FIRMS_API_KEY;
    const coords = await loadProjectCoords(projectId);
    const bbox = projectBboxFromCoords(coords);
    if (!bbox) {
      return c.json({ error: 'Cadastre entidades geolocalizadas para sincronizar focos de calor.' }, 400);
    }

    let fetched: FireHotspotRecord[] = [];
    if (apiKey) {
      try {
        fetched = await fetchFirmsHotspots(bbox, apiKey, 2);
      } catch (e: any) {
        return c.json({ error: e.message || 'Falha ao consultar NASA FIRMS' }, 502);
      }
    } else {
      return c.json(
        {
          error: 'FIRMS_API_KEY não configurada. Use importação demo ou configure a chave NASA FIRMS.',
          hint: 'POST /fire-hotspots/demo para dados de exemplo',
        },
        503
      );
    }

    await query('DELETE FROM fire_hotspot_signals WHERE project_id = $1', [projectId]);
    for (const h of fetched) {
      await query(
        `INSERT INTO fire_hotspot_signals (id, project_id, latitude, longitude, detected_at, source, frp, synced_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
        [randomUUID(), projectId, h.latitude, h.longitude, h.detected_at, h.source || 'FIRMS', h.frp ?? null]
      );
    }

    await writeAuditLog({
      projectId,
      userId: actor.id,
      userEmail: actor.email,
      action: 'sync',
      entityType: 'fire_hotspots',
      entityId: projectId,
      summary: `Sincronizados ${fetched.length} focos FIRMS`,
      ip: clientIp(c),
    });

    return c.json({ synced: fetched.length, source: 'FIRMS' });
  });

  app.post(`${base}/fire-hotspots/demo`, async (c) => {
    const projectId = c.req.param('projectId');
    const actor = await assertProjectManage(c, projectId);
    const coords = await loadProjectCoords(projectId);
    if (!coords.length) {
      return c.json({ error: 'Cadastre ao menos uma entidade geolocalizada.' }, 400);
    }
    const center = coords[0];
    const demo: FireHotspotRecord[] = [
      { latitude: center.lat + 0.02, longitude: center.lon + 0.01, detected_at: new Date().toISOString(), source: 'DEMO', frp: 45 },
      { latitude: center.lat - 0.015, longitude: center.lon - 0.02, detected_at: new Date(Date.now() - 86400000).toISOString(), source: 'DEMO', frp: 72 },
      { latitude: center.lat + 0.005, longitude: center.lon - 0.03, detected_at: new Date(Date.now() - 172800000).toISOString(), source: 'DEMO', frp: 28 },
    ];
    await query('DELETE FROM fire_hotspot_signals WHERE project_id = $1 AND source = $2', [projectId, 'DEMO']);
    for (const h of demo) {
      await query(
        `INSERT INTO fire_hotspot_signals (id, project_id, latitude, longitude, detected_at, source, frp, synced_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
        [randomUUID(), projectId, h.latitude, h.longitude, h.detected_at, h.source, h.frp]
      );
    }
    await writeAuditLog({
      projectId,
      userId: actor.id,
      userEmail: actor.email,
      action: 'create',
      entityType: 'fire_hotspots_demo',
      entityId: projectId,
      summary: `Demo: ${demo.length} focos de calor`,
      ip: clientIp(c),
    });
    return c.json({ imported: demo.length, source: 'DEMO' });
  });

  app.get(`${base}/biome`, async (c) => {
    const projectId = c.req.param('projectId');
    await assertProjectAccess(c, projectId);
    const lat = c.req.query('lat');
    const lon = c.req.query('lon');
    const proj = await query('SELECT biome_code FROM projects WHERE id = $1 LIMIT 1', [projectId]);
    if (lat && lon) {
      const code = detectBiome(Number(lat), Number(lon));
      return c.json({ biome: code, label: biomeLabel(code), source: 'coordinates' });
    }
    const override = proj.rows[0]?.biome_code;
    if (override) {
      return c.json({ biome: override, label: biomeLabel(override), source: 'project' });
    }
    const coords = await loadProjectCoords(projectId);
    if (!coords.length) return c.json({ biome: 'unknown', label: biomeLabel('unknown'), source: 'none' });
    const code = detectBiome(coords[0].lat, coords[0].lon);
    return c.json({ biome: code, label: biomeLabel(code), source: 'centroid' });
  });
}
