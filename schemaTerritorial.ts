/**
 * Fase 3 — território (GeoJSON), bioma e focos de calor.
 */
import { query } from './db.js';

export async function ensureTerritorialSchema(): Promise<void> {
  await query(`ALTER TABLE locations ADD COLUMN IF NOT EXISTS territory_geojson JSONB`);
  await query(`ALTER TABLE locations ADD COLUMN IF NOT EXISTS territory_radius_km NUMERIC`);
  await query(`ALTER TABLE projects ADD COLUMN IF NOT EXISTS biome_code TEXT`);

  await query(`
    CREATE TABLE IF NOT EXISTS fire_hotspot_signals (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL,
      latitude DOUBLE PRECISION NOT NULL,
      longitude DOUBLE PRECISION NOT NULL,
      detected_at TIMESTAMPTZ NOT NULL,
      source TEXT DEFAULT 'FIRMS',
      frp NUMERIC,
      confidence NUMERIC,
      synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await query(
    `CREATE INDEX IF NOT EXISTS idx_fire_hotspots_project ON fire_hotspot_signals (project_id, detected_at DESC)`
  );
}
