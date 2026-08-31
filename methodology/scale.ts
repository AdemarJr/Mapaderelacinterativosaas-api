/** POP scale bands: 0, 20, 40, 60, 80, 100 */
import { isBurnSeasonForBiome, type BiomeCode } from './biomes.js';

export function classifyBand(value: number | null): string {
  if (value === null || value === undefined || Number.isNaN(value)) return 'INSUFICIENTE';
  if (value <= 0) return 'Inexistente';
  if (value <= 20) return 'Muito baixo';
  if (value <= 40) return 'Baixo';
  if (value <= 60) return 'Médio';
  if (value <= 80) return 'Alto';
  return 'Muito alto';
}

export function formatIndexLabel(indexType: string, value: number | null, band: string): string {
  if (value === null) return `${indexType} — ${band}`;
  const upperBand = band === 'INSUFICIENTE' ? band : band.toUpperCase();
  return `${indexType} ${Math.round(value)} — ${upperBand}`;
}

export function hopsToProximityScore(hops: number | null): number | null {
  if (hops === null) return null;
  if (hops <= 0) return 100;
  if (hops === 1) return 80;
  if (hops === 2) return 60;
  if (hops === 3) return 40;
  return 20;
}

export function diversityToScore(kindCount: number): number {
  if (kindCount <= 0) return 0;
  if (kindCount === 1) return 20;
  if (kindCount === 2) return 40;
  if (kindCount === 3) return 60;
  if (kindCount === 4) return 80;
  return 100;
}

export function connectionCountToScore(connections: number, _maxConnections?: number): number {
  const c = Math.max(0, connections);
  if (c === 0) return 0;
  if (c <= 2) return 20;
  if (c <= 5) return 40;
  if (c <= 10) return 60;
  if (c <= 20) return 80;
  return 100;
}

/** @deprecated use connectionCountToScore — kept for compatibility */
export function connectionCountAbsoluteToScore(connections: number): number {
  return connectionCountToScore(connections);
}

export function confidenceToIcScore(confidence?: string | null): number | null {
  const c = String(confidence || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .trim();
  if (!c) return null;
  if (c.includes('confirmada') && !c.includes('nao')) return 80;
  if (c.includes('provavel')) return 50;
  if (c.includes('nao')) return 20;
  return null;
}

export function recencyToScore(isoDate?: string | null, now = Date.now()): number | null {
  if (!isoDate) return null;
  const ts = new Date(isoDate).getTime();
  if (Number.isNaN(ts)) return null;
  const days = (now - ts) / (1000 * 60 * 60 * 24);
  if (days <= 30) return 100;
  if (days <= 90) return 80;
  if (days <= 180) return 60;
  if (days <= 365) return 40;
  return 20;
}

/** IRE-3 — urgência por prazo de revisão (dias até vencimento). */
export function reviewDueUrgencyScore(isoDate?: string | null, now = Date.now()): number | null {
  if (!isoDate) return null;
  const ts = new Date(isoDate).getTime();
  if (Number.isNaN(ts)) return null;
  const daysUntil = (ts - now) / (1000 * 60 * 60 * 24);
  if (daysUntil < 0) return 100;
  if (daysUntil <= 30) return 90;
  if (daysUntil <= 90) return 70;
  if (daysUntil <= 180) return 50;
  return 30;
}

/** IRE-3 — reforço sazonal queimadas por bioma + subtipo/categoria. */
export function burnSeasonImmediacyBoost(
  subtypeLabel?: string | null,
  categoryLabels?: string[],
  now = new Date(),
  biome: BiomeCode = 'amazonia'
): number {
  if (!isBurnSeasonForBiome(biome, now)) return 0;
  const burnSubtype = String(subtypeLabel || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .includes('queimada');
  const ambient = (categoryLabels || []).some((c) =>
    c.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').includes('ambient')
  );
  if (burnSubtype) return 25;
  if (ambient) return 15;
  return 0;
}

export function scopeToScore(scope?: string): number {
  const s = String(scope || 'pontual').toLowerCase();
  if (s.includes('multiterritorial')) return 60;
  if (s.includes('localizado')) return 40;
  if (s.includes('amplo')) return 90;
  if (s.includes('projeto') || s.includes('project')) return 85;
  return 20;
}

/** POP IRR-5 — centralidade estratégica por bridge score + conectividade. */
export function centralityToScore(bridgeScore: number, connections: number): number {
  if (connections === 0) return 0;
  const combined = Math.round(bridgeScore * 0.55 + Math.min(100, connections * 6) * 0.45);
  if (combined >= 85) return 100;
  if (combined >= 65) return 80;
  if (combined >= 45) return 60;
  if (combined >= 25) return 40;
  return 20;
}
