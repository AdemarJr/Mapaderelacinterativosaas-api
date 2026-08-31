export type BiomeCode =
  | 'amazonia'
  | 'cerrado'
  | 'mata_atlantica'
  | 'caatinga'
  | 'pantanal'
  | 'pampa'
  | 'unknown';

export interface BurnSeasonWindow {
  startMonth: number;
  endMonth: number;
  label: string;
}

const BIOME_SEASONS: Record<BiomeCode, BurnSeasonWindow> = {
  amazonia: { startMonth: 6, endMonth: 11, label: 'jun–nov' },
  cerrado: { startMonth: 5, endMonth: 10, label: 'mai–out' },
  mata_atlantica: { startMonth: 7, endMonth: 10, label: 'jul–out' },
  caatinga: { startMonth: 8, endMonth: 11, label: 'ago–nov' },
  pantanal: { startMonth: 6, endMonth: 10, label: 'jun–out' },
  pampa: { startMonth: 12, endMonth: 3, label: 'dez–mar' },
  unknown: { startMonth: 6, endMonth: 11, label: 'jun–nov' },
};

const BIOME_LABELS: Record<BiomeCode, string> = {
  amazonia: 'Amazônia',
  cerrado: 'Cerrado',
  mata_atlantica: 'Mata Atlântica',
  caatinga: 'Caatinga',
  pantanal: 'Pantanal',
  pampa: 'Pampa',
  unknown: 'Indefinido',
};

/** Detecção simplificada por coordenadas (Brasil). */
export function detectBiome(lat: number, lon: number): BiomeCode {
  if (lat < -33.5 || lat > 5.5 || lon < -74 || lon > -34) return 'unknown';
  if (lat >= -5 && lat <= 5 && lon >= -74 && lon <= -46) return 'amazonia';
  if (lat >= -18 && lat <= -2 && lon >= -58 && lon <= -44) return 'cerrado';
  if (lat >= -25 && lat <= -2 && lon >= -52 && lon <= -38) return 'mata_atlantica';
  if (lat >= -18 && lat <= -2 && lon >= -46 && lon <= -34) return 'caatinga';
  if (lat >= -22 && lat <= -15 && lon >= -58 && lon <= -54) return 'pantanal';
  if (lat <= -28 && lon >= -58 && lon <= -49) return 'pampa';
  if (lon <= -58) return 'amazonia';
  if (lat <= -20) return 'pampa';
  return 'cerrado';
}

export function biomeLabel(code: BiomeCode): string {
  return BIOME_LABELS[code] || BIOME_LABELS.unknown;
}

export function burnSeasonForBiome(biome: BiomeCode): BurnSeasonWindow {
  return BIOME_SEASONS[biome] || BIOME_SEASONS.unknown;
}

export function isBurnSeasonForBiome(biome: BiomeCode, date = new Date()): boolean {
  const month = date.getMonth() + 1;
  const { startMonth, endMonth } = burnSeasonForBiome(biome);
  if (startMonth <= endMonth) return month >= startMonth && month <= endMonth;
  return month >= startMonth || month <= endMonth;
}
