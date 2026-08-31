import type { IndexAssessmentResult } from './types.js';
import { classifyBand } from './scale.js';

export interface RiskWithAssessment {
  riskId: string;
  title: string;
  status: string;
  categories: string[];
  assessment: IndexAssessmentResult;
}

/** IRE consolidado = MAX entre riscos ativos (prefer VALIDADO, fallback PRELIMINAR). */
export function consolidateIreForEntity(
  risks: RiskWithAssessment[],
  preferValidated = true
): {
  value: number | null;
  band: string;
  status: IndexAssessmentResult['status'];
  activeRiskCount: number;
  maxRiskTitle?: string;
  categories: string[];
} | null {
  const active = risks.filter((r) => r.status === 'ativo' || r.status === 'monitorando');
  if (active.length === 0) return null;

  const pool = preferValidated
    ? active.filter((r) => r.assessment.status === 'VALIDADO').length > 0
      ? active.filter((r) => r.assessment.status === 'VALIDADO')
      : active
    : active;

  let maxValue = -1;
  let maxRisk: RiskWithAssessment | null = null;
  const categories = new Set<string>();

  for (const r of pool) {
    if (r.assessment.value !== null && r.assessment.value > maxValue) {
      maxValue = r.assessment.value;
      maxRisk = r;
    }
    for (const c of r.categories) categories.add(c);
  }

  if (maxValue < 0 || !maxRisk) {
    return {
      value: null,
      band: 'INSUFICIENTE',
      status: 'NAO_CALCULADO',
      activeRiskCount: active.length,
      categories: [...categories],
    };
  }

  const allValidated = pool.every((r) => r.assessment.status === 'VALIDADO');

  return {
    value: maxValue,
    band: classifyBand(maxValue),
    status: allValidated ? 'VALIDADO' : 'PRELIMINAR',
    activeRiskCount: active.length,
    maxRiskTitle: maxRisk.title,
    categories: [...categories],
  };
}

export function maxIcAmongAssessments(assessments: IndexAssessmentResult[]): number | null {
  let max: number | null = null;
  for (const a of assessments) {
    if (a.value !== null && (max === null || a.value > max)) max = a.value;
  }
  return max;
}

/** IRE consolidado por categoria = MAX entre riscos ativos da categoria. */
export function consolidateIreByCategory(
  risks: RiskWithAssessment[]
): Record<string, { value: number; band: string; riskTitle: string }> {
  const active = risks.filter((r) => r.status === 'ativo' || r.status === 'monitorando');
  const byCategory: Record<string, { value: number; band: string; riskTitle: string }> = {};

  for (const risk of active) {
    if (risk.assessment.value === null) continue;
    for (const cat of risk.categories) {
      const current = byCategory[cat];
      if (!current || risk.assessment.value > current.value) {
        byCategory[cat] = {
          value: risk.assessment.value,
          band: risk.assessment.band,
          riskTitle: risk.title,
        };
      }
    }
  }
  return byCategory;
}
