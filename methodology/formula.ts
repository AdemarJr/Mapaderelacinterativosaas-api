import type { FactorScoreResult, IndexAssessmentResult, IndexType, AssessmentStatus } from './types.js';
import { classifyBand } from './scale.js';

const MIN_FACTORS = 3;

export function computeIndexFromFactors(
  indexType: IndexType,
  methodologyVersionId: string,
  factors: FactorScoreResult[],
  status: AssessmentStatus = 'PRELIMINAR'
): IndexAssessmentResult {
  const applicable = factors.filter((f) => f.isApplicable && f.effectiveValue !== null);

  if (applicable.length < MIN_FACTORS) {
    return {
      indexType,
      value: null,
      band: 'INSUFICIENTE',
      status: 'NAO_CALCULADO',
      methodologyVersionId,
      factors,
      insufficientReason: `Menos de ${MIN_FACTORS} fatores aplicáveis (${applicable.length})`,
    };
  }

  const sum = applicable.reduce((acc, f) => acc + (f.effectiveValue ?? 0) * (f.weight || 1), 0);
  const weightSum = applicable.reduce((acc, f) => acc + (f.weight || 1), 0);
  const value = Math.round(sum / weightSum);

  return {
    indexType,
    value,
    band: classifyBand(value),
    status,
    methodologyVersionId,
    factors,
  };
}

export function makeFactor(
  factorCode: string,
  autoValue: number | null,
  opts?: {
    isApplicable?: boolean;
    validatedValue?: number | null;
    weight?: number;
    origin?: FactorScoreResult['origin'];
    justification?: string;
    evidenceRefs?: string[];
  }
): FactorScoreResult {
  const isApplicable = opts?.isApplicable ?? autoValue !== null;
  const validatedValue = opts?.validatedValue ?? null;
  const effectiveValue = validatedValue ?? autoValue;
  const origin = opts?.origin ?? (validatedValue !== null ? 'override' : 'automatic');

  return {
    factorCode,
    isApplicable,
    autoValue,
    validatedValue,
    effectiveValue: isApplicable ? effectiveValue : null,
    weight: opts?.weight ?? 1,
    origin,
    justification: opts?.justification,
    evidenceRefs: opts?.evidenceRefs,
  };
}
