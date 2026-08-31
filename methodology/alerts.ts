import type { DecisionAlert, IndexAssessmentResult } from './types.js';

function isHighIre(ire: IndexAssessmentResult | null | undefined): boolean {
  return ire != null && ire.value !== null && ire.value >= 61;
}

function isLowIc(ic: number | null | undefined): boolean {
  return ic == null || ic <= 40;
}

function isHighIc(ic: number | null | undefined): boolean {
  return ic != null && ic >= 61;
}

function isHighIrr(irr: IndexAssessmentResult | null | undefined): boolean {
  return irr != null && irr.value !== null && irr.value >= 61;
}

function isLowIre(ire: IndexAssessmentResult | null | undefined): boolean {
  return ire == null || ire.value === null || ire.value <= 40;
}

/** POP 4 decision rules — not a fourth index. */
export function computeDecisionAlerts(input: {
  entityId: string;
  entityName?: string;
  irr: IndexAssessmentResult | null;
  ire: IndexAssessmentResult | null;
  maxIc: number | null;
}): DecisionAlert[] {
  const alerts: DecisionAlert[] = [];
  const name = input.entityName || input.entityId;

  if (isHighIre(input.ire) && isLowIc(input.maxIc)) {
    alerts.push({
      type: 'VALIDAR_INVESTIGAR',
      title: 'Validar / Investigar',
      detail: `${name}: IRE alto com IC baixo — validar informações antes de agir.`,
      entityId: input.entityId,
    });
  }

  if (isHighIre(input.ire) && isHighIc(input.maxIc)) {
    alerts.push({
      type: 'RESPONDER_MITIGAR',
      title: 'Responder / Mitigar',
      detail: `${name}: IRE alto com IC alto — priorizar resposta ou mitigação.`,
      entityId: input.entityId,
    });
  }

  if (isHighIrr(input.irr) && isLowIre(input.ire) && isHighIc(input.maxIc)) {
    alerts.push({
      type: 'MONITORAMENTO_ESTRATEGICO',
      title: 'Monitoramento estratégico',
      detail: `${name}: alta relevância relacional, baixa exposição, informação confiável.`,
      entityId: input.entityId,
    });
  }

  if (isHighIrr(input.irr) && isHighIre(input.ire) && isHighIc(input.maxIc)) {
    alerts.push({
      type: 'PRIORIDADE_OPERACIONAL',
      title: 'Prioridade operacional / estratégica',
      detail: `${name}: relevância, risco e confiança altos — prioridade máxima.`,
      entityId: input.entityId,
    });
  }

  return alerts;
}
