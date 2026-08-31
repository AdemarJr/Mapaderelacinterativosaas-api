export type IndexType = 'IRR' | 'IRE' | 'IC';

import type { BiomeCode } from './biomes.js';
import type { FireHotspotRecord } from './fireHotspots.js';
import { isBurnSeasonForBiome } from './biomes.js';

export type AssessmentStatus =
  | 'NAO_CALCULADO'
  | 'PRELIMINAR'
  | 'EM_ANALISE'
  | 'VALIDADO'
  | 'EXPIRADO'
  | 'REVISAR';

export type TargetType = 'entity' | 'relationship' | 'evidence' | 'risk' | 'assertion' | 'project';

export type FactorOrigin = 'automatic' | 'manual' | 'override';

export type EntityKind = 'person' | 'institution' | 'activity' | 'location';

export interface FactorScoreResult {
  factorCode: string;
  isApplicable: boolean;
  autoValue: number | null;
  validatedValue: number | null;
  effectiveValue: number | null;
  weight: number;
  origin: FactorOrigin;
  justification?: string | null;
  evidenceRefs?: string[];
}

export interface IndexAssessmentResult {
  indexType: IndexType;
  value: number | null;
  band: string;
  status: AssessmentStatus;
  methodologyVersionId: string;
  factors: FactorScoreResult[];
  insufficientReason?: string;
}

export interface GraphEntity {
  id: string;
  name: string;
  kind: EntityKind;
  latitude?: number | null;
  longitude?: number | null;
  territory_geojson?: unknown | null;
  territory_radius_km?: number | null;
}

export interface GraphRelationship {
  id: string;
  source_id: string;
  target_id: string;
  source_type?: string;
  target_type?: string;
  type?: string;
  level?: string;
  source?: string;
  confidence?: string;
  start_date?: string;
  end_date?: string;
  created_at?: string;
  is_active?: boolean;
  documents?: Array<{ name?: string; url?: string }>;
}

export interface GraphEvidence {
  id: string;
  relationship_id?: string | null;
  related_entity_id?: string | null;
  source?: string;
  confidence?: string;
  validation_status?: string;
  occurred_at?: string | null;
  source_independence?: string | null;
  evidence_type?: string;
}

export interface ProjectRiskRecord {
  id: string;
  project_id: string;
  title: string;
  description?: string;
  status: string;
  related_entity_id?: string | null;
  related_entity_type?: string | null;
  relationship_id?: string | null;
  evidence_id?: string | null;
  occurred_at?: string | null;
  review_due_at?: string | null;
  category_ids?: string[];
  /** Manual factor overrides from risk metadata */
  factor_overrides?: Record<string, { value: number; justification?: string }>;
  subtype_id?: string | null;
  assertion_id?: string | null;
  risk_level?: string;
  scope?: string;
  /** Resolved at compute time from subtype catalog */
  subtype_label?: string | null;
  category_labels?: string[];
}

export interface AssertionRecord {
  id: string;
  project_id: string;
  text: string;
  assertion_type?: string;
  status?: string;
  related_entity_id?: string | null;
  related_entity_type?: string | null;
  relationship_id?: string | null;
  evidence_ids?: string[];
}

export interface ComputeContext {
  projectId: string;
  methodologyVersionId: string;
  anchorEntityId?: string | null;
  projectBiome?: BiomeCode | null;
  entities: GraphEntity[];
  relationships: GraphRelationship[];
  evidences: GraphEvidence[];
  assertions?: AssertionRecord[];
  fireHotspots?: FireHotspotRecord[];
  risk?: ProjectRiskRecord;
  existingOverrides?: Record<string, { validatedValue: number; justification?: string }>;
}

export interface EntityIndexSummary {
  entityId: string;
  irr: IndexAssessmentResult | null;
  ireConsolidated: { value: number | null; band: string; status: AssessmentStatus; activeRiskCount: number; maxRiskTitle?: string; categories: string[] } | null;
  alerts: DecisionAlert[];
}

export type DecisionAlertType =
  | 'VALIDAR_INVESTIGAR'
  | 'RESPONDER_MITIGAR'
  | 'MONITORAMENTO_ESTRATEGICO'
  | 'PRIORIDADE_OPERACIONAL';

export interface DecisionAlert {
  type: DecisionAlertType;
  title: string;
  detail: string;
  entityId?: string;
}
