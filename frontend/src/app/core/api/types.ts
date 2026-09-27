/**
 * Aliases sobre o schema gerado.
 *
 * Nenhuma interface do backend é escrita à mão aqui: `schema.d.ts` vem do
 * `api/openapi.yaml` e é regenerado no CI (`npm run api:check`), que falha se
 * o arquivo versionado divergir. Uma mudança incompatível de contrato vira
 * erro de compilação em vez de erro em produção.
 */
import type { components } from './schema';

export type IncidentSummary = components['schemas']['IncidentSummary'];
export type Incident = components['schemas']['Incident'];
export type IncidentStatus = components['schemas']['IncidentStatus'];
export type Severity = components['schemas']['Severity'];
export type Resolution = components['schemas']['Resolution'];
export type PageMeta = components['schemas']['PageMeta'];
export type TimelineEntry = components['schemas']['TimelineEntry'];
export type CaseTask = components['schemas']['CaseTask'];
export type TaskNote = components['schemas']['TaskNote'];
export type CurrentActor = components['schemas']['CurrentActor'];
export type LoginRequest = components['schemas']['LoginRequest'];

export interface Envelope<T> {
  data: T;
  meta?: PageMeta;
  request_id: string;
}

/** A ordem que a fila usa. Vive aqui porque é vocabulário do domínio. */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Crítico',
  high: 'Alto',
  medium: 'Médio',
  low: 'Baixo',
  info: 'Info',
};

export const STATUS_LABEL: Record<IncidentStatus, string> = {
  new: 'Novo',
  triage: 'Triagem',
  investigating: 'Investigando',
  pending_action: 'Aguardando ação',
  resolved: 'Resolvido',
  closed: 'Fechado',
};

export const RESOLUTION_LABEL: Record<Resolution, string> = {
  true_positive: 'Verdadeiro positivo',
  benign_true_positive: 'Verdadeiro positivo benigno',
  false_positive: 'Falso positivo',
  inconclusive: 'Inconclusivo',
};
