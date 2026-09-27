import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, map } from 'rxjs';
import type { Envelope } from './types';
import type { components } from './schema';

export type Integration = components['schemas']['Integration'];
export type IntegrationAction = components['schemas']['IntegrationAction'];
export type ActionPlan = components['schemas']['ActionPlan'];
export type ActionPreview = components['schemas']['ActionPreview'];
export type Approval = components['schemas']['Approval'];
export type ActionRun = components['schemas']['ActionRun'];
export type Autonomy = components['schemas']['Autonomy'];

/**
 * Cliente das ações de resposta.
 *
 * Escrito sobre o HttpClient, como o de incidentes: um cliente gerado sobre
 * `fetch` não passaria pelos interceptors e ficaria sem request-id, sem
 * timeout, sem CSRF e sem tradução de erro.
 */
@Injectable({ providedIn: 'root' })
export class ResponseService {
  private readonly http = inject(HttpClient);
  private readonly base = '/api/v1';

  integrations(): Observable<Integration[]> {
    return this.http
      .get<Envelope<Integration[]>>(`${this.base}/integrations`)
      .pipe(map((r) => r.data));
  }

  plan(incidentId: string, qualified: string, input: Record<string, unknown>): Observable<ActionPreview> {
    return this.http
      .post<Envelope<ActionPreview>>(
        `${this.base}/incidents/${incidentId}/actions/${qualified}/plan`,
        { input },
      )
      .pipe(map((r) => r.data));
  }

  /**
   * A Idempotency-Key é gerada AQUI e reusada se a requisição for repetida —
   * é propriedade da tentativa, não do clique. Sem isso, um timeout de rede
   * seguido de "tentar de novo" executaria a ação duas vezes em produção.
   */
  execute(
    incidentId: string,
    qualified: string,
    input: Record<string, unknown>,
    approvalId: string | null,
    idempotencyKey: string,
  ): Observable<ActionRun> {
    const body: Record<string, unknown> = { input };
    if (approvalId) body['approval_id'] = approvalId;
    return this.http
      .post<Envelope<ActionRun>>(
        `${this.base}/incidents/${incidentId}/actions/${qualified}/execute`,
        body,
        { headers: { 'Idempotency-Key': idempotencyKey } },
      )
      .pipe(map((r) => r.data));
  }

  runs(incidentId: string): Observable<ActionRun[]> {
    return this.http
      .get<Envelope<ActionRun[]>>(`${this.base}/incidents/${incidentId}/actions`)
      .pipe(map((r) => r.data));
  }

  approvals(limit = 50): Observable<Approval[]> {
    return this.http
      .get<Envelope<Approval[]>>(`${this.base}/approvals`, {
        params: new HttpParams().set('limit', String(limit)),
      })
      .pipe(map((r) => r.data));
  }

  decide(approvalId: string, approve: boolean, note: string, version: number): Observable<Approval> {
    return this.http
      .post<Envelope<Approval>>(
        `${this.base}/approvals/${approvalId}/decide`,
        { approve, note, expected_version: version },
        // A versão vai no If-Match: dois analistas decidindo a mesma
        // aprovação não podem ambos acreditar que ganharam.
        { headers: { 'If-Match': `"${version}"` } },
      )
      .pipe(map((r) => r.data));
  }
}

export const AUTONOMY_LABEL: Record<Autonomy, string> = {
  auto: 'Automática',
  approval_required: 'Exige aprovação',
  manual: 'Somente sugestão',
};
