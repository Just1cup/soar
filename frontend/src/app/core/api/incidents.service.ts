import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, map } from 'rxjs';
import type {
  Envelope, Incident, IncidentStatus, IncidentSummary, PageMeta, Resolution, Severity, TimelineEntry, CaseTask, TaskNote,
} from './types';

export interface IncidentPage {
  items: IncidentSummary[];
  nextCursor: string | null;
  count: number;
}

export interface ListParams {
  status?: IncidentStatus;
  openOnly?: boolean;
  severity?: Severity;
  ownerId?: string;
  limit?: number;
  cursor?: string;
}

/**
 * O cliente da API.
 *
 * Escrito à mão sobre o HttpClient do Angular, e não gerado, por uma razão
 * concreta: um cliente gerado sobre `fetch` **não passa pelos interceptors** —
 * ficaria sem request-id, sem timeout, sem tradução de erro e, quando houver
 * autenticação, sem ela. Os *tipos* continuam vindo do contrato (types.ts);
 * o que é escrito aqui é só a chamada.
 */
@Injectable({ providedIn: 'root' })
export class IncidentsService {
  private readonly http = inject(HttpClient);
  private readonly base = '/api/v1';

  list(params: ListParams = {}): Observable<IncidentPage> {
    let query = new HttpParams();
    if (params.status) query = query.set('status', params.status);
    if (params.openOnly) query = query.set('open_only', 'true');
    if (params.severity) query = query.set('severity', params.severity);
    if (params.ownerId) query = query.set('owner_id', params.ownerId);
    if (params.limit) query = query.set('limit', String(params.limit));
    if (params.cursor) query = query.set('cursor', params.cursor);

    return this.http
      .get<Envelope<IncidentSummary[]>>(`${this.base}/incidents`, { params: query })
      .pipe(
        map((res) => ({
          items: res.data,
          nextCursor: (res.meta as PageMeta | undefined)?.next_cursor ?? null,
          count: res.data.length,
        })),
      );
  }

  get(id: string): Observable<Incident> {
    return this.http
      .get<Envelope<Incident>>(`${this.base}/incidents/${id}`)
      .pipe(map((res) => res.data));
  }

  timeline(id: string): Observable<TimelineEntry[]> {
    return this.http
      .get<Envelope<TimelineEntry[]>>(`${this.base}/incidents/${id}/timeline`)
      .pipe(map((res) => res.data));
  }

  tasks(id: string): Observable<CaseTask[]> {
    return this.http.get<Envelope<CaseTask[]>>(`${this.base}/incidents/${id}/tasks`).pipe(map((res) => res.data));
  }

  taskNotes(id: string, taskId: string): Observable<TaskNote[]> {
    return this.http.get<Envelope<TaskNote[]>>(`${this.base}/incidents/${id}/tasks/${taskId}/notes`).pipe(map((res) => res.data));
  }

  completeTask(id: string, task: CaseTask): Observable<CaseTask> {
    return this.http.post<Envelope<CaseTask>>(`${this.base}/incidents/${id}/tasks/${task.id}/complete`, { expected_version: task.version }).pipe(map((res) => res.data));
  }

  addTaskNote(id: string, taskId: string, body: string): Observable<TaskNote> {
    return this.http.post<Envelope<TaskNote>>(`${this.base}/incidents/${id}/tasks/${taskId}/notes`, { body }).pipe(map((res) => res.data));
  }

  close(id: string, version: number, resolution: Resolution, reason: string): Observable<Incident> {
    return this.http
      .post<Envelope<Incident>>(
        `${this.base}/incidents/${id}/close`,
        { resolution, reason, expected_version: version },
        { headers: { 'If-Match': `"${version}"` } },
      )
      .pipe(map((res) => res.data));
  }
}
