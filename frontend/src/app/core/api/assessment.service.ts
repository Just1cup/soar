import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, map } from 'rxjs';
import type { components } from './schema';
import type { Envelope } from './types';

export type Assessment = components['schemas']['Assessment'];
export type AssessmentHypothesis = components['schemas']['AssessmentHypothesis'];
export type CaseEvidence = components['schemas']['CaseEvidence'];

@Injectable({ providedIn: 'root' })
export class AssessmentService {
  private readonly http = inject(HttpClient);
  private readonly base = '/api/v1';

  list(incidentId: string): Observable<Assessment[]> {
    return this.http
      .get<Envelope<Assessment[]>>(`${this.base}/incidents/${incidentId}/assessments`)
      .pipe(map((response) => response.data));
  }

  evidence(incidentId: string): Observable<CaseEvidence> {
    return this.http
      .get<Envelope<CaseEvidence>>(`${this.base}/incidents/${incidentId}/evidence`)
      .pipe(map((response) => response.data));
  }

  promote(incidentId: string, assessmentId: string, note: string): Observable<Assessment> {
    return this.http
      .post<Envelope<Assessment>>(
        `${this.base}/incidents/${incidentId}/assessments/${assessmentId}/promote`,
        { note },
      )
      .pipe(map((response) => response.data));
  }
}
