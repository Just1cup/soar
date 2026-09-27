import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { IncidentsService } from '../../core/api/incidents.service';
import { AssessmentService } from '../../core/api/assessment.service';
import { ResponseService } from '../../core/api/response.service';
import type { Incident, Resolution, TimelineEntry } from '../../core/api/types';
import { AuthService } from '../../core/auth/auth.service';
import { IncidentPage } from './incident-page';

const openIncident: Incident = {
  id: '00000000-0000-7000-8000-000000000010', key: 'INC-1', title: 'Caso de teste',
  type_slug: 'generic', description: 'evidência', status: 'investigating', severity: 'high',
  priority: 2, owner_id: null, source_rule: 'Regra', alert_count: 3,
  first_seen: '2026-09-20T10:00:00Z', last_seen: '2026-09-20T11:00:00Z',
  created_at: '2026-09-20T10:00:00Z', updated_at: '2026-09-20T11:00:00Z', version: 4,
  attack_tactics: [], attack_techniques: [], tags: [],
};

const timelineEvent: TimelineEntry = {
  id: '00000000-0000-7000-8000-000000000020', occurred_at: '2026-09-20T11:00:00Z',
  event_type: 'incident.assigned', actor_kind: 'user', actor_label: 'Ana',
  title: 'Incidente atribuído', detail: '', payload: {},
};

class StubIncidents {
  closeArgs: [string, number, Resolution, string] | null = null;
  current = openIncident;
  get() { return of(this.current); }
  timeline() { return of([timelineEvent]); }
  tasks() { return of([]); }
  close(id: string, version: number, resolution: Resolution, reason: string) {
    this.closeArgs = [id, version, resolution, reason];
    this.current = { ...openIncident, status: 'closed', resolution, closed_reason: reason,
      closed_at: '2026-09-20T12:00:00Z', version: 5 };
    return of(this.current);
  }
}

describe('IncidentPage', () => {
  let fixture: ComponentFixture<IncidentPage>;
  let api: StubIncidents;

  beforeEach(async () => {
    api = new StubIncidents();
    await TestBed.configureTestingModule({
      imports: [IncidentPage],
      providers: [
        provideRouter([]),
        { provide: IncidentsService, useValue: api },
        { provide: AssessmentService, useValue: { list: () => of([]), evidence: () => of({
          cluster: { cluster_id: 'c1', rule_name: 'Regra', host: 'host', entity_kind: 'process.executable', entity: '/bin/test', count: 3, first_seen: openIncident.first_seen, last_seen: openIncident.last_seen, severity: 'high', risk_score: null, rule_tactics: [], rule_techniques: [], observables: {} },
          case_context: { window: { first: openIncident.first_seen, last: openIncident.last_seen, alerts: 3 }, collected: [], missing: [], timeline: [], related_alerts: [], prevalence: {}, ioc_hits: [], entities: { hosts: 1, users: 0, processes: 1, files: 0, hashes: 0, ips: 0, domains: 0, urls: 0, ioc_hits: 0 } },
        }) } },
        { provide: ResponseService, useValue: { integrations: () => of([]) } },
        { provide: AuthService, useValue: { can: () => true } },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(IncidentPage);
    fixture.componentRef.setInput('id', openIncident.id);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  });

  it('renderiza o caso e o War Room', () => {
    const root = fixture.nativeElement as HTMLElement;
    expect(root.textContent).toContain('Tasks');
    const tabs = root.querySelectorAll('.tabs button');
    (tabs[1] as HTMLButtonElement).click();
    fixture.detectChanges();
    const text = root.textContent ?? '';
    expect(text).toContain('Caso de teste');
    expect(text).toContain('Incidente atribuído');
    expect(text).toContain('Ana');
  });

  it('fecha usando a versão observada e só então troca o estado', () => {
    const root = fixture.nativeElement as HTMLElement;
    const select = root.querySelector('select') as HTMLSelectElement;
    const reason = root.querySelector('textarea') as HTMLTextAreaElement;
    const form = root.querySelector('form') as HTMLFormElement;
    select.value = 'false_positive';
    reason.value = 'regra disparou incorretamente';
    form.dispatchEvent(new Event('submit'));
    fixture.detectChanges();

    expect(api.closeArgs).toEqual([
      openIncident.id, 4, 'false_positive', 'regra disparou incorretamente',
    ]);
    expect((root.textContent ?? '')).toContain('Fechado');
    expect((root.textContent ?? '')).not.toContain('Fechar incidente');
  });
});
