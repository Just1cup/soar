import { provideZonelessChangeDetection } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Router, provideRouter, withComponentInputBinding } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { of } from 'rxjs';
import { routes } from '../../app.routes';
import { AuthService } from '../../core/auth/auth.service';
import { IncidentsService } from '../../core/api/incidents.service';
import { ResponseService } from '../../core/api/response.service';
import { AssessmentService } from '../../core/api/assessment.service';

const ID = '01a0c0b3-87bb-7ec4-bb72-586fd883208b';

function incident() {
  return {
    id: ID, key: 'INC-2026-000001', title: 'Caso de teste',
    status: 'new', severity: 'high', priority: 2, owner_id: null,
    source_rule: 'Regra X', alert_count: 3,
    first_seen: '2026-09-20T12:00:00Z', last_seen: '2026-09-20T12:30:00Z',
    created_at: '2026-09-20T12:00:00Z', updated_at: '2026-09-20T12:00:00Z',
    version: 1, type_slug: 'generic', description: null, resolution: null,
    closed_reason: null, closed_at: null, first_ack_at: null,
    attack_tactics: [], attack_techniques: [], tags: [],
  };
}

/**
 * Um refresh (F5) numa URL profunda não é o mesmo que navegar até ela: o
 * aplicativo inicializa JÁ naquela rota, sem sessão em memória, e o guard
 * precisa reconstruí-la com /auth/me antes de a página carregar.
 */
describe('refresh em /incidents/:id', () => {
  let http: HttpTestingController;
  let auth: AuthService;
  let getCalls: string[];

  beforeEach(() => {
    getCalls = [];
    TestBed.configureTestingModule({
      providers: [
        provideZonelessChangeDetection(),
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter(routes, withComponentInputBinding()),
        {
          provide: IncidentsService,
          useValue: {
            get: (id: string) => { getCalls.push(id); return of(incident()); },
            timeline: () => of([]),
            tasks: () => of([]),
            close: () => of(incident()),
          },
        },
        { provide: ResponseService, useValue: { integrations: () => of([]), runs: () => of([]) } },
        { provide: AssessmentService, useValue: { list: () => of([]), evidence: () => of({
          cluster: { cluster_id: 'c1', rule_name: 'Regra X', host: 'host', entity_kind: 'none', entity: null, count: 3, first_seen: incident().first_seen, last_seen: incident().last_seen, severity: 'high', risk_score: null, rule_tactics: [], rule_techniques: [], observables: {} },
          case_context: { window: { first: incident().first_seen, last: incident().last_seen, alerts: 3 }, collected: [], missing: [], timeline: [], related_alerts: [], prevalence: {}, ioc_hits: [], entities: { hosts: 1, users: 0, processes: 0, files: 0, hashes: 0, ips: 0, domains: 0, urls: 0, ioc_hits: 0 } },
        }) } },
      ],
    });
    http = TestBed.inject(HttpTestingController);
    auth = TestBed.inject(AuthService);
  });

  afterEach(() => http.verify({ ignoreCancelled: true }));

  it('carrega quando a sessão já está em memória (navegação normal)', async () => {
    auth.actor.set({ actor_id: 'u1', kind: 'user', display_name: 'Example Analyst', permissions: ['incident.read'] });
    const harness = await RouterTestingHarness.create();
    await harness.navigateByUrl(`/incidents/${ID}`);
    harness.detectChanges();
    expect(getCalls).toEqual([ID]);
  });

  // O caso do bug: F5 na URL do caso, com cookie de sessão VÁLIDO.
  it('carrega entrando direto na URL com sessão válida no cookie', async () => {
    auth.actor.set(null);
    const harness = await RouterTestingHarness.create();
    const navigation = harness.navigateByUrl(`/incidents/${ID}`);

    // O guard roda numa microtarefa: sem este tick, a asserção aconteceria
    // antes de a requisição sequer existir.
    await new Promise((resolve) => setTimeout(resolve, 0));

    // O guard consulta a sessão; o cookie é válido, então responde 200.
    const me = http.expectOne('/api/v1/auth/me');
    me.flush({
      data: { actor_id: 'u1', kind: 'user', display_name: 'Example Analyst', permissions: ['incident.read'] },
      request_id: 'r1',
    });

    await navigation;
    harness.detectChanges();
    expect(TestBed.inject(Router).url).toBe(`/incidents/${ID}`);
    expect(getCalls).toEqual([ID]);
  });
});
