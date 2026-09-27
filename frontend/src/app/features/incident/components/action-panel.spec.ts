import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Observable, of, throwError } from 'rxjs';
import { AssessmentService, type CaseEvidence } from '../../../core/api/assessment.service';
import { ApiError } from '../../../core/errors/api-error';
import { AuthService } from '../../../core/auth/auth.service';
import { ResponseService, type ActionPreview, type ActionRun, type Integration } from '../../../core/api/response.service';
import { ActionPanel } from './action-panel';

const field = (required: boolean, descr = '') => ({ type: 'string', required, descr });

function catalogue(): Integration[] {
  return [{
    id: 'elastic-siem', name: 'Elastic Security', pack_id: 'elastic-siem',
    actions: [
      {
        id: 'close_alerts', name: 'Fechar alertas', autonomy: 'approval_required',
        permission: 'response.close_alerts', idempotent: true, plan: true,
        reversible: 'reabrir', implemented: true,
        input: { rule_name: field(true), host: field(false), entity: field(false), status: field(false) },
      },
      {
        id: 'create_exception', name: 'Criar exceção', autonomy: 'approval_required',
        permission: 'response.create_exception', idempotent: false, plan: true,
        reversible: 'remover a exceção', implemented: true,
        input: { rule_name: field(true), field: field(true), value: field(true), comment: field(true) },
      },
      {
        id: 'isolate_host', name: 'Isolar endpoint', autonomy: 'approval_required',
        permission: 'response.isolate_endpoint', idempotent: true, plan: true,
        reversible: '', implemented: false, unavailable: 'Desabilitado neste ambiente.', input: {},
      },
    ],
  }];
}

const evidence: CaseEvidence = {
  cluster: {
    cluster_id: 'inc-1', rule_name: 'Regra X', host: 'srv-01',
    entity_kind: 'process.executable', entity: '/usr/bin/caddy', count: 3,
    first_seen: '2026-09-21T02:00:00Z', last_seen: '2026-09-21T03:00:00Z',
    severity: 'medium', risk_score: null, rule_tactics: [], rule_techniques: [],
    observables: { 'process.executable': ['/usr/bin/caddy', '/usr/bin/bash'], 'source.ip': ['10.0.0.8'] },
  },
  case_context: {
    window: { first: '2026-09-21T02:00:00Z', last: '2026-09-21T03:00:00Z', alerts: 3 },
    collected: [], missing: [], timeline: [], process_chain: [], related_alerts: [],
    prevalence: {}, ioc_hits: [],
    entities: { hosts: 1, users: 0, processes: 2, files: 0, hashes: 0, ips: 1, domains: 0, urls: 0, ioc_hits: 0 },
  },
};

function preview(over: Partial<ActionPreview> = {}): ActionPreview {
  return {
    plan: {
      summary: 'Marcar 42 alerta(s) como "closed"', details: ['Regra: Regra X'],
      affected: 42, reversible: 'reabrir os alertas', warnings: [],
      request: { method: 'POST', url: 'http://kibana/x' }, ready: true,
    },
    autonomy: 'approval_required', idempotent: true,
    approval_id: '00000000-0000-7000-8000-000000000010', approval_version: 1,
    expires_at: '2026-09-21T04:00:00Z', ...over,
  };
}

class StubResponse {
  planCalls = 0;
  decideCalls: Array<{ approve: boolean; note: string; version: number }> = [];
  executeCalls = 0;
  lastQualified = '';
  lastInput: Record<string, unknown> = {};
  lastKey = '';
  executeError: ApiError | null = null;
  integrations(): Observable<Integration[]> { return of(catalogue()); }
  plan(_incident: string, qualified: string, input: Record<string, unknown>): Observable<ActionPreview> {
    this.planCalls++; this.lastQualified = qualified; this.lastInput = input; return of(preview());
  }
  decide(_id: string, approve: boolean, note: string, version: number): Observable<unknown> {
    this.decideCalls.push({ approve, note, version }); return of({});
  }
  execute(_i: string, _q: string, _in: unknown, _a: string | null, key: string): Observable<ActionRun> {
    this.executeCalls++; this.lastKey = key;
    if (this.executeError) return throwError(() => this.executeError);
    return of({
      id: 'run-1', integration: 'elastic-siem', action: 'close_alerts',
      autonomy: 'approval_required', status: 'succeeded', affected: 42,
      error: '', actor_kind: 'user', actor_id: 'u1', requested_at: '2026-09-21T03:00:00Z',
      finished_at: null, latency_ms: 415,
    });
  }
}

class StubAuth {
  perms = new Set(['response.close_alerts', 'response.create_exception', 'approval.decide']);
  can(permission: string): boolean { return this.perms.has(permission); }
}

describe('ActionPanel', () => {
  let fixture: ComponentFixture<ActionPanel>;
  let api: StubResponse;

  async function render(): Promise<HTMLElement> {
    fixture = TestBed.createComponent(ActionPanel);
    fixture.componentRef.setInput('incidentId', 'inc-1');
    fixture.detectChanges(); await fixture.whenStable(); fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }
  function select(root: HTMLElement, value: string, index = 0): void {
    const el = root.querySelectorAll('select')[index] as HTMLSelectElement;
    el.value = value; el.dispatchEvent(new Event('change')); fixture.detectChanges();
  }
  function click(root: HTMLElement, text: string): void {
    const button = Array.from(root.querySelectorAll('button')).find((item) => (item.textContent ?? '').includes(text));
    if (!button) throw new Error(`botão "${text}" não encontrado`);
    button.click(); fixture.detectChanges();
  }

  beforeEach(() => {
    api = new StubResponse();
    TestBed.configureTestingModule({
      imports: [ActionPanel],
      providers: [
        { provide: ResponseService, useValue: api },
        { provide: AssessmentService, useValue: { evidence: () => of(evidence) } },
        { provide: AuthService, useValue: new StubAuth() },
      ],
    });
  });

  it('preenche e planeja o fechamento a partir do caso sem pedir campos técnicos', async () => {
    const root = await render();
    select(root, 'elastic-siem.close_alerts');

    expect(api.planCalls).toBe(1);
    expect(api.lastInput).toEqual({ rule_name: 'Regra X', host: 'srv-01', entity: '/usr/bin/caddy', status: 'closed' });
    expect(root.textContent).toContain('42');
    expect(root.textContent).toContain('Aplicar este plano?');
    expect(root.querySelector('input')).toBeNull();
  });

  it('aprova e executa com um único sim, mantendo as duas operações no backend', async () => {
    const root = await render();
    select(root, 'elastic-siem.close_alerts');
    click(root, 'Sim, aprovar e executar');

    expect(api.decideCalls).toEqual([{ approve: true, note: 'Aprovado diretamente no incidente.', version: 1 }]);
    expect(api.executeCalls).toBe(1);
    expect(root.textContent).toContain('Executada com sucesso');
    expect(root.textContent).toContain('42 objeto(s) afetado(s)');
  });

  it('recusa com um único não e não executa', async () => {
    const root = await render();
    select(root, 'elastic-siem.close_alerts');
    click(root, 'Não');

    expect(api.decideCalls[0]).toEqual({ approve: false, note: 'Não aprovado pelo analista no incidente.', version: 1 });
    expect(api.executeCalls).toBe(0);
    expect(root.textContent).toContain('Nenhuma alteração foi feita');
  });

  it('propõe uma exceção pronta e permite escolher outro observável', async () => {
    const root = await render();
    select(root, 'elastic-siem.create_exception');
    expect(root.textContent).toContain('Processo · /usr/bin/caddy');
    expect(root.textContent).toContain('Revisar exceção pronta');

    select(root, '1', 1);
    click(root, 'Revisar exceção pronta');
    expect(api.lastInput['field']).toBe('process.executable');
    expect(api.lastInput['value']).toBe('/usr/bin/bash');
    expect(api.lastInput['comment']).toContain('/usr/bin/bash');
  });

  it('reusa a mesma Idempotency-Key ao repetir a execução depois de falha', async () => {
    const root = await render();
    select(root, 'elastic-siem.close_alerts');
    api.executeError = new ApiError('network', 'TRANSPORT', 'sem rede', 0, null);
    click(root, 'Sim, aprovar e executar');
    const first = api.lastKey;
    api.executeError = null;
    click(root, 'Sim, aprovar e executar');
    expect(api.decideCalls.length).toBe(1);
    expect(api.lastKey).toBe(first);
    expect(root.textContent).toContain('Executada com sucesso');
  });

  it('mostra a razão de uma ação sem implementação', async () => {
    const root = await render();
    const option = Array.from(root.querySelectorAll('option')).find((item) => item.textContent?.includes('Isolar endpoint'));
    expect(option?.disabled).toBe(true);
    expect(option?.textContent).toContain('indisponível');
  });
});
