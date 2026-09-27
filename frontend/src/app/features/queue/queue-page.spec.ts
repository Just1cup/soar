import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Observable, of, throwError } from 'rxjs';
import { IncidentsService, type IncidentPage } from '../../core/api/incidents.service';
import { ApiError } from '../../core/errors/api-error';
import type { IncidentSummary } from '../../core/api/types';
import { QueuePage } from './queue-page';

function incident(over: Partial<IncidentSummary>): IncidentSummary {
  return {
    id: crypto.randomUUID(), key: 'INC-2026-000001', title: 'um incidente',
    status: 'new', severity: 'low', priority: 4, owner_id: null, source_rule: null,
    alert_count: 1, first_seen: '2026-09-20T12:00:00Z', last_seen: '2026-09-20T12:00:00Z',
    created_at: '2026-09-20T12:00:00Z', updated_at: '2026-09-20T12:00:00Z', version: 1,
    ...over,
  };
}

class StubIncidents {
  page: IncidentPage = { items: [], nextCursor: null, count: 0 };
  error: ApiError | null = null;
  list(): Observable<IncidentPage> {
    return this.error ? throwError(() => this.error) : of(this.page);
  }
}

describe('QueuePage', () => {
  let fixture: ComponentFixture<QueuePage>;
  let stub: StubIncidents;

  async function render(): Promise<void> {
    fixture = TestBed.createComponent(QueuePage);
    await fixture.whenStable();
    fixture.detectChanges();
  }

  beforeEach(() => {
    stub = new StubIncidents();
    TestBed.configureTestingModule({
      imports: [QueuePage],
      providers: [{ provide: IncidentsService, useValue: stub }],
    });
  });

  it('ordena por severidade e, dentro dela, por quem espera há mais tempo', async () => {
    stub.page = {
      items: [
        incident({ key: 'INC-baixo', severity: 'low' }),
        incident({ key: 'INC-critico-recente', severity: 'critical', first_seen: '2026-09-20T17:00:00Z' }),
        incident({ key: 'INC-critico-antigo', severity: 'critical', first_seen: '2026-09-19T01:00:00Z' }),
        incident({ key: 'INC-medio', severity: 'medium' }),
      ],
      nextCursor: null, count: 4,
    };
    await render();

    // `nativeElement` é `any`; tipar aqui é o que faz o strict valer no teste.
    const root = fixture.nativeElement as HTMLElement;
    const keys = Array.from(root.querySelectorAll('.key')).map(
      (el) => (el.textContent ?? '').trim().split(' ')[0],
    );
    expect(keys).toEqual(['INC-critico-antigo', 'INC-critico-recente', 'INC-medio', 'INC-baixo']);
  });

  it('diferencia fila vazia de fila não carregada', async () => {
    stub.page = { items: [], nextCursor: null, count: 0 };
    await render();
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('Nada aguardando tratamento');
  });

  it('mostra erro acionável, com código, e não uma tela em branco', async () => {
    stub.error = new ApiError('server', 'INTERNAL_ERROR', 'detalhe interno', 500, 'ffffffff-0000');
    await render();

    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('Erro interno da plataforma');
    expect(text).toContain('INTERNAL_ERROR');
    expect(text).toContain('Tentar de novo');
    // O detalhe do servidor nunca chega à tela.
    expect(text).not.toContain('detalhe interno');
  });

  it('só oferece "carregar mais" quando há próxima página', async () => {
    stub.page = { items: [incident({})], nextCursor: null, count: 1 };
    await render();
    expect((fixture.nativeElement as HTMLElement).textContent).not.toContain('Carregar mais');

    stub.page = { items: [incident({})], nextCursor: 'cursor-opaco', count: 1 };
    await render();
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('Carregar mais');
  });
});
