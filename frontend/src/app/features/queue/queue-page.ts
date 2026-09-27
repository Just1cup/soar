import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { DestroyRef } from '@angular/core';
import { Router } from '@angular/router';
import { IncidentsService } from '../../core/api/incidents.service';
import { ApiError } from '../../core/errors/api-error';
import { SEVERITY_RANK, type IncidentStatus, type IncidentSummary } from '../../core/api/types';
import { type AsyncState, failure, loading, success } from '../../shared/ui/async-state';
import { IncidentTable } from './components/incident-table';

/**
 * O componente inteligente da fila: carrega, guarda estado, ordena.
 *
 * Ordenação no cliente **apenas** dentro da página já recebida — o backend é
 * quem ordena e pagina (docs/soar/06 §94: nunca trazer tudo para filtrar no
 * browser). Aqui a reordenação por severidade é uma preferência de leitura
 * sobre 50 linhas, não uma consulta.
 */
@Component({
  selector: 'soar-queue-page',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [IncidentTable],
  template: `
    <header class="head">
      <div>
        <h1>Incidentes</h1>
        <p class="sub">Fila de triagem e acompanhamento</p>
      </div>
      <div class="filters">
        <label>
          <span>Estado</span>
          <select [value]="status()" (change)="onStatus($event)">
            <option value="open">Todos os incidentes abertos</option>
            <option value="all">Todos os incidentes</option>
            <option value="new">Novo</option>
            <option value="triage">Triagem</option>
            <option value="investigating">Investigando</option>
            <option value="pending_action">Aguardando ação</option>
            <option value="closed">Fechado</option>
          </select>
        </label>
        <button type="button" (click)="reload()" [disabled]="isLoading()">Atualizar</button>
      </div>
    </header>

    @switch (state().status) {
      @case ('loading') {
        <p class="note" role="status">Carregando a fila…</p>
      }
      @case ('error') {
        <div class="error" role="alert">
          <strong>{{ errorMessage() }}</strong>
          <p class="code">{{ errorCode() }}</p>
          <button type="button" (click)="reload()">Tentar de novo</button>
        </div>
      }
      @case ('success') {
        @if (rows().length === 0) {
          <p class="note">Nada aguardando tratamento.</p>
        } @else {
          <p class="count">
            {{ rows().length }} incidente{{ rows().length === 1 ? '' : 's' }}
            @if (nextCursor()) { · há mais páginas }
          </p>
          <soar-incident-table [incidents]="rows()" (select)="onSelect($event)" />
          @if (nextCursor()) {
            <button class="more" type="button" (click)="loadMore()" [disabled]="isLoading()">
              Carregar mais
            </button>
          }
        }
      }
    }
  `,
  styles: `
    :host { display: block; max-width: 88rem; margin: 0 auto; padding: 1.5rem 1rem 4rem; }
    .head { display: flex; flex-wrap: wrap; gap: 1rem; align-items: flex-end;
            justify-content: space-between; margin-bottom: 1.25rem; }
    h1 { font-size: 1.375rem; font-weight: 650; margin: 0; letter-spacing: -.01em; }
    .sub { margin: .25rem 0 0; color: var(--fg-muted); font-size: .875rem; }
    .filters { display: flex; gap: .75rem; align-items: flex-end; }
    label { display: flex; flex-direction: column; gap: .25rem; font-size: .75rem; color: var(--fg-muted); }
    select, button {
      font: inherit; font-size: .875rem; padding: .375rem .625rem;
      border: 1px solid var(--border); border-radius: .375rem;
      background: var(--bg-raised); color: var(--fg);
    }
    button { cursor: pointer; }
    button:hover:not(:disabled) { background: var(--bg-hover); }
    button:disabled { opacity: .5; cursor: default; }
    :is(select, button):focus-visible { outline: 2px solid var(--focus); outline-offset: 1px; }
    .note { color: var(--fg-muted); font-size: .875rem; padding: 2rem 0; }
    .count { color: var(--fg-muted); font-size: .8125rem; margin: 0 0 .5rem; }
    .error { border: 1px solid var(--sev-critical-fg); background: var(--sev-critical-bg);
             border-radius: .5rem; padding: 1rem; }
    .error strong { display: block; margin-bottom: .25rem; }
    .code { font-family: ui-monospace, monospace; font-size: .75rem; color: var(--fg-muted); margin: 0 0 .75rem; }
    .more { margin-top: 1rem; }
    @media (prefers-reduced-motion: no-preference) { button { transition: background-color .12s ease; } }
  `,
})
export class QueuePage {
  private readonly incidents = inject(IncidentsService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly router = inject(Router);

  protected readonly state = signal<AsyncState<IncidentSummary[]>>(loading());
  protected readonly status = signal<IncidentStatus | 'open' | 'all'>('open');
  protected readonly nextCursor = signal<string | null>(null);

  protected readonly isLoading = computed(() => this.state().status === 'loading');

  /** Ordem de leitura do SOC: severidade primeiro, depois quem espera há mais tempo. */
  protected readonly rows = computed(() => {
    const s = this.state();
    if (s.status !== 'success') return [] as IncidentSummary[];
    return [...s.value].sort(
      (a, b) =>
        SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
        Date.parse(a.first_seen) - Date.parse(b.first_seen),
    );
  });

  protected readonly errorMessage = computed(() => {
    const s = this.state();
    return s.status === 'error' ? s.error.userMessage : '';
  });

  protected readonly errorCode = computed(() => {
    const s = this.state();
    return s.status === 'error' ? `${s.error.code} · HTTP ${s.error.status}` : '';
  });

  constructor() {
    this.reload();
  }

  protected reload(): void {
    this.nextCursor.set(null);
    this.state.set(loading());
    this.fetch(undefined, []);
  }

  protected loadMore(): void {
    const cursor = this.nextCursor();
    const current = this.state();
    if (!cursor || current.status !== 'success') return;
    this.fetch(cursor, current.value);
  }

  private fetch(cursor: string | undefined, previous: IncidentSummary[]): void {
    this.incidents
      .list({ status: this.status() !== 'open' && this.status() !== 'all' ? this.status() as IncidentStatus : undefined, openOnly: this.status() === 'open', limit: 50, cursor })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (page) => {
          this.nextCursor.set(page.nextCursor);
          this.state.set(success([...previous, ...page.items]));
        },
        // O erro já chega classificado do interceptor; o componente não
        // inspeciona status HTTP nem lê mensagem do servidor.
        error: (err: ApiError) => this.state.set(failure(err)),
      });
  }

  protected onStatus(event: Event): void {
    const value = (event.target as HTMLSelectElement).value;
    this.status.set(value as IncidentStatus | 'open' | 'all');
    this.reload();
  }

  protected onSelect(incident: IncidentSummary): void {
    void this.router.navigate(['/incidents', incident.id]);
  }
}
