import { ChangeDetectionStrategy, Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { ApiError } from '../../core/errors/api-error';
import { ResponseService, type Approval } from '../../core/api/response.service';
import { AuthService } from '../../core/auth/auth.service';
import { ActionPlanCard } from '../incident/components/action-plan-card';
import { AgePipe } from '../../shared/ui/age.pipe';

/**
 * A fila de aprovações.
 *
 * Cada item mostra o plano inteiro, porque aprovar sem ler a contagem
 * afetada e o "como reverter" é o mesmo que clicar em "Tem certeza?".
 *
 * Recusar exige motivo: o backend impõe, e a tela diz por quê em vez de
 * apenas bloquear o botão.
 */
@Component({
  selector: 'soar-approvals-page',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ActionPlanCard, AgePipe, RouterLink],
  template: `
    <div class="page">
      <header class="head">
        <div>
          <h1>Aprovações</h1>
          <p class="muted">Ações de resposta aguardando decisão humana</p>
        </div>
        <button type="button" class="ghost" (click)="load()" [disabled]="loading()">Atualizar</button>
      </header>

      @if (loading()) { <p class="muted" role="status">Carregando…</p> }
      @if (error()) { <p class="error-text" role="alert">{{ error() }}</p> }

      @if (!loading() && pending().length === 0) {
        <p class="muted empty">Nada aguardando aprovação.</p>
      }

      @for (item of pending(); track item.id) {
        <article class="item">
          <header>
            <div>
              <p class="action">{{ item.action }}</p>
              <p class="muted">
                pedida por {{ item.requested_by }} · {{ item.requested_at | age }}
                @if (item.incident_id) {
                  · <a [routerLink]="['/incidents', item.incident_id]">ver incidente</a>
                }
              </p>
            </div>
          </header>

          <soar-action-plan-card [plan]="item.plan" />

          @if (canDecide()) {
            <label class="note">
              Motivo <span class="hint">(obrigatório ao recusar)</span>
              <textarea
                rows="2" maxlength="4000"
                [value]="notes()[item.id] ?? ''"
                (input)="onNote(item.id, $event)"></textarea>
            </label>
            <div class="row">
              <button type="button" (click)="decide(item, true)" [disabled]="busy() === item.id">
                Aprovar
              </button>
              <button
                type="button" class="danger"
                (click)="decide(item, false)"
                [disabled]="busy() === item.id || !(notes()[item.id] ?? '').trim()">
                Recusar
              </button>
            </div>
          } @else {
            <p class="muted">Você não tem permissão para decidir aprovações.</p>
          }

          @if (itemError()[item.id]; as err) { <p class="error-text" role="alert">{{ err }}</p> }
        </article>
      }
    </div>
  `,
  styles: `
    .page { max-width: 52rem; margin: 0 auto; padding: 1.5rem 1rem 4rem; }
    .head { display: flex; align-items: flex-end; justify-content: space-between; margin-bottom: 1.25rem; }
    h1 { margin: 0; font-size: 1.375rem; font-weight: 650; letter-spacing: -.01em; }
    .muted { color: var(--fg-muted); font-size: .8125rem; margin: .25rem 0 0; }
    .empty { padding: 2rem 0; }
    .item {
      border: 1px solid var(--border); border-radius: .5rem; padding: 1rem;
      background: var(--bg-raised); margin-bottom: 1rem;
      display: flex; flex-direction: column; gap: .75rem;
    }
    .action { margin: 0; font-weight: 600; font-family: ui-monospace, monospace; font-size: .875rem; }
    .note { display: flex; flex-direction: column; gap: .25rem; font-size: .8125rem; color: var(--fg-muted); }
    .hint { font-weight: 400; opacity: .8; }
    textarea {
      font: inherit; font-size: .875rem; padding: .375rem .5rem; color: var(--fg);
      background: var(--bg); border: 1px solid var(--border); border-radius: .375rem; resize: vertical;
    }
    .row { display: flex; gap: .5rem; }
    button {
      font: inherit; font-size: .875rem; padding: .4rem .75rem; cursor: pointer; font-weight: 600;
      border: 1px solid var(--border); border-radius: .375rem;
      background: var(--focus); color: var(--bg);
    }
    button.ghost { background: transparent; color: var(--fg-muted); font-weight: 400; }
    button.danger { background: transparent; color: var(--sev-critical-fg); border-color: var(--sev-critical-fg); }
    button:disabled { opacity: .45; cursor: default; }
    .error-text { margin: 0; color: var(--sev-critical-fg); font-size: .8125rem; }
    a { color: var(--focus); }
  `,
})
export class ApprovalsPage {
  private readonly api = inject(ResponseService);
  private readonly auth = inject(AuthService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly pending = signal<Approval[]>([]);
  protected readonly loading = signal(true);
  protected readonly error = signal('');
  protected readonly busy = signal<string | null>(null);
  protected readonly notes = signal<Record<string, string>>({});
  protected readonly itemError = signal<Record<string, string>>({});
  protected readonly canDecide = computed(() => this.auth.can('approval.decide'));

  constructor() {
    this.load();
  }

  protected load(): void {
    this.loading.set(true);
    this.error.set('');
    this.api
      .approvals()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (list) => { this.pending.set(list); this.loading.set(false); },
        error: (err: ApiError) => { this.error.set(err.userMessage); this.loading.set(false); },
      });
  }

  protected onNote(id: string, event: Event): void {
    const value = (event.target as HTMLTextAreaElement).value;
    this.notes.update((c) => ({ ...c, [id]: value }));
  }

  protected decide(item: Approval, approve: boolean): void {
    this.busy.set(item.id);
    this.itemError.update((c) => ({ ...c, [item.id]: '' }));
    this.api
      .decide(item.id, approve, this.notes()[item.id] ?? '', item.version)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          // Sai da fila: só o que ainda pode ser decidido pertence aqui.
          this.pending.update((list) => list.filter((a) => a.id !== item.id));
          this.busy.set(null);
        },
        error: (err: ApiError) => {
          this.itemError.update((c) => ({ ...c, [item.id]: err.userMessage }));
          this.busy.set(null);
          // Conflito significa que alguém decidiu antes; recarregar é a
          // única resposta honesta.
          if (err.kind === 'conflict') this.load();
        },
      });
  }
}
