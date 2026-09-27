import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import type { ActionPlan } from '../../../core/api/response.service';

/**
 * O plano, do jeito que o operador precisa ler antes de confirmar.
 *
 * Mostra a contagem afetada, como reverter, os avisos e a requisição literal.
 * A requisição aparece de propósito: nas primeiras vezes o analista executa
 * à mão em vez de confiar no botão, e esconder isso não aumenta a confiança
 * — só reduz a informação.
 */
@Component({
  selector: 'soar-action-plan-card',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <article class="plan" [class.blocked]="!plan().ready">
      <header>
        <h3>{{ plan().summary }}</h3>
        @if (affected() !== null) {
          <span class="count" [class.big]="isLarge()">{{ affected() }}</span>
        }
      </header>

      @if (!plan().ready) {
        <p class="blocked-note" role="status">
          Este plano não pode ser aplicado agora.
        </p>
      }

      @if (plan().details.length) {
        <ul class="details">
          @for (d of plan().details; track d) { <li>{{ d }}</li> }
        </ul>
      }

      @for (w of plan().warnings; track w) {
        <p class="warning" role="note">{{ w }}</p>
      }

      @if (plan().reversible) {
        <p class="reversible"><strong>Como reverter:</strong> {{ plan().reversible }}</p>
      }

      @if (request()) {
        <details>
          <summary>Requisição que será enviada</summary>
          <pre>{{ request() }}</pre>
        </details>
      }
    </article>
  `,
  styles: `
    .plan {
      border: 1px solid var(--border); border-radius: .5rem; padding: 1rem;
      background: var(--bg-raised);
    }
    .plan.blocked { border-color: var(--sev-medium-fg); }
    header { display: flex; align-items: baseline; gap: 1rem; justify-content: space-between; }
    h3 { margin: 0; font-size: 1rem; font-weight: 600; line-height: 1.35; }
    .count {
      font-variant-numeric: tabular-nums; font-size: 1.5rem; font-weight: 650;
      color: var(--fg); line-height: 1;
    }
    /* Um escopo grande não bloqueia, mas não passa despercebido. */
    .count.big { color: var(--sev-high-fg); }
    .blocked-note { color: var(--sev-medium-fg); font-size: .875rem; margin: .5rem 0 0; }
    .details { margin: .625rem 0 0; padding-left: 1.1rem; color: var(--fg-muted); font-size: .875rem; }
    .details li { margin-bottom: .125rem; }
    .warning {
      margin: .625rem 0 0; padding: .5rem .625rem; border-radius: .375rem;
      background: var(--sev-medium-bg); color: var(--sev-medium-fg); font-size: .8125rem;
    }
    .reversible { margin: .625rem 0 0; font-size: .8125rem; color: var(--fg-muted); }
    details { margin-top: .75rem; font-size: .8125rem; color: var(--fg-muted); }
    summary { cursor: pointer; }
    pre {
      margin: .5rem 0 0; padding: .625rem; overflow-x: auto;
      background: var(--bg); border: 1px solid var(--border-subtle); border-radius: .375rem;
      font-size: .75rem; line-height: 1.5;
    }
  `,
})
export class ActionPlanCard {
  readonly plan = input.required<ActionPlan>();

  protected readonly affected = computed(() => this.plan().affected ?? null);
  protected readonly isLarge = computed(() => (this.plan().affected ?? 0) > 1000);
  protected readonly request = computed(() => {
    const r = this.plan().request;
    return r ? JSON.stringify(r, null, 2) : '';
  });
}
