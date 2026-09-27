import { ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, input, output, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  AssessmentService,
  type Assessment,
  type AssessmentHypothesis,
} from '../../../core/api/assessment.service';
import { RESOLUTION_LABEL } from '../../../core/api/types';
import { AuthService } from '../../../core/auth/auth.service';
import { ApiError } from '../../../core/errors/api-error';

const CONFIDENCE_LABEL: Record<Assessment['confidence'], string> = {
  low: 'baixa', medium: 'média', high: 'alta',
};

const BASIS_LABEL: Record<string, string> = {
  observed: 'observado', inferred: 'inferido', unknown: 'desconhecido',
};

@Component({
  selector: 'soar-assessment-panel',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="panel" aria-labelledby="assessment-title">
      <div class="head">
        <div>
          <p class="eyebrow">IA local · apoio à decisão</p>
          <h2 id="assessment-title">Avaliação do caso</h2>
        </div>
        @if (current(); as item) {
          <span class="verdict" [attr.data-verdict]="item.verdict">{{ verdict(item) }}</span>
        }
      </div>

      @if (loading()) { <p class="muted" role="status">Carregando avaliação…</p> }
      @if (failure()) {
        <p class="error" role="alert">{{ failure() }}</p>
        <button type="button" class="ghost" (click)="load()">Tentar novamente</button>
      }

      @if (!loading() && !failure() && !current()) {
        <p class="empty">A análise ainda não foi produzida para este incidente.</p>
        <p class="muted">Novos casos entram automaticamente na fila do modelo local.</p>
      }

      @if (current(); as item) {
        <div class="meta">
          <span>Confiança {{ confidence(item) }}</span>
          <span title="Confiabilidade da fonte + credibilidade da informação">Admiralty {{ item.admiralty }}</span>
          <span>{{ item.model }}</span>
          <span>{{ date(item.generated_at) }}</span>
        </div>

        @if (item.disagreed) {
          <p class="warning" role="note">
            Os dois passes discordaram. A confiança foi reduzida automaticamente.
          </p>
        }

        <h3>{{ item.title }}</h3>
        <p class="summary">{{ item.summary }}</p>
        @if (item.body.why_notable) { <p><strong>Por que importa:</strong> {{ item.body.why_notable }}</p> }

        <div class="hypotheses" aria-label="Hipóteses concorrentes">
          @for (hypothesis of orderedHypotheses(item); track hypothesis.kind) {
            <article [class.suspicious]="hypothesis.kind === 'suspicious'">
              <p class="eyebrow">Hipótese {{ hypothesis.kind === 'benign' ? 'benigna' : 'suspeita' }}</p>
              <h4>{{ hypothesis.statement }}</h4>
              <h5>Sustenta</h5>
              <ul>
                @for (evidence of hypothesis.supporting; track evidence) { <li>{{ evidence }}</li> }
                @empty { <li class="muted">Nenhuma evidência registrada.</li> }
              </ul>
              <h5>Contradiz</h5>
              <ul>
                @for (evidence of hypothesis.contradicting; track evidence) { <li>{{ evidence }}</li> }
                @empty { <li class="muted">Nenhuma evidência registrada.</li> }
              </ul>
            </article>
          }
        </div>

        <div class="analysis-grid">
          <section>
            <h4>Base das observações</h4>
            <ul class="observations">
              @for (observation of item.body.observed; track observation.statement) {
                <li><span class="basis">{{ basis(observation.basis) }}</span>{{ observation.statement }}</li>
              }
            </ul>
          </section>
          <section>
            <h4>Diamond Model</h4>
            <dl>
              <div><dt>Adversário</dt><dd>{{ item.body.diamond.adversary || 'desconhecido' }}</dd></div>
              <div><dt>Capacidade</dt><dd>{{ item.body.diamond.capability || 'desconhecida' }}</dd></div>
              <div><dt>Infraestrutura</dt><dd>{{ item.body.diamond.infrastructure || 'desconhecida' }}</dd></div>
              <div><dt>Vítima</dt><dd>{{ item.body.diamond.victim || 'desconhecida' }}</dd></div>
            </dl>
          </section>
        </div>

        <div class="analysis-grid">
          <section>
            <h4>Provável benigno se…</h4>
            <ul>@for (fact of item.body.likely_benign_if; track fact) { <li>{{ fact }}</li> }</ul>
          </section>
          <section>
            <h4>Mais suspeito se…</h4>
            <ul>@for (fact of item.body.more_suspicious_if; track fact) { <li>{{ fact }}</li> }</ul>
          </section>
          <section>
            <h4>Lacunas de inteligência</h4>
            <ul>@for (gap of item.body.intelligence_gaps; track gap) { <li>{{ gap }}</li> }</ul>
          </section>
          <section>
            <h4>Próximas ações sugeridas</h4>
            <ul>@for (action of item.body.recommended_actions; track action) { <li>{{ action }}</li> }</ul>
          </section>
        </div>

        <details>
          <summary>Raciocínio e contexto ATT&amp;CK</summary>
          <p>{{ item.body.reasoning }}</p>
          <p>{{ item.body.attack_context }}</p>
          @if (item.attack_tactics.length || item.attack_techniques.length) {
            <p class="muted">{{ item.attack_tactics.join(' · ') }} {{ item.attack_techniques.join(' · ') }}</p>
          }
        </details>

        <footer>
          @if (item.promoted_at) {
            <p class="promoted">Veredito promovido por um analista em {{ date(item.promoted_at) }}.</p>
          } @else if (canPromote()) {
            <form (submit)="promote($event, item, note.value)">
              <label>Justificativa humana
                <textarea #note required minlength="1" maxlength="4000"></textarea>
              </label>
              <button type="submit" [disabled]="saving()">
                {{ saving() ? 'Promovendo…' : 'Promover a veredito' }}
              </button>
            </form>
            <p class="muted">Promover registra concordância; não fecha o incidente.</p>
          }
          @if (mutationFailure()) { <p class="error" role="alert">{{ mutationFailure() }}</p> }
        </footer>
      }
    </section>
  `,
  styles: `
    :host { display: block; grid-column: 1 / -1; }
    .panel { border: 1px solid var(--border); border-radius: .625rem; padding: 1rem; background: var(--bg-raised); }
    .head, .meta { display: flex; justify-content: space-between; gap: .75rem; align-items: flex-start; flex-wrap: wrap; }
    .eyebrow { margin: 0; font-size: .6875rem; text-transform: uppercase; letter-spacing: .06em; color: var(--fg-muted); font-weight: 600; }
    h2 { margin: .125rem 0 0; font-size: 1rem; } h3 { margin: 1rem 0 .25rem; } h4 { margin: .2rem 0 .5rem; font-size: .875rem; }
    h5 { margin: .75rem 0 .25rem; color: var(--fg-muted); font-size: .7rem; text-transform: uppercase; }
    .verdict, .basis { border: 1px solid var(--border); border-radius: 999px; padding: .25rem .55rem; font-size: .72rem; font-weight: 700; }
    .verdict[data-verdict='true_positive'] { color: var(--sev-critical-fg); background: var(--sev-critical-bg); }
    .verdict[data-verdict='benign_true_positive'], .verdict[data-verdict='false_positive'] { color: var(--sev-low-fg); background: var(--sev-low-bg); }
    .meta { justify-content: flex-start; margin-top: .75rem; color: var(--fg-muted); font-size: .75rem; }
    .summary { font-size: .9375rem; } .muted { color: var(--fg-muted); font-size: .8125rem; }
    .warning, .error, .empty, .promoted { padding: .625rem; border-radius: .375rem; font-size: .8125rem; }
    .warning { background: var(--sev-medium-bg); color: var(--sev-medium-fg); }
    .error { background: var(--sev-critical-bg); color: var(--sev-critical-fg); }
    .empty, .promoted { background: var(--sev-low-bg); color: var(--sev-low-fg); }
    .hypotheses, .analysis-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .75rem; margin-top: 1rem; }
    .hypotheses article, .analysis-grid section { border: 1px solid var(--border-subtle); border-radius: .5rem; padding: .75rem; }
    .hypotheses article.suspicious { border-color: var(--sev-critical-fg); }
    ul { margin: .25rem 0; padding-left: 1.1rem; } li { margin: .25rem 0; font-size: .8125rem; }
    .observations { list-style: none; padding: 0; } .observations li { display: flex; align-items: flex-start; gap: .4rem; }
    .basis { flex: none; padding: .1rem .35rem; color: var(--fg-muted); font-weight: 500; }
    dl { margin: 0; } dl div { display: grid; grid-template-columns: 7rem 1fr; gap: .5rem; padding: .25rem 0; }
    dt { color: var(--fg-muted); font-size: .75rem; } dd { margin: 0; font-size: .8125rem; }
    details { margin-top: 1rem; font-size: .8125rem; } summary { cursor: pointer; font-weight: 600; }
    footer { border-top: 1px solid var(--border-subtle); margin-top: 1rem; padding-top: 1rem; }
    form, label { display: flex; flex-direction: column; } form { gap: .5rem; max-width: 36rem; } label { gap: .25rem; color: var(--fg-muted); font-size: .75rem; }
    textarea, button { font: inherit; color: var(--fg); background: var(--bg); border: 1px solid var(--border); border-radius: .375rem; padding: .5rem; }
    textarea { min-height: 4rem; resize: vertical; } button { cursor: pointer; background: var(--focus); color: white; border-color: var(--focus); font-weight: 600; }
    button.ghost { background: transparent; color: var(--fg-muted); } button:disabled { opacity: .5; cursor: default; }
    :is(button,textarea,summary):focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
    @media(max-width: 48rem) { .hypotheses, .analysis-grid { grid-template-columns: 1fr; } }
  `,
})
export class AssessmentPanel implements OnInit {
  readonly incidentId = input.required<string>();
  readonly promoted = output<Assessment>();

  private readonly api = inject(AssessmentService);
  private readonly auth = inject(AuthService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly assessments = signal<Assessment[]>([]);
  protected readonly loading = signal(true);
  protected readonly saving = signal(false);
  protected readonly failure = signal('');
  protected readonly mutationFailure = signal('');
  protected readonly current = computed(() => this.assessments()[0] ?? null);
  protected readonly canPromote = computed(() => this.auth.can('assessment.promote'));

  ngOnInit(): void { this.load(); }

  protected load(): void {
    this.loading.set(true); this.failure.set('');
    this.api.list(this.incidentId()).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: (items) => { this.assessments.set(items); this.loading.set(false); },
      error: (err: ApiError) => { this.failure.set(err.userMessage); this.loading.set(false); },
    });
  }

  protected promote(event: Event, item: Assessment, rawNote: string): void {
    event.preventDefault();
    const note = rawNote.trim();
    if (!note) { this.mutationFailure.set('Informe uma justificativa.'); return; }
    this.saving.set(true); this.mutationFailure.set('');
    this.api.promote(this.incidentId(), item.id, note)
      .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: (updated) => {
          this.assessments.update((items) => items.map((a) => a.id === updated.id ? updated : a));
          this.saving.set(false); this.promoted.emit(updated);
        },
        error: (err: ApiError) => { this.mutationFailure.set(err.userMessage); this.saving.set(false); },
      });
  }

  protected orderedHypotheses(item: Assessment): AssessmentHypothesis[] {
    const order: Record<string, number> = { benign: 0, suspicious: 1 };
    return [...item.body.hypotheses].sort((a, b) => (order[a.kind] ?? 2) - (order[b.kind] ?? 2));
  }

  protected verdict(item: Assessment): string { return RESOLUTION_LABEL[item.verdict]; }
  protected confidence(item: Assessment): string { return CONFIDENCE_LABEL[item.confidence]; }
  protected basis(value: string): string { return BASIS_LABEL[value] ?? value; }
  protected date(value: string): string {
    return new Intl.DateTimeFormat('pt-BR', { dateStyle: 'short', timeStyle: 'short' }).format(new Date(value));
  }
}
