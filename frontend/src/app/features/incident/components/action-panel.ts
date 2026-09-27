import { ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, input, output, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { forkJoin, switchMap } from 'rxjs';
import { AssessmentService, type CaseEvidence } from '../../../core/api/assessment.service';
import { ApiError } from '../../../core/errors/api-error';
import {
  AUTONOMY_LABEL,
  ResponseService,
  type ActionPreview,
  type ActionRun,
  type Integration,
  type IntegrationAction,
} from '../../../core/api/response.service';
import { AuthService } from '../../../core/auth/auth.service';
import { ActionPlanCard } from './action-plan-card';

type Step = 'choose' | 'planned' | 'awaiting_approval' | 'done';

interface ObservableOption { field: string; value: string; label: string; }

const ACTION_CLOSE = 'elastic-siem.close_alerts';
const ACTION_EXCEPTION = 'elastic-siem.create_exception';

const FIELD_LABEL: Record<string, string> = {
  rule_name: 'Regra', host: 'Host', entity: 'Entidade', status: 'Estado final',
  field: 'Campo ECS', value: 'Valor', comment: 'Justificativa',
  'process.executable': 'Processo', 'process.parent.executable': 'Processo pai',
  'user.name': 'Usuário', 'source.ip': 'IP de origem', 'destination.ip': 'IP de destino',
  'destination.domain': 'Domínio', 'dns.question.name': 'Consulta DNS',
  'url.original': 'URL', 'file.path': 'Arquivo', 'file.hash.sha256': 'Hash SHA-256',
};

// Evita sugerir automaticamente campos frágeis ou amplos demais, como linha
// de comando, método HTTP e status. Eles continuam disponíveis no editor.
const TUNING_FIELDS = new Set([
  'process.executable', 'process.parent.executable', 'user.name',
  'source.ip', 'destination.ip', 'destination.domain', 'dns.question.name',
  'url.original', 'file.path', 'file.hash.sha256',
]);

/** Os dados técnicos do caso viram uma proposta editável; o operador decide
 * o plano, em vez de redigitar a telemetria que o SOAR já possui. */
@Component({
  selector: 'soar-action-panel',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ActionPlanCard],
  template: `
    <section class="panel" aria-labelledby="action-title">
      <div class="head">
        <div><p class="eyebrow">Resposta guiada</p><h2 id="action-title">Ações</h2></div>
        @if (evidence()) { <span class="prefilled">preenchido pelo caso</span> }
      </div>

      @if (loading()) { <p class="muted" role="status">Preparando ações e evidências…</p> }

      @if (!loading() && (step() === 'choose' || step() === 'done')) {
        <label class="field">O que deseja fazer?
          <select [value]="selected()" (change)="onSelect($event)">
            <option value="">Escolha uma ação…</option>
            @for (opt of options(); track opt.qualified) {
              <option [value]="opt.qualified" [disabled]="!opt.action.implemented || !opt.allowed">
                {{ opt.action.name }}
                @if (!opt.action.implemented) { (indisponível) }
                @else if (!opt.allowed) { (sem permissão) }
              </option>
            }
          </select>
        </label>

        @if (chosen(); as action) {
          <p class="autonomy">{{ autonomyLabel(action.autonomy) }} · {{ action.reversible }}</p>
          @if (!action.implemented && action.unavailable) { <p class="unavailable" role="note">{{ action.unavailable }}</p> }

          @if (selected() === actionException) {
            <div class="proposal">
              <p><strong>Exceção proposta</strong><span>Escolha o elemento que identifica esta atividade legítima.</span></p>
              @if (observableOptions().length) {
                <label class="field">Entidade, processo ou artefato
                  <select [value]="selectedObservable()" (change)="onObservable($event)">
                    @for (option of observableOptions(); track option.field + option.value; let index = $index) {
                      <option [value]="index">{{ option.label }} · {{ option.value }}</option>
                    }
                    <option value="custom">Outro valor…</option>
                  </select>
                </label>
              } @else { <p class="unavailable">O caso não contém um observável adequado. Informe um valor no editor abaixo.</p> }
            </div>
          }

          @if (selected() !== actionClose) {
            <details class="editor" [open]="selected() === actionException && !hasExceptionTarget()">
              <summary>Editar detalhes da proposta</summary>
              <div class="editor-fields">
                @for (field of inputFields(); track field) {
                  <label class="field">{{ fieldLabel(field) }}
                    @if (field === 'comment') {
                      <textarea rows="3" [value]="inputs()[field] ?? ''" (input)="onInput(field, $event)"></textarea>
                    } @else {
                      <input type="text" [value]="inputs()[field] ?? ''" (input)="onInput(field, $event)" />
                    }
                    @if (fieldDescription(field)) { <span class="hint">{{ fieldDescription(field) }}</span> }
                  </label>
                }
              </div>
            </details>
          }

          @if (selected() === actionException) {
            <button type="button" (click)="doPlan()" [disabled]="busy() || !action.implemented || !canPlan()">
              {{ busy() ? 'Preparando plano…' : 'Revisar exceção pronta' }}
            </button>
          } @else if (selected() !== actionClose) {
            <button type="button" (click)="doPlan()" [disabled]="busy() || !action.implemented || !canPlan()">
              {{ busy() ? 'Preparando plano…' : 'Revisar ação' }}
            </button>
          }
        }
      }

      @if (busy() && selected() === actionClose && !preview()) { <p class="muted" role="status">Contando os alertas que serão fechados…</p> }

      @if (preview(); as p) {
        <soar-action-plan-card [plan]="p.plan" />
        @if (step() === 'awaiting_approval') {
          <p class="question"><strong>Aplicar este plano?</strong> Nenhuma alteração foi feita ainda.</p>
          @if (canDecide()) {
            <div class="row" aria-label="Decisão da aprovação">
              <button type="button" (click)="approveAndExecute()" [disabled]="busy() || !p.plan.ready">
                {{ busy() ? 'Aplicando…' : 'Sim, aprovar e executar' }}
              </button>
              <button type="button" class="danger" (click)="reject()" [disabled]="busy()">Não</button>
            </div>
          } @else {
            <p class="awaiting" role="status">Aguardando decisão de quem possui permissão de aprovação.</p>
            <a class="queue-link" href="/approvals">Abrir fila de aprovações</a>
          }
          @if (p.expires_at) { <p class="expiry">O plano expira às {{ expiry() }}.</p> }
        } @else if (step() === 'planned') {
          <div class="row">
            <button type="button" (click)="doExecute()" [disabled]="busy() || !p.plan.ready">{{ busy() ? 'Executando…' : 'Executar' }}</button>
            <button type="button" class="ghost" (click)="reset()">Cancelar</button>
          </div>
        }
      }

      @if (decision()) { <p class="decision" role="status">{{ decision() }}</p> }
      @if (result(); as run) {
        <p class="result" [class.failed]="run.status === 'failed'" role="status">
          @if (run.status === 'succeeded') {
            Executada com sucesso.
            @if (run.affected !== null && run.affected !== undefined) { {{ run.affected }} objeto(s) afetado(s). }
          } @else { Falhou: {{ run.error }} }
        </p>
        <button type="button" class="ghost" (click)="reset()">Nova ação</button>
      }
      @if (failure(); as err) { <p class="error-text" role="alert">{{ err }}</p> }
    </section>
  `,
  styles: `
    :host{display:block;min-width:0}.panel{border:1px solid var(--border);border-radius:.625rem;padding:1rem;background:var(--bg-raised);display:flex;flex-direction:column;gap:.75rem;min-width:0}.head{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem}.eyebrow{margin:0;font-size:.6875rem;text-transform:uppercase;letter-spacing:.06em;color:var(--fg-muted);font-weight:600}h2{margin:.125rem 0 0;font-size:1rem}.prefilled{border:1px solid var(--border);border-radius:999px;color:var(--sev-low-fg);font-size:.68rem;font-weight:700;padding:.22rem .5rem;white-space:nowrap}
    .field{display:flex;flex-direction:column;gap:.3rem;font-size:.8125rem;color:var(--fg-muted);min-width:0}select,input,textarea{box-sizing:border-box;width:100%;max-width:100%;min-width:0;font:inherit;font-size:.875rem;padding:.45rem .55rem;color:var(--fg);background:var(--bg);border:1px solid var(--border);border-radius:.375rem}textarea{resize:vertical}.hint{font-size:.7rem}button{font:inherit;font-size:.875rem;padding:.45rem .75rem;cursor:pointer;border:1px solid var(--border);border-radius:.375rem;background:var(--focus);color:var(--bg);font-weight:650}button.ghost{background:transparent;color:var(--fg-muted);font-weight:400}button.danger{background:transparent;color:var(--sev-critical-fg);border-color:var(--sev-critical-fg)}button:disabled{opacity:.5;cursor:default}.row{display:flex;gap:.5rem;flex-wrap:wrap}
    .autonomy,.muted,.expiry{color:var(--fg-muted);font-size:.78rem;margin:0}.unavailable,.awaiting,.decision{margin:0;padding:.55rem .625rem;border-radius:.375rem;font-size:.8125rem}.unavailable{background:var(--sev-medium-bg);color:var(--sev-medium-fg)}.awaiting,.decision{background:var(--sev-low-bg);color:var(--sev-low-fg)}.proposal{background:var(--bg);border:1px solid var(--border-subtle);border-radius:.5rem;padding:.7rem}.proposal p{display:flex;flex-direction:column;gap:.15rem;margin:0 0 .6rem}.proposal p span{color:var(--fg-muted);font-size:.75rem}.editor{border-top:1px solid var(--border-subtle);padding-top:.65rem}.editor summary{cursor:pointer;color:var(--fg-muted);font-size:.78rem}.editor-fields{display:flex;flex-direction:column;gap:.65rem;margin-top:.65rem}.question{margin:0;font-size:.875rem}.queue-link{color:var(--focus);font-size:.8125rem}.result{margin:0;padding:.55rem .625rem;border-radius:.375rem;font-size:.875rem;background:var(--sev-low-bg);color:var(--sev-low-fg)}.result.failed{background:var(--sev-critical-bg);color:var(--sev-critical-fg)}.error-text{margin:0;color:var(--sev-critical-fg);font-size:.8125rem}:is(button,select,input,textarea,summary,a):focus-visible{outline:2px solid var(--focus);outline-offset:2px}
  `,
})
export class ActionPanel implements OnInit {
  readonly incidentId = input.required<string>();
  readonly executed = output<ActionRun>();
  private readonly api = inject(ResponseService);
  private readonly assessment = inject(AssessmentService);
  private readonly auth = inject(AuthService);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly actionClose = ACTION_CLOSE;
  protected readonly actionException = ACTION_EXCEPTION;
  protected readonly integrations = signal<Integration[]>([]);
  protected readonly evidence = signal<CaseEvidence | null>(null);
  protected readonly loading = signal(true);
  protected readonly busy = signal(false);
  protected readonly failure = signal('');
  protected readonly decision = signal('');
  protected readonly selected = signal('');
  protected readonly selectedObservable = signal('0');
  protected readonly inputs = signal<Record<string, string>>({});
  protected readonly preview = signal<ActionPreview | null>(null);
  protected readonly result = signal<ActionRun | null>(null);
  protected readonly step = signal<Step>('choose');
  private idempotencyKey = '';
  private approvalAlreadyDecided = false;

  protected readonly options = computed(() => this.integrations().flatMap((integration) => integration.actions.map((action) => ({
    qualified: `${integration.id}.${action.id}`, integration, action, allowed: this.auth.can(action.permission),
  }))));
  protected readonly chosen = computed<IntegrationAction | null>(() => this.options().find((option) => option.qualified === this.selected())?.action ?? null);
  protected readonly inputFields = computed(() => Object.keys(this.chosen()?.input ?? {}));
  protected readonly observableOptions = computed<ObservableOption[]>(() => this.buildObservableOptions());
  protected readonly hasExceptionTarget = computed(() => Boolean(this.inputs()['field']?.trim() && this.inputs()['value']?.trim()));
  protected readonly canPlan = computed(() => this.inputFields().every((field) => !this.chosen()?.input[field]?.required || Boolean(this.inputs()[field]?.trim())));
  protected readonly expiry = computed(() => this.preview()?.expires_at ? new Date(this.preview()!.expires_at!).toLocaleTimeString('pt-BR') : '');
  protected readonly canDecide = computed(() => this.auth.can('approval.decide'));
  protected readonly autonomyLabel = (value: IntegrationAction['autonomy']): string => AUTONOMY_LABEL[value];

  ngOnInit(): void {
    forkJoin({ integrations: this.api.integrations(), evidence: this.assessment.evidence(this.incidentId()) })
      .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: ({ integrations, evidence }) => { this.integrations.set(integrations); this.evidence.set(evidence); this.loading.set(false); },
        error: (error: ApiError) => { this.failure.set(error.userMessage); this.loading.set(false); },
      });
  }

  protected onSelect(event: Event): void {
    const qualified = (event.target as HTMLSelectElement).value;
    this.selected.set(qualified); this.clearOutcome(); this.inputs.set(this.defaultInputs(qualified)); this.selectedObservable.set('0');
    if (qualified === ACTION_CLOSE && this.canPlan()) this.doPlan();
  }

  protected onObservable(event: Event): void {
    const selected = (event.target as HTMLSelectElement).value;
    this.selectedObservable.set(selected);
    if (selected === 'custom') { this.inputs.update((current) => ({ ...current, field: '', value: '' })); return; }
    const option = this.observableOptions()[Number(selected)];
    if (option) this.inputs.update((current) => ({ ...current, field: option.field, value: option.value, comment: this.exceptionComment(option.field, option.value) }));
  }

  protected onInput(field: string, event: Event): void {
    const value = (event.target as HTMLInputElement | HTMLTextAreaElement).value;
    this.inputs.update((current) => ({ ...current, [field]: value }));
  }
  protected fieldLabel(field: string): string { return FIELD_LABEL[field] ?? field; }
  protected fieldDescription(field: string): string { return this.chosen()?.input[field]?.descr ?? ''; }

  protected doPlan(): void {
    if (!this.canPlan()) return;
    this.busy.set(true); this.failure.set(''); this.result.set(null); this.decision.set('');
    this.api.plan(this.incidentId(), this.selected(), this.inputs()).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: (preview) => {
        this.preview.set(preview); this.idempotencyKey = crypto.randomUUID(); this.approvalAlreadyDecided = false;
        this.step.set(preview.approval_id ? 'awaiting_approval' : 'planned'); this.busy.set(false);
      },
      error: (error: ApiError) => { this.failure.set(error.userMessage); this.busy.set(false); },
    });
  }

  protected approveAndExecute(): void {
    const preview = this.preview();
    if (!preview?.approval_id) return;
    if (this.approvalAlreadyDecided) { this.doExecute(); return; }
    const version = preview.approval_version;
    if (!version) { this.failure.set('O plano não informou a versão da aprovação. Atualize e tente novamente.'); return; }
    this.busy.set(true); this.failure.set('');
    this.api.decide(preview.approval_id, true, 'Aprovado diretamente no incidente.', version).pipe(
      switchMap(() => {
        this.approvalAlreadyDecided = true;
        return this.api.execute(this.incidentId(), this.selected(), this.inputs(), preview.approval_id ?? null, this.idempotencyKey);
      }), takeUntilDestroyed(this.destroyRef),
    ).subscribe({
      next: (run) => this.finishRun(run),
      error: (error: ApiError) => { this.failure.set(error.userMessage); this.busy.set(false); },
    });
  }

  protected reject(): void {
    const preview = this.preview();
    if (!preview?.approval_id || !preview.approval_version) return;
    this.busy.set(true); this.failure.set('');
    this.api.decide(preview.approval_id, false, 'Não aprovado pelo analista no incidente.', preview.approval_version)
      .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: () => { this.preview.set(null); this.step.set('done'); this.busy.set(false); this.decision.set('Ação não aprovada. Nenhuma alteração foi feita.'); },
        error: (error: ApiError) => { this.failure.set(error.userMessage); this.busy.set(false); },
      });
  }

  protected doExecute(): void {
    const preview = this.preview();
    if (!preview) return;
    this.busy.set(true); this.failure.set('');
    this.api.execute(this.incidentId(), this.selected(), this.inputs(), preview.approval_id ?? null, this.idempotencyKey)
      .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: (run) => this.finishRun(run),
        error: (error: ApiError) => { this.failure.set(error.userMessage); this.busy.set(false); },
      });
  }

  protected reset(): void { this.selected.set(''); this.inputs.set({}); this.clearOutcome(); }
  private clearOutcome(): void {
    this.preview.set(null); this.result.set(null); this.failure.set(''); this.decision.set(''); this.step.set('choose'); this.approvalAlreadyDecided = false;
  }
  private finishRun(run: ActionRun): void {
    this.result.set(run); this.step.set('done'); this.preview.set(null); this.busy.set(false); this.executed.emit(run);
  }

  private defaultInputs(qualified: string): Record<string, string> {
    const cluster = this.evidence()?.cluster;
    if (!cluster) return {};
    if (qualified === ACTION_CLOSE) return { rule_name: cluster.rule_name, host: cluster.host ?? '', entity: cluster.entity ?? '', status: 'closed' };
    if (qualified === ACTION_EXCEPTION) {
      const target = this.observableOptions()[0];
      return {
        rule_name: cluster.rule_name, field: target?.field ?? '', value: target?.value ?? '',
        comment: target ? this.exceptionComment(target.field, target.value) : `Tuning revisado pelo SOAR para a regra ${cluster.rule_name}.`,
      };
    }
    return { rule_name: cluster.rule_name };
  }

  private buildObservableOptions(): ObservableOption[] {
    const cluster = this.evidence()?.cluster;
    if (!cluster) return [];
    const result: ObservableOption[] = [];
    const seen = new Set<string>();
    const add = (field: string, value: string | null | undefined): void => {
      const clean = value?.trim();
      if (!clean || !TUNING_FIELDS.has(field)) return;
      const key = `${field}\u0000${clean}`;
      if (seen.has(key)) return;
      seen.add(key); result.push({ field, value: clean, label: FIELD_LABEL[field] ?? field });
    };
    add(cluster.entity_kind, cluster.entity);
    for (const [field, values] of Object.entries(cluster.observables ?? {})) for (const value of values) add(field, value);
    return result;
  }

  private exceptionComment(field: string, value: string): string {
    return `Tuning revisado pelo SOAR para ${this.evidence()?.cluster.rule_name ?? 'regra do incidente'}: ${field} = ${value}.`;
  }
}
