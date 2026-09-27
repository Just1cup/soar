import { ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, input, output, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { IncidentsService } from '../../../core/api/incidents.service';
import type { CaseTask, TaskNote } from '../../../core/api/types';
import { AuthService } from '../../../core/auth/auth.service';
import { ApiError } from '../../../core/errors/api-error';

@Component({
  selector: 'soar-task-panel',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="tasks" aria-labelledby="tasks-heading">
      <div class="topline">
        <div><p class="eyebrow">Plano de tratamento</p><h2 id="tasks-heading">Tarefas do incidente</h2></div>
        <strong>{{ doneCount() }} de {{ tasks().length }} concluídas</strong>
      </div>
      <div class="progress" role="progressbar" [attr.aria-valuenow]="doneCount()" [attr.aria-valuemax]="tasks().length" aria-valuemin="0" aria-label="Tarefas concluídas"><span [style.width.%]="progress()"></span></div>
      @if (loading()) { <p class="muted" role="status">Carregando tarefas…</p> }
      @if (error()) { <p class="error" role="alert">{{ error() }} <button type="button" (click)="load()">Tentar novamente</button></p> }
      @if (!loading() && !error() && tasks().length === 0) { <p class="muted">Nenhuma tarefa para este incidente.</p> }
      @for (phase of phases(); track phase) {
        <h3>{{ phase }}</h3>
        @for (task of tasksFor(phase); track task.id) {
          <article class="task" [class.open]="selectedTaskId() === task.id">
            <button class="task-main" type="button" (click)="open(task)" [attr.aria-expanded]="selectedTaskId() === task.id">
              <span class="check" [class.done]="task.status === 'done'">{{ task.status === 'done' ? '✓' : '' }}</span>
              <span class="task-copy"><strong>{{ task.title }}</strong><small>{{ task.status === 'done' ? 'Concluída' : 'Pendente' }} · {{ task.mandatory ? 'Obrigatória' : 'Opcional' }}</small></span>
              <span class="chevron">{{ selectedTaskId() === task.id ? '−' : '+' }}</span>
            </button>
            @if (selectedTaskId() === task.id) {
              <div class="detail">
                <p>{{ task.instruction }}</p>
                @if (task.status !== 'done' && canComplete()) {
                  <button class="complete" type="button" [disabled]="busy()" (click)="complete(task)">Concluir tarefa</button>
                }
                <div class="notes-head"><h4>Notes</h4><span>{{ notes().length }} nota{{ notes().length === 1 ? '' : 's' }}</span></div>
                @if (notesLoading()) { <p class="muted">Carregando notas…</p> }
                @for (note of notes(); track note.id) {
                  <div class="note"><div><strong>{{ note.author_label }}</strong><time [attr.datetime]="note.created_at">{{ date(note.created_at) }}</time></div><p>{{ note.body }}</p></div>
                }
                @if (!notesLoading() && notes().length === 0) { <p class="muted">Ainda não há notas nesta tarefa.</p> }
                @if (canComment()) {
                  <form (submit)="sendNote($event, task)">
                    <label for="task-note">Nova nota</label>
                    <textarea id="task-note" [value]="draft()" (input)="onDraft($event)" maxlength="4000" placeholder="Registre o que foi verificado e o resultado…"></textarea>
                    <button type="submit" [disabled]="busy() || !draft().trim()">Enviar nota</button>
                  </form>
                }
                @if (actionError()) { <p class="error" role="alert">{{ actionError() }}</p> }
              </div>
            }
          </article>
        }
      }
    </section>
  `,
  styles: `
    :host{display:block}.tasks{background:var(--bg-raised);border:1px solid var(--border);border-radius:.5rem;padding:1.25rem}.topline{display:flex;justify-content:space-between;align-items:end;gap:1rem}.eyebrow{color:var(--fg-muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.07em;margin:0}.topline h2{font-size:1.15rem;margin:.25rem 0 .75rem}.topline strong{font-size:.8rem;color:var(--fg-muted);white-space:nowrap;margin-bottom:.75rem}.progress{height:.35rem;background:var(--border);border-radius:1rem;overflow:hidden}.progress span{display:block;height:100%;background:var(--focus);transition:width .2s}h3{font-size:.85rem;color:var(--fg-muted);font-weight:600;border-bottom:1px solid var(--border);padding:.9rem .25rem .45rem;margin:1rem 0 0}.task{border-bottom:1px solid var(--border-subtle)}.task-main{width:100%;display:flex;align-items:center;gap:.75rem;text-align:left;padding:.9rem .25rem;border:0;background:transparent;color:var(--fg);font:inherit;cursor:pointer}.task-main:hover{background:var(--bg-hover)}.check{width:1.1rem;height:1.1rem;border:1px solid var(--fg-muted);border-radius:.25rem;display:grid;place-items:center;flex:none;font-size:.7rem}.check.done{background:var(--focus);border-color:var(--focus);color:white}.task-copy{display:flex;flex-direction:column;gap:.2rem;flex:1}.task-copy strong{font-size:.88rem}.task-copy small,.chevron,.muted{color:var(--fg-muted);font-size:.77rem}.detail{padding:.25rem .25rem 1rem 2.1rem}.detail>p{font-size:.85rem;line-height:1.5}.complete,form button{border:1px solid var(--focus);background:var(--focus);color:white;border-radius:.3rem;padding:.45rem .7rem;font:inherit;font-size:.8rem;cursor:pointer}.notes-head{display:flex;align-items:center;justify-content:space-between;margin-top:1.25rem;border-top:1px solid var(--border);padding-top:.85rem}.notes-head h4{margin:0;font-size:.9rem}.notes-head span{font-size:.75rem;color:var(--fg-muted)}.note{padding:.75rem 0;border-bottom:1px solid var(--border-subtle)}.note div{display:flex;gap:.8rem;align-items:baseline}.note strong{font-size:.8rem}.note time{font-size:.72rem;color:var(--fg-muted)}.note p{margin:.35rem 0 0;white-space:pre-wrap;font-size:.85rem}form{display:flex;flex-direction:column;align-items:flex-start;gap:.5rem;margin-top:1rem}form label{font-size:.75rem;color:var(--fg-muted)}textarea{width:100%;min-height:5rem;box-sizing:border-box;background:var(--bg);border:1px solid var(--border);color:var(--fg);border-radius:.3rem;padding:.6rem;font:inherit;resize:vertical}.error{color:var(--sev-critical-fg);font-size:.8rem}:is(button,textarea):focus-visible{outline:2px solid var(--focus);outline-offset:2px}button:disabled{opacity:.5;cursor:default}
  `,
})
export class TaskPanel implements OnInit {
  readonly incidentId = input.required<string>();
  readonly changed = output<void>();
  private readonly api = inject(IncidentsService);
  private readonly auth = inject(AuthService);
  private readonly destroyRef = inject(DestroyRef);
  protected readonly tasks = signal<CaseTask[]>([]);
  protected readonly notes = signal<TaskNote[]>([]);
  protected readonly selectedTaskId = signal<string | null>(null);
  protected readonly draft = signal('');
  protected readonly loading = signal(true);
  protected readonly notesLoading = signal(false);
  protected readonly busy = signal(false);
  protected readonly error = signal('');
  protected readonly actionError = signal('');
  protected readonly canComplete = computed(() => this.auth.can('case.task.complete'));
  protected readonly canComment = computed(() => this.auth.can('case.comment'));
  protected readonly doneCount = computed(() => this.tasks().filter((task) => task.status === 'done').length);
  protected readonly progress = computed(() => this.tasks().length ? this.doneCount() * 100 / this.tasks().length : 0);
  protected readonly phases = computed(() => [...new Set(this.tasks().map((task) => task.phase))]);

  ngOnInit(): void { this.load(); }
  protected tasksFor(phase: string): CaseTask[] { return this.tasks().filter((task) => task.phase === phase); }
  protected load(): void {
    this.loading.set(true); this.error.set('');
    this.api.tasks(this.incidentId()).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: (tasks) => { this.tasks.set(tasks); this.loading.set(false); },
      error: (err: ApiError) => { this.error.set(err.userMessage); this.loading.set(false); },
    });
  }
  protected open(task: CaseTask): void {
    if (this.selectedTaskId() === task.id) { this.selectedTaskId.set(null); return; }
    this.selectedTaskId.set(task.id); this.notes.set([]); this.draft.set(''); this.actionError.set(''); this.notesLoading.set(true);
    this.api.taskNotes(this.incidentId(), task.id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: (notes) => { if (this.selectedTaskId() === task.id) this.notes.set(notes); this.notesLoading.set(false); },
      error: (err: ApiError) => { this.actionError.set(err.userMessage); this.notesLoading.set(false); },
    });
  }
  protected complete(task: CaseTask): void {
    this.busy.set(true); this.actionError.set('');
    this.api.completeTask(this.incidentId(), task).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: (updated) => { this.tasks.update((tasks) => tasks.map((item) => item.id === updated.id ? updated : item)); this.busy.set(false); this.changed.emit(); },
      error: (err: ApiError) => { this.actionError.set(err.userMessage); this.busy.set(false); },
    });
  }
  protected onDraft(event: Event): void { this.draft.set((event.target as HTMLTextAreaElement).value); }
  protected sendNote(event: Event, task: CaseTask): void {
    event.preventDefault(); const body = this.draft().trim(); if (!body) return;
    this.busy.set(true); this.actionError.set('');
    this.api.addTaskNote(this.incidentId(), task.id, body).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: (note) => { this.notes.update((notes) => [...notes, note]); this.draft.set(''); this.busy.set(false); this.changed.emit(); },
      error: (err: ApiError) => { this.actionError.set(err.userMessage); this.busy.set(false); },
    });
  }
  protected date(value: string): string { return new Intl.DateTimeFormat('pt-BR', { dateStyle: 'short', timeStyle: 'short' }).format(new Date(value)); }
}
