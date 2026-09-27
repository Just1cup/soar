import { TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { IncidentsService } from '../../../core/api/incidents.service';
import type { CaseTask, TaskNote } from '../../../core/api/types';
import { AuthService } from '../../../core/auth/auth.service';
import { TaskPanel } from './task-panel';

const task: CaseTask = {
  id: '00000000-0000-7000-8000-000000000031', phase: 'Detecção e análise',
  title: 'Verificar processo', instruction: 'Revise a cadeia de execução.',
  position: 20, mandatory: true, status: 'pending', completed_at: null, version: 1,
};

class StubIncidents {
  notes: TaskNote[] = [];
  tasks() { return of([task]); }
  taskNotes() { return of(this.notes); }
  completeTask() { return of({ ...task, status: 'done' as const, version: 2 }); }
  addTaskNote(_id: string, taskId: string, body: string) {
    const note: TaskNote = { id: crypto.randomUUID(), task_id: taskId, body, author_label: 'Analista', created_at: '2026-09-27T10:00:00Z' };
    this.notes.push(note);
    return of(note);
  }
}

describe('TaskPanel', () => {
  it('abre uma tarefa, publica nota e conclui com progresso atualizado', async () => {
    const api = new StubIncidents();
    TestBed.configureTestingModule({
      imports: [TaskPanel],
      providers: [
        { provide: IncidentsService, useValue: api },
        { provide: AuthService, useValue: { can: () => true } },
      ],
    });
    const fixture = TestBed.createComponent(TaskPanel);
    fixture.componentRef.setInput('incidentId', '00000000-0000-7000-8000-000000000010');
    fixture.detectChanges();
    const root = fixture.nativeElement as HTMLElement;
    (root.querySelector('.task-main') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(root.textContent).toContain('Revise a cadeia de execução.');
    const textarea = root.querySelector('textarea') as HTMLTextAreaElement;
    textarea.value = 'Hash conferido no SIEM';
    textarea.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    (root.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'));
    fixture.detectChanges();
    expect(root.textContent).toContain('Hash conferido no SIEM');
    (root.querySelector('.complete') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(root.textContent).toContain('1 de 1 concluídas');
  });
});
