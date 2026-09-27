import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';
import { ApiError } from '../../core/errors/api-error';

@Component({
  selector: 'soar-login-page',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="card" aria-labelledby="login-title">
      <p class="eyebrow">SOAR · acesso local</p>
      <h1 id="login-title">Entrar</h1>
      <p class="help">Use a conta provisionada pelo administrador da plataforma.</p>
      <form (submit)="submit($event, email.value, password.value)">
        <label>E-mail<input #email type="email" autocomplete="username" required /></label>
        <label>Senha<input #password type="password" autocomplete="current-password" required /></label>
        @if (error()) { <p class="error" role="alert">{{ error() }}</p> }
        <button type="submit" [disabled]="busy()">{{ busy() ? 'Entrando…' : 'Entrar' }}</button>
      </form>
    </section>
  `,
  styles: `
    :host { display:grid; min-height:calc(100vh - 3rem); place-items:center; padding:1rem; }
    .card { width:min(25rem,100%); border:1px solid var(--border); border-radius:.75rem;
            background:var(--bg-raised); padding:1.5rem; box-shadow:0 .75rem 2.5rem rgb(0 0 0 / .08); }
    .eyebrow { color:var(--fg-muted); font-size:.75rem; letter-spacing:.08em; text-transform:uppercase; }
    h1 { margin:.25rem 0; font-size:1.5rem; }
    .help { color:var(--fg-muted); font-size:.875rem; margin:0 0 1.25rem; }
    form,label { display:flex; flex-direction:column; }
    form { gap:1rem; } label { gap:.35rem; font-size:.8125rem; color:var(--fg-muted); }
    input,button { font:inherit; color:var(--fg); background:var(--bg); border:1px solid var(--border);
                   border-radius:.375rem; padding:.625rem .75rem; }
    button { background:var(--focus); color:white; border-color:var(--focus); cursor:pointer; font-weight:600; }
    button:disabled { opacity:.55; } .error { color:var(--sev-critical-fg); margin:0; font-size:.8125rem; }
    :is(input,button):focus-visible { outline:2px solid var(--focus); outline-offset:2px; }
  `,
})
export class LoginPage {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  protected readonly busy = signal(false);
  protected readonly error = signal('');

  protected submit(event: Event, email: string, password: string): void {
    event.preventDefault();
    this.busy.set(true); this.error.set('');
    this.auth.login(email.trim(), password).subscribe({
      next: () => void this.router.navigateByUrl('/queue'),
      error: (err: ApiError) => { this.busy.set(false); this.error.set(err.userMessage); },
    });
  }
}
