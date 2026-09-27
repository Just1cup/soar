import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { ThemeService } from './core/theme.service';

@Component({
  selector: 'app-root',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  template: `
    <a class="skip" href="#main">Pular para o conteúdo</a>
    <nav class="nav">
      <span class="brand" aria-label="SOAR">
        <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true" fill="none">
          <path d="M12 2.5 4.5 5.5v6c0 4.6 3.1 8.8 7.5 10 4.4-1.2 7.5-5.4 7.5-10v-6L12 2.5Z"
                stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>
          <path d="M8.5 12.2h2l1.3-2.6 1.4 4 1.1-1.8h1.8" stroke="currentColor"
                stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        SOAR
      </span>
      <a routerLink="/queue" routerLinkActive="active">Fila</a>
      <a routerLink="/approvals" routerLinkActive="active">Aprovações</a>

      <button
        type="button"
        class="theme"
        (click)="theme.toggle()"
        [attr.aria-label]="toggleLabel()"
        [title]="toggleLabel()">
        @if (theme.theme() === 'dark') {
          <!-- Sol: clicar vai para o claro. O ícone mostra o DESTINO, que é o
               que o usuário está prestes a obter, não o estado atual. -->
          <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"
               fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round">
            <circle cx="12" cy="12" r="4"/>
            <path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M18.4 5.6 17 7M7 17l-1.4 1.4"/>
          </svg>
        } @else {
          <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"
               fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round">
            <path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5Z"/>
          </svg>
        }
      </button>
    </nav>
    <main id="main"><router-outlet /></main>
  `,
  styles: `
    .nav {
      display: flex; align-items: center; gap: 1.25rem;
      padding: .625rem 1rem; border-bottom: 1px solid var(--border);
      background: var(--bg-raised);
    }
    .brand {
      display: inline-flex; align-items: center; gap: .4rem;
      font-weight: 650; letter-spacing: .02em; color: var(--fg);
    }
    .nav a {
      color: var(--fg-muted); text-decoration: none; font-size: .875rem;
      padding: .25rem .5rem; border-radius: .25rem;
    }
    .nav a:hover { color: var(--fg); background: var(--bg-hover); }
    .nav a.active { color: var(--fg); font-weight: 600; }
    .nav a:focus-visible { outline: 2px solid var(--focus); outline-offset: 1px; }
    .theme {
      margin-left: auto; display: inline-flex; align-items: center; justify-content: center;
      width: 2rem; height: 2rem; padding: 0; cursor: pointer;
      background: transparent; color: var(--fg-muted);
      border: 1px solid var(--border); border-radius: .375rem;
    }
    .theme:hover { color: var(--fg); background: var(--bg-hover); }
    @media (prefers-reduced-motion: no-preference) {
      .theme { transition: color .12s ease, background-color .12s ease; }
    }
    .skip {
      position: absolute; left: -9999px;
    }
    .skip:focus {
      left: .5rem; top: .5rem; z-index: 10; padding: .5rem .75rem;
      background: var(--bg-raised); border: 1px solid var(--focus); border-radius: .25rem;
    }
  `,
})
export class App {
  protected readonly theme = inject(ThemeService);

  protected readonly toggleLabel = computed(() =>
    this.theme.theme() === 'dark' ? 'Mudar para o tema claro' : 'Mudar para o tema escuro',
  );
}
