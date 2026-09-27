import { Injectable, signal } from '@angular/core';

export type Theme = 'dark' | 'light';

const STORAGE_KEY = 'soar.theme';

/**
 * Tema da aplicação.
 *
 * O padrão é escuro e NÃO segue o `prefers-color-scheme`: um console de SOC é
 * olhado por horas, e seguir o sistema devolveria o claro para quem tem o SO
 * no claro. A escolha do operador vence e persiste.
 *
 * O acesso ao localStorage é envolvido em try/catch: numa janela anônima, com
 * dados de site bloqueados, o acessor lança — e um tema que derruba a tela é
 * pior que um tema errado.
 */
@Injectable({ providedIn: 'root' })
export class ThemeService {
  private readonly current = signal<Theme>(this.read());
  readonly theme = this.current.asReadonly();

  constructor() {
    this.apply(this.current());
  }

  toggle(): void {
    this.set(this.current() === 'dark' ? 'light' : 'dark');
  }

  set(theme: Theme): void {
    this.current.set(theme);
    this.apply(theme);
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      // Preferência de conveniência: perder não quebra nada.
    }
  }

  private read(): Theme {
    try {
      return localStorage.getItem(STORAGE_KEY) === 'light' ? 'light' : 'dark';
    } catch {
      return 'dark';
    }
  }

  private apply(theme: Theme): void {
    // O escuro é o padrão do CSS, então só o claro precisa do atributo.
    const root = document.documentElement;
    if (theme === 'light') {
      root.setAttribute('data-theme', 'light');
    } else {
      root.removeAttribute('data-theme');
    }
    // A barra do navegador acompanha: no celular ela ocupa a tela toda e uma
    // faixa clara sobre a aplicação escura fica pior que não ter cor nenhuma.
    document
      .querySelector('meta[name="theme-color"]')
      ?.setAttribute('content', theme === 'light' ? '#fbfbfd' : '#0d0f14');
  }
}
