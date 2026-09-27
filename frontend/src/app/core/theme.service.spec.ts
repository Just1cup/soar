import { TestBed } from '@angular/core/testing';
import { ThemeService } from './theme.service';

describe('ThemeService', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute('data-theme');
    TestBed.resetTestingModule();
  });

  it('nasce escuro, sem depender do prefers-color-scheme do sistema', () => {
    const svc = TestBed.inject(ThemeService);
    expect(svc.theme()).toBe('dark');
    // O escuro é o padrão do CSS: só o claro precisa marcar o atributo.
    expect(document.documentElement.hasAttribute('data-theme')).toBe(false);
  });

  it('alterna e persiste a escolha do operador', () => {
    const svc = TestBed.inject(ThemeService);
    svc.toggle();
    expect(svc.theme()).toBe('light');
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    expect(localStorage.getItem('soar.theme')).toBe('light');

    svc.toggle();
    expect(svc.theme()).toBe('dark');
    expect(document.documentElement.hasAttribute('data-theme')).toBe(false);
  });

  it('restaura a escolha anterior na inicialização', () => {
    localStorage.setItem('soar.theme', 'light');
    const svc = TestBed.inject(ThemeService);
    expect(svc.theme()).toBe('light');
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
  });

  it('sobrevive a um localStorage que lança', () => {
    // Janela anônima, dados de site bloqueados, captura de miniatura: o
    // acessor lança. Um tema que derruba a tela é pior que um tema errado.
    const getItem = Storage.prototype.getItem;
    const setItem = Storage.prototype.setItem;
    Storage.prototype.getItem = () => { throw new Error('bloqueado'); };
    Storage.prototype.setItem = () => { throw new Error('bloqueado'); };
    try {
      const svc = TestBed.inject(ThemeService);
      expect(svc.theme()).toBe('dark');
      expect(() => svc.toggle()).not.toThrow();
      expect(svc.theme()).toBe('light');
    } finally {
      Storage.prototype.getItem = getItem;
      Storage.prototype.setItem = setItem;
    }
  });

  it('mantém a cor da barra do navegador em sincronia', () => {
    const meta = document.createElement('meta');
    meta.name = 'theme-color';
    meta.content = '#000000';
    document.head.appendChild(meta);
    try {
      const svc = TestBed.inject(ThemeService);
      expect(meta.content).toBe('#0d0f14');
      svc.toggle();
      expect(meta.content).toBe('#fbfbfd');
    } finally {
      meta.remove();
    }
  });
});
