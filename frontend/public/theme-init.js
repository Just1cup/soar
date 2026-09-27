// Roda antes da primeira pintura: sem isto, quem escolheu o tema claro vê um
// lampejo escuro enquanto o Angular inicializa. O escuro é o padrão do CSS,
// então só o claro precisa do atributo.
//
// Arquivo separado, e não script inline, porque a CSP declara `script-src
// 'self'`: inline seria recusado. Um hash na CSP também resolveria, mas teria
// de ser recalculado a cada build — e falharia em silêncio quando esquecido.
try {
  if (localStorage.getItem('soar.theme') === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
    document.querySelector('meta[name=theme-color]').content = '#fbfbfd';
  }
} catch (_) { /* janela anônima: o padrão escuro serve */ }
