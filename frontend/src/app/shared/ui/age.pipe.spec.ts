import { AgePipe } from './age.pipe';

describe('AgePipe', () => {
  const pipe = new AgePipe();
  const now = new Date('2026-09-20T18:00:00Z');

  it.each([
    ['2026-09-20T17:59:40Z', 'agora'],
    ['2026-09-20T17:45:00Z', '15 min'],
    ['2026-09-20T15:00:00Z', '3 h'],
    ['2026-09-18T18:00:00Z', '2 d'],
    ['2026-07-20T18:00:00Z', '2 meses'],
  ])('%s -> %s', (input, expected) => {
    expect(pipe.transform(input, now)).toBe(expected);
  });

  it('não inventa idade para valor ausente ou futuro', () => {
    expect(pipe.transform(null, now)).toBe('—');
    expect(pipe.transform('2026-09-21T18:00:00Z', now)).toBe('—');
  });
});
