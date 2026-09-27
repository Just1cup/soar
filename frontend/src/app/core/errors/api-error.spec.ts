import { ApiError } from './api-error';

describe('ApiError', () => {
  it('nunca mostra o detalhe de um erro 500 ao analista, mas dá o request_id', () => {
    const err = new ApiError('server', 'INTERNAL_ERROR', 'pq: relation does not exist', 500, 'abc12345-dead-beef');
    expect(err.userMessage).not.toContain('pq:');
    expect(err.userMessage).toContain('abc12345');
    expect(err.retryable).toBe(true);
  });

  it('distingue o que o usuário pode resolver do que não pode', () => {
    expect(new ApiError('authorization', 'FORBIDDEN', 'x', 403, null).retryable).toBe(false);
    expect(new ApiError('conflict', 'VERSION_CONFLICT', 'x', 409, null).retryable).toBe(false);
    expect(new ApiError('network', 'TRANSPORT', 'x', 0, null).retryable).toBe(true);
  });

  it('num erro de rede diz explicitamente que nada foi aplicado', () => {
    // Importa num SOAR: depois de clicar em "fechar 429 alertas", a diferença
    // entre "falhou" e "não sei se aplicou" é a diferença entre tentar de novo
    // com segurança e duplicar uma ação em produção.
    expect(new ApiError('network', 'TRANSPORT', 'x', 0, null).userMessage).toContain('não foram aplicadas');
  });
});
