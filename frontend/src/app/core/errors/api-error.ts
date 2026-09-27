/**
 * O erro que o resto da aplicação enxerga.
 *
 * O componente nunca vê um HttpErrorResponse: ele vê um `kind` classificado e
 * um `code` estável vindo do backend. Isso é o que permite a UI ramificar sem
 * nunca ler prosa — renomear uma mensagem no servidor não pode mudar o
 * comportamento da tela (docs/soar/06 §4).
 */
export type ApiErrorKind =
  | 'validation'
  | 'authentication'
  | 'authorization'
  | 'not_found'
  | 'conflict'
  | 'rate_limited'
  | 'network'
  | 'timeout'
  | 'server';

export class ApiError extends Error {
  constructor(
    readonly kind: ApiErrorKind,
    readonly code: string,
    message: string,
    readonly status: number,
    readonly requestId: string | null,
  ) {
    super(message);
    this.name = 'ApiError';
  }

  /** Erro que some sozinho se o usuário tentar de novo. */
  get retryable(): boolean {
    return this.kind === 'network' || this.kind === 'timeout' || this.status >= 500;
  }

  /**
   * Texto para o analista. Nunca "Error 500": um operador de SOC precisa saber
   * se o problema é dele ou do sistema — e o request_id é o que torna o
   * segundo caso investigável.
   */
  get userMessage(): string {
    switch (this.kind) {
      case 'network':
        return 'Sem conexão com a plataforma. As ações não foram aplicadas.';
      case 'timeout':
        return 'A plataforma demorou a responder. Nada foi alterado.';
      case 'authentication':
        return 'Sessão expirada. Entre novamente.';
      case 'authorization':
        return 'Você não tem permissão para esta operação.';
      case 'conflict':
        return 'O registro mudou desde que você o abriu. Recarregue e revise.';
      case 'server':
        return `Erro interno da plataforma${this.requestId ? ` (ref. ${this.requestId.slice(0, 8)})` : ''}.`;
      default:
        return this.message;
    }
  }
}
