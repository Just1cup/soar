# Content pack: Elastic SIEM

Integração com o Elastic Security pela API do Kibana. A leitura dos alertas
usa a API do Elasticsearch; o passo a passo está no
[README principal](../../README.md#conectar-fontes-de-alertas-e-o-siem).

## Ações

| Ação | Autonomia | Idempotente | Reversível |
|---|---|---|---|
| `close_alerts` | aprovação | sim | sim, voltando o status |
| `create_exception` | aprovação | **não** | sim, removendo o item |
| `find_rule` | automática | sim | leitura |
| `isolate_host` | aprovação | sim | — **sem adapter neste deploy** |

## Credencial

`env://KIBANA_AUTH`, no formato `usuario:senha`. É um ponteiro: o banco nunca
guarda o segredo.

## Por que `create_exception` não é idempotente

Criar a mesma exceção duas vezes cria dois itens na lista. Por isso a ação
nunca é repetida automaticamente por timeout — quem repete é o operador, e com
um plano novo pela frente.

## O que este pack não faz

Contenção: `isolate_host` é apenas uma entrada indisponível do catálogo.
