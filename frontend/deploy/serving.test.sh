#!/usr/bin/env bash
# Contrato de entrega do SPA. Nasceu de um bug real: a CSP declarava
# `base-uri 'none'`, o navegador descartava o `<base href="/">` do index e os
# assets relativos passavam a resolver contra a rota aberta. Em /incidents/<id>
# o bundle era pedido como /incidents/main-*.js, o try_files devolvia o index
# com 200 text/html, o navegador recusava o módulo por MIME type e a aplicação
# não inicializava — tela parada, nenhum pedido à API, nenhum erro na rede.
#
# Uso: ./serving.test.sh [base-url]   (padrão http://127.0.0.1:8088)
set -uo pipefail

BASE="${1:-http://127.0.0.1:8088}"
fails=0

check() {
  local nome="$1" esperado="$2" obtido="$3"
  if [[ "$obtido" == "$esperado" ]]; then
    printf '  ok   %s\n' "$nome"
  else
    printf '  FALHA %s\n       esperado: %s\n       obtido:   %s\n' "$nome" "$esperado" "$obtido"
    fails=$((fails + 1))
  fi
}

ROTA="/incidents/01a0c1cd-1524-7aa9-a49e-daa5cf24d2e0"

# 1. A CSP não pode neutralizar o <base> do próprio documento.
csp=$(curl -fsSI "$BASE$ROTA" | tr -d '\r' | grep -i '^content-security-policy:' || true)
if [[ "$csp" == *"base-uri 'none'"* ]]; then
  base_uri="none (descarta o <base> do index)"
elif [[ "$csp" == *"base-uri 'self'"* ]]; then
  base_uri="self"
else
  base_uri="ausente"
fi
check "CSP permite o <base> da própria origem" "self" "$base_uri"

# 2. O documento precisa declarar o <base>, senão nada disso importa.
check "index declara <base href=\"/\">" 'presente' \
  "$(curl -fsS "$BASE$ROTA" | grep -qF '<base href="/">' && echo presente || echo ausente)"

# 3. Asset inexistente é 404, nunca o index disfarçado de script.
resp=$(curl -sS -o /dev/null -w '%{http_code} %{content_type}' "$BASE$ROTA/main-FY6SZGVT.js")
check "asset inexistente sob rota profunda devolve 404" "404" "${resp%% *}"

# 4. O bundle de verdade continua sendo servido como JavaScript.
# O padrão exige o hash: senão casa com theme-init.js, que é outro arquivo.
bundle=$(curl -fsS "$BASE/" | grep -oE 'src="[^"]*-[0-9A-Za-z]{8,}\.js"' | sed 's/src="//;s/"//' | head -1)
[[ -n "$bundle" ]] || { echo "  FALHA não achei o bundle no index"; fails=$((fails + 1)); }
if [[ -n "$bundle" ]]; then
  ct=$(curl -sS -o /dev/null -w '%{http_code} %{content_type}' "$BASE/$bundle")
  check "bundle servido como JavaScript" "200" "${ct%% *}"
  case "${ct#* }" in
    *javascript*) printf '  ok   bundle tem MIME de módulo (%s)\n' "${ct#* }" ;;
    *) printf '  FALHA bundle com MIME %s\n' "${ct#* }"; fails=$((fails + 1)) ;;
  esac

  # Artefato com hash no nome tem de sair com cache imutável.
  check "bundle com hash tem cache imutável" "sim" \
    "$(curl -fsSI "$BASE/$bundle" | grep -qi 'cache-control:.*immutable' && echo sim || echo nao)"

  # O esbuild usa base64 URL-safe nos hashes. Isso inclui '-' e '_', inclusive
  # na última posição (`chunk-D4S01PW-.js`). Testar apenas main-*.js deixaria
  # uma regressão de cache nos lazy chunks passar em silêncio.
  lazy=$(curl -fsS "$BASE/$bundle" | grep -oE 'chunk-[0-9A-Za-z_-]{8,}\.js' | sort -u | grep -E 'chunk-[0-9A-Za-z_]*[-_][0-9A-Za-z_-]*\.js' | head -1 || true)
  if [[ -n "$lazy" ]]; then
    check "lazy chunk com hash URL-safe tem cache imutável" "sim" \
      "$(curl -fsSI "$BASE/$lazy" | grep -qi 'cache-control:.*immutable' && echo sim || echo nao)"
  else
    echo "  FALHA não achei lazy chunk com '-' ou '_' no hash"
    fails=$((fails + 1))
  fi
fi

# 5. O bootstrap de tema tem de ser carregável: inline seria recusado pela CSP.
check "theme-init.js servido como JavaScript" "200" \
  "$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/theme-init.js")"

# 6. Nenhum handler inline no index: a CSP declara `script-src 'self'` e os
# recusa. O inlinador de CSS crítico do Angular emitia
# `<link media="print" onload="this.media='all'">`, e com o onload recusado a
# folha de estilo ficava em media=print — carregada e nunca aplicada.
check "index sem handler de evento inline" 'nenhum' \
  "$(curl -fsS "$BASE$ROTA" | grep -qiE '<[^>]+ on[a-z]+=' && echo presente || echo nenhum)"

# 7. E a folha de estilo tem de valer para a tela, não só para impressão.
check "folha de estilo não fica em media=print" 'ok' \
  "$(curl -fsS "$BASE$ROTA" | grep -oE '<link[^>]*rel="stylesheet"[^>]*>' | grep -q 'media="print"' && echo 'presa em media=print' || echo ok)"

# 8. Rota desconhecida ainda cai no index — o router é quem decide.
check "rota desconhecida devolve o index" "200" \
  "$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/rota/que/nao/existe")"

echo
if (( fails )); then echo "$fails verificação(ões) falharam"; exit 1; fi
echo "entrega ok"
