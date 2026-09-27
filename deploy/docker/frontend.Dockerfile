# syntax=docker/dockerfile:1.7
# Orçamento: <= 30 MB (docs/soar/03 §14.1).
# Base alpine-slim, não a variante "unprivileged": aquela traz 41 MB de build
# próprio para fazer o que a configuração abaixo faz em dez linhas.

FROM node:24-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY . .
RUN npx ng build --configuration production

FROM nginx:1.29-alpine-slim
COPY --from=build /src/dist/frontend/browser /usr/share/nginx/html
COPY deploy/nginx.conf /etc/nginx/nginx.conf
# O entrypoint oficial roda envsubst nos templates e escreve em conf.d, que
# por isso precisa ser gravável (tmpfs/emptyDir com rootfs read-only).
COPY deploy/default.conf.template /etc/nginx/templates/default.conf.template
COPY deploy/security-headers.conf /etc/nginx/security-headers.conf
# Os diretórios que o nginx precisa escrever, já com dono, para o rootfs poder
# ser montado read-only com tmpfs por cima.
ENV NGINX_RESOLVER=127.0.0.11 API_UPSTREAM=http://api:8080
RUN mkdir -p /tmp/client_body /var/cache/nginx /etc/nginx/conf.d \
 && chown -R 101:101 /tmp /var/cache/nginx /etc/nginx/conf.d /usr/share/nginx/html
USER 101:101
EXPOSE 8080
