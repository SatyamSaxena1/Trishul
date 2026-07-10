FROM node:22.17-alpine@sha256:5539840ce9d013fa13e3b9814c9353024be7ac75aca5db6d039504a56c04ea59 AS build
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM nginx:1.28-alpine@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236
RUN rm -f /etc/nginx/conf.d/default.conf \
    && mkdir -p /var/cache/nginx /var/run/nginx \
    && chown -R 101:101 /var/cache/nginx /var/run/nginx
COPY deploy/edge/nginx.conf /etc/nginx/nginx.conf.template
COPY deploy/edge/entrypoint.sh /usr/local/bin/trishul-edge
RUN chmod 0555 /usr/local/bin/trishul-edge
COPY --from=build /src/dist /usr/share/nginx/html
USER 101:101
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -q --no-check-certificate -O /dev/null https://127.0.0.1:8443/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/trishul-edge"]
