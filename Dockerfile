# All dependencies are plain JavaScript, so the build stage runs on the build
# machine's own platform and its output is reused for every target platform.
FROM --platform=$BUILDPLATFORM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production DATABASE_PATH=/data/device-auth.db PORT=3080
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
RUN mkdir -p /data && chown 1000:1000 /data
# Numeric so Kubernetes can verify runAsNonRoot (1000 is the image's "node" user).
USER 1000:1000
VOLUME /data
EXPOSE 3080
HEALTHCHECK CMD wget -qO- http://127.0.0.1:3080/healthz || exit 1
CMD ["node", "--disable-warning=ExperimentalWarning", "dist/index.js"]
