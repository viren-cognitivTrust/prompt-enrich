FROM node:20-alpine AS builder

WORKDIR /app

COPY frontend/package*.json ./
RUN npm ci

COPY frontend ./
RUN npm run build


FROM nginx:1.27-alpine

RUN addgroup -S app && adduser -S app -G app

COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY --from=builder /app/dist /usr/share/nginx/html

RUN chown -R app:app /var/cache/nginx /var/run /var/log/nginx /usr/share/nginx/html

USER app

EXPOSE 8080 8443


