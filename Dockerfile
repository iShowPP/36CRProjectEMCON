# Runs the EMCON server anywhere that runs containers (Fly.io, Railway, a VPS, ...).
#   docker build -t emcon .
#   docker run -p 8787:8787 -e EMCON_SECRET=<long random string> -e EMCON_PUBLIC_URL=https://your.host emcon
# Mount a volume at /app/data to keep demo data (accounts, reports, photos) across restarts.
FROM node:22-alpine
WORKDIR /app
COPY package.json ./
COPY server ./server
COPY extension/lib ./extension/lib
COPY web ./web
RUN mkdir -p /app/data && chown node:node /app/data
ENV PORT=8787
EXPOSE 8787
USER node
CMD ["node", "server/index.js"]
