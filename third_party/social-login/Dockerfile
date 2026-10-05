# X's Castle throttles headless bundled/Debian Chromium ("temporarily limited").
# The working old smore sidecar uses real Google Chrome, headful under Xvfb, and
# Mesa llvmpipe so WebGL reports a consistent software GPU instead of SwiftShader.
FROM node:22-bookworm-slim

ENV NODE_ENV=production \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    CAP_PROFILE_BASE=/profiles \
    CAP_HEADLESS=false \
    CAP_BROWSER_CHANNEL=chrome \
    CAP_WEBGL_SPOOF=false \
    CAP_EXTRA_CHROME_ARGS="--use-gl=angle,--use-angle=gl,--ignore-gpu-blocklist" \
    LIBGL_ALWAYS_SOFTWARE=1 \
    GALLIUM_DRIVER=llvmpipe \
    MESA_LOADER_DRIVER_OVERRIDE=llvmpipe \
    DISPLAY=:99 \
    SOCIAL_LOGIN_PROFILE_RETENTION_DAYS=90 \
    SOCIAL_LOGIN_MAX_PROFILE_BYTES=1073741824 \
    SOCIAL_LOGIN_MAX_VOLUME_BYTES=8589934592 \
    SOCIAL_LOGIN_MAX_PROFILES=1000

WORKDIR /app
COPY package*.json ./
# CapSolver browser extension auto-solves Reddit/LinkedIn Enterprise reCAPTCHA
# inside headed Chrome. Same commercial key as RECAPTCHA_SOLVER_API_KEY.
ARG CAPSOLVER_EXTENSION_TAG=v.1.17.0
ARG CAPSOLVER_EXTENSION_ZIP=CapSolver.Browser.Extension-chrome-v1.17.0.zip
RUN npm install --omit=dev --ignore-scripts \
 && apt-get update \
 && apt-get install -y --no-install-recommends xvfb x11-utils procps libgl1-mesa-dri curl unzip ca-certificates libpcre2-8-0 \
 && npx playwright install --with-deps chrome \
 && curl -fsSL -o /tmp/capsolver-ext.zip \
      "https://github.com/capsolver/capsolver-browser-extension/releases/download/${CAPSOLVER_EXTENSION_TAG}/${CAPSOLVER_EXTENSION_ZIP}" \
 && mkdir -p /opt/capsolver-extension \
 && unzip -q /tmp/capsolver-ext.zip -d /tmp/capsolver-ext \
 && if [ -f /tmp/capsolver-ext/manifest.json ]; then \
      cp -a /tmp/capsolver-ext/. /opt/capsolver-extension/; \
    else \
      inner=$(find /tmp/capsolver-ext -mindepth 1 -maxdepth 1 -type d | head -1); \
      cp -a "$inner"/. /opt/capsolver-extension/; \
    fi \
 && test -f /opt/capsolver-extension/manifest.json \
 && chown -R node:node /opt/capsolver-extension \
 && rm -rf /tmp/capsolver-ext /tmp/capsolver-ext.zip \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx \
 && rm -rf /var/lib/apt/lists/* /root/.npm

COPY --chown=node:node src ./src
COPY --chown=node:node inject-capsolver-key.mjs docker-entrypoint.sh ./
RUN chmod 755 /app/docker-entrypoint.sh \
 && mkdir -p /profiles /tmp/.X11-unix \
 && chmod 1777 /tmp/.X11-unix \
 && chown node:node /profiles

ENV CAPSOLVER_EXTENSION_DIR=/opt/capsolver-extension

USER node
EXPOSE 8090
VOLUME ["/profiles"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8090/v1/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["node", "src/server.js"]
