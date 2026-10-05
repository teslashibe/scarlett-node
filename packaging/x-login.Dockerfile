# Browser authentication companion, never published on a host port by default.
FROM node:22.23.3-bookworm-slim
ENV NODE_ENV=production CAP_PROFILE_BASE=/profiles CAP_HEADLESS=false \
    CAP_BROWSER_EXECUTABLE_PATH=/opt/google/chrome/chrome CAP_WEBGL_SPOOF=false \
    CAP_EXTRA_CHROME_ARGS="--use-gl=angle,--use-angle=gl,--ignore-gpu-blocklist" \
    LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=llvmpipe MESA_LOADER_DRIVER_OVERRIDE=llvmpipe \
    DISPLAY=:99 HOST=0.0.0.0 PORT=8090 SOCIAL_LOGIN_MAX_CONCURRENCY=1 \
    SOCIAL_LOGIN_PROFILE_RETENTION_DAYS=90 SOCIAL_LOGIN_MAX_VOLUME_BYTES=8589934592
WORKDIR /app
COPY third_party/social-login ./third_party/social-login
COPY scripts/verify-social-login.mjs ./scripts/verify-social-login.mjs
RUN node scripts/verify-social-login.mjs \
 && cd third_party/social-login \
 && npm ci --omit=dev --omit=optional --ignore-scripts \
 && apt-get update \
 && apt-get install -y --no-install-recommends xvfb x11-utils procps libgl1-mesa-dri ca-certificates \
 && ./node_modules/.bin/playwright install --with-deps chrome \
 && rm -rf /var/lib/apt/lists/* /root/.npm \
 && mkdir -p /profiles /tmp/.X11-unix \
 && chmod 1777 /tmp/.X11-unix && chown node:node /profiles
RUN apt-get update && apt-get install -y --no-install-recommends gosu && rm -rf /var/lib/apt/lists/*
COPY packaging/x-login-entrypoint.sh /app/x-login-entrypoint.sh
VOLUME ["/profiles"]
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 CMD node -e "fetch('http://127.0.0.1:8090/v1/ready').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
ENTRYPOINT ["/bin/sh", "/app/x-login-entrypoint.sh"]
