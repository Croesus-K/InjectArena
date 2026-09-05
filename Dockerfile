# 攻心 InjectArena —— 生产镜像
# 构建即验证：CI 每次推送都会 docker build（见 .github/workflows/ci.yml）
FROM node:24-alpine
ENV NODE_ENV=production
WORKDIR /app

# 依赖层独立成层：源码变更不触发重装
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# 运行所需：服务端、前端三件套、关卡与语料（schema 校验在启动时执行）
COPY src/ src/
COPY public/ public/
COPY levels/ levels/
COPY corpus/ corpus/

# 运行时数据（SQLite 审计与两榜）落独立卷；key 走环境变量，绝不进镜像
RUN mkdir -p /data && chown node:node /data
ENV INJECTARENA_HOST=0.0.0.0 \
    INJECTARENA_PORT=8787 \
    INJECTARENA_DB_PATH=/data/audit.db
VOLUME /data

USER node
EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8787/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "src/server.js"]
