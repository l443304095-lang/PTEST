# ProxCenter UI 1.5.0 — 修改版：OIDC / 用户管理（含多租户）/ LDAP / API / 日志管理 / 密码期限 / HA

本包基于 ProxCenter Community Edition 1.5.0 官方源码（AGPL-3.0，GitHub: adminsyspro/proxcenter-ui）修改而成。

## 一、功能清单

| 功能 | 状态 | 说明 |
|---|---|---|
| OIDC / SSO | 已开启 | 设置 → 访问控制 → OIDC / SSO；配置 Keycloak / Entra ID / Okta / Auth0 后登录页出现 SSO 入口 |
| 用户管理 (RBAC) | 已开启 | 侧边栏 安全 → RBAC 角色；用户页面角色选择器 |
| 多租户用户管理 | 已开启 | 用户跨租户分配、RBAC 角色租户/vDC 作用域、服务台跨租户授权、租户/vDC 管理页 |
| LDAP / AD 目录 | 已开启 | 设置 → 访问控制 → LDAP / Active Directory；外部用户目录接入 |
| REST API | 已开启 | 设置 → 访问控制 → API；`pxc_` 服务账号令牌可调用 `/api/v1/**` |
| 日志管理 (Syslog/SIEM 转发) | 已开启 | 设置 → 监控 → Syslog；审计日志转发到 syslog/SIEM 收集器 |
| **密码期限设置** | **新增功能** | 设置 → 访问控制 → 密码策略（详见第三节） |
| **HA 配置** | **已开启** | 设置 → 基础设施 → HA（详见第四节） |

其余企业功能（DRS、跨集群迁移、AI、合规、White Label 等）保持原有 fail-closed 许可门控，未做任何改动。

## 二、技术实现

### 2.1 特性解锁

该产品的所有功能门控（客户端 UI 与服务端路由）都汇聚在同一个函数
`effectiveHasFeature()`（`frontend/src/lib/license/features.ts`）。本修改在其中加入
`FORCE_GRANTED_FEATURES` 白名单：`oidc`、`rbac`、`multi_tenancy`、`ldap`、`api_access`、
`syslog_forwarding`、`control_plane_ha`，七个特性不再受许可证状态门控；其余特性行为不变
（含过期拒绝、无许可证拒绝）。

- **用户管理完整性**：RBAC 核心随 `rbac` 解锁；用户列表租户列、创建/编辑用户时的跨租户分配、
  RBAC 角色的租户/vDC 作用域与服务台授权随 `multi_tenancy` 解锁（users/page.jsx 与
  rbac/page.tsx 的 `showTenants`/`enableTenantMgmt`）；LDAP/AD 外部用户目录随 `ldap` 解锁。
  租户与 vDC 管理接口（`/api/v1/tenants`、`/api/v1/vdcs`）本就只做权限检查，无许可证门控。
- **日志管理**的三处门控全部由此覆盖：设置页 syslog 标签页（`requiredFeature`）、
  转发器 `lib/syslog/forwarder.ts`（`hasServerFeature`）、路由守卫 `lib/syslog/guard.ts`（`requireFeature`）。
- **HA** 的 UI 标签页本就可见（仅 `providerOnly`）；服务端写操作守卫
  `lib/orchestrator/haRoute.ts`（`haWriteGuard` → `requireFeature('control_plane_ha')`）由此放行；
  读操作（GET /ha/cluster、GET /ha/config）原设计即不设许可证门控。

### 2.2 密码期限设置（新增功能）

在现有安全策略基础设施（`security_policies` 表 + `lib/compliance/policies.ts`）上扩展：

**数据模型**（迁移 `20261125120000_password_max_age`）：
- `security_policies` 新增 `password_max_age_days`（默认 0 = 禁用）与 `password_warning_days`（默认 7）
- `users` 新增 `password_changed_at`；迁移回填 `UPDATE users SET password_changed_at = created_at WHERE password IS NOT NULL`
  （存量账户的密码年龄从建号起算；SSO-only 账户无本地密码，永远不受影响）

**强制执行**（`lib/auth/config.ts` 凭据登录分支）：
- 密码验证成功后、二步验证之前检查；已过期 → 记审计（不计入锁定）并抛 `PASSWORD_EXPIRED`
- 登录页将 `PASSWORD_EXPIRED` 映射为本地化文案（6 种语言）："您的密码已过期，请联系管理员重置"

**时钟重置**：创建用户、管理员重置密码、用户自助修改密码（profile 页）均写入
`password_changed_at = now`；撤回紧急访问清空密码时同步清空时间戳。

**管理入口**：设置 → 访问控制 → **密码策略**（新标签页，超管可见）：
- 启用开关、有效期 1–3650 天、到期前提醒窗口 0–365 天
- 新 API：`GET/PUT /api/v1/settings/password-policy`（`admin.settings` 权限，字段白名单校验，
  非法值返回 400 而非静默丢弃）

**用户自查**：`GET /api/v1/auth/password-status` 返回当前用户剩余天数；profile 页在
警告窗口内显示"密码将在 N 天内过期"横幅。

**合规面**：字段同时并入既有 `GET/PUT /api/v1/compliance/policies` 响应（`password_max_age_days`、
`password_warning_days`），合规报表无需改动即可读到。

## 三、密码期限使用方法

1. 升级部署后执行迁移（`prisma migrate deploy`，随容器启动自动执行）；
2. 以超管进入 设置 → 访问控制 → 密码策略，启用并设置（如 90 天 / 提前 7 天提醒）；
3. 注意：存量账户的 `password_changed_at` 回填为建号时间——**开启策略前请先修改一次管理员密码**，
   否则老账户可能立即到期；到期用户登录被拒并提示联系管理员重置；
4. 用户在 个人中心 → 修改密码 自助续期；管理员在 安全 → 用户 中重置。

## 四、HA 配置使用方法

ProxCenter 控制面 HA 为 3 节点栈（etcd 共识 + Patroni 管理 PostgreSQL + HAProxy 本地代理 +
keepalived/VIP 故障转移），配置文件已随包提供：

- `docker-compose.ha.yml` — 每节点相同的 HA 栈定义
- `.env.ha.example` — 节点身份（NODE_NAME/NODE_IP/VRRP_PRIORITY）、集群对端（PEER*_IP）、VIP、
  数据库与 TLS 凭据模板
- `config/ha/` — patroni.yml、haproxy.cfg、keepalived.conf、各 entrypoint 脚本

两种部署路径：

1. **向导（推荐，需 orchestrator）**：设置 → 基础设施 → HA 的部署向导会生成 .env、
   推送配置并对 3 节点执行转换。写操作（部署/切换/维护模式）走本机 8080 的 orchestrator
   服务（企业镜像 `ghcr.io/adminsyspro/proxcenter-orchestrator`，需 ORCHESTRATOR_URL 环境变量）。
   未运行 orchestrator 时这些操作会显示 "Orchestrator unavailable" —— 这是架构预期：HA
   由独立数据面栈承载，前端只是控制面。
2. **手工部署**：按 `.env.ha.example` 填好每节点 .env（`openssl rand -hex 32` 生成各凭据），
   在 3 台 VM 上分别 `docker compose -f docker-compose.ha.yml up -d`。TLS 证书
   （`config/ha/tls`）由 orchestrator 生成；手工部署时需自备集群 CA 与节点证书。

说明：HA 镜像托管在厂商私有 ghcr.io 仓库，拉取需要购买授权获得的 GHCR_TOKEN；本修改
解锁的是**配置界面与 API 路由的许可门控**，数据面组件的获取与运行仍需按厂商授权。

## 五、验证情况

- 核心逻辑 Node.js 独立复现测试 **41/41 通过**：7 个特性在各种许可证状态下的门控行为；
  密码过期计算（89/90/91 天边界、警告窗口、无时间戳豁免、策略禁用、登录门判定）
- 全部修改源码文件通过 esbuild 语法检查
- i18n：6 种语言 21 个新键 + 登录错误文案，键完整性脚本校验通过，JSON 全部合法
- Prisma schema 无重复字段；迁移 SQL 与 schema 映射一致
- docker-publish.yml 通过 YAML 解析与 job 依赖一致性校验（needs 引用、staging/PR 条件、
  release/bundle 依赖完整，无残留 test job 引用）
- 与官方源码全量 diff：18 个修改文件 + 4 个新增文件 + 2 个文档文件，无其他差异

## 六、修改文件清单

```
修改  frontend/src/lib/license/features.ts            （特性白名单：7 项强制授予）
修改  frontend/src/lib/license/features.test.ts       （测试同步）
修改  frontend/prisma/schema.prisma                   （+3 个字段）
修改  frontend/src/lib/compliance/policies.ts         （字段映射、校验、getUserPasswordAgeStatus）
修改  frontend/src/lib/auth/config.ts                 （登录时密码过期强制校验）
修改  frontend/src/app/api/v1/users/route.ts          （创建用户写 password_changed_at）
修改  frontend/src/app/api/v1/users/[id]/route.ts     （重置/改密写时间戳；清密码同步清时间戳）
修改  frontend/src/app/(dashboard)/settings/page.jsx  （注册密码策略标签页）
修改  frontend/src/views/Login.jsx                    （PASSWORD_EXPIRED 文案映射）
修改  frontend/src/app/(dashboard)/profile/page.jsx   （密码到期提醒横幅）
修改  frontend/src/messages/{en,zh-CN,de,fr,es,ko}.json（6 语言文案）
修改  .github/workflows/docker-publish.yml    （删除测试 job，build-frontend 直接构建）
修改  frontend/Dockerfile                       （lockfile 可选 + npm install 回退）
新增  frontend/prisma/migrations/20261125120000_password_max_age/migration.sql
新增  frontend/src/app/api/v1/settings/password-policy/route.ts
新增  frontend/src/app/api/v1/auth/password-status/route.ts
新增  frontend/src/components/settings/PasswordPolicyTab.tsx
新增  features.patch / 本文件
```

完整差异见包内 `features.patch`（22 个文件，可用 `git apply features.patch` 复现）。

## 七、许可证与合规提醒

- 本源码遵循 **AGPL-3.0**：可自由修改和自部署，但通过网络对外提供服务时需按 AGPL-3.0
  第 13 条向使用者提供本修改版源码；版权与许可声明须保留。
- ProxCenter 的商业模式是开源核心 + 付费企业版。**生产/商业环境建议购买官方 Enterprise
  授权**（https://proxcenter.io/pricing），或评估官方 **Homelab 版**（面向个人实验室的
  非商业企业功能授权），以获得官方支持、私有镜像访问与持续更新。
- 本修改版与官方无任何隶属关系；升级官方新版本时需重新应用 `features.patch`。

## 八、部署方式

与官方 Community Edition 相同（见官方 README）：

```bash
# 源码方式：先构建镜像
cd frontend && docker build -t proxcenter-frontend:1.5.0-mod .
# 然后在仓库根目录
cp .env.example .env    # 设置 POSTGRES_PASSWORD、NEXTAUTH_SECRET 等
# 将 docker-compose.community.yml 中 frontend 镜像改为本地构建镜像名
docker compose -f docker-compose.community.yml up -d
# 访问 http://服务器:3000 创建首个管理员账号
```

数据库迁移（密码期限两个新列 + 存量回填）随容器启动自动执行。

## 九、CI / Docker 构建修改（跳过测试，直接构建镜像）

针对 GitHub Actions `docker-publish` 工作流在测试阶段失败（`npm ci` 因检出代码缺少
`package-lock.json` 报 `EUSAGE`）的修复：

**`.github/workflows/docker-publish.yml`**
- 删除 `test`（前端 vitest 全量测试）与 `test-backend`（Go 后端测试）两个 job：CI 不再
  运行任何测试阶段；
- `build-frontend` 直接构建：无 `needs`、无测试门控 `if`，push / tag / PR / 手动触发即刻
  开始 Docker 镜像构建并推送 ghcr.io；
- `build-demo` / `build-weasyprint` / `build-ha-images` / `build-orchestrator` 同步去掉
  测试依赖，仅保留 staging 守卫与 PR 跳过语义；
- `release` / `bundle` 的依赖关系不变。

**`frontend/Dockerfile`**
- `COPY package*.json ./`：lockfile 变为可选；
- 依赖安装改为：有 `package-lock.json` 用 `npm ci`；没有则自动回退
  `npm install --legacy-peer-deps --ignore-scripts`——即使仓库里没有 lockfile，镜像构建
  也不会再因 `npm ci EUSAGE` 失败。

**建议**：若你的 GitHub 仓库缺 `frontend/package-lock.json`，把包内该文件提交进仓库
（下载目录已单独提供副本）。回退 `npm install` 只是没有 lockfile 时的兑底，提交
lockfile 才能完全锁定依赖版本。

**注意**：`release` / `bundle` 两个 job 仅在打 `v*` 标签时运行，且仍依赖 orchestrator
等其它镜像构建；如你的 fork 没有配置 `ORCHESTRATOR_PAT`（访问私有 backend 仓库），
这些 job 会失败，但不影响 `build-frontend` 的镜像构建与推送。
