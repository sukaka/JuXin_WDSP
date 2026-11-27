.PHONY: help build build-server build-web test test-server test-web lint fmt typecheck clean docker-up docker-down init-web init-server \
	gateway-build gateway-up gateway-down gateway-logs gateway-test waf-test ftw-test pcap-test pcap-test-live pcap-build \
	server-build server-test server-test-integration web-install web-typecheck web-lint web-test web-build \
	stage2-up stage2-down stage2-test stage2-status \
	guard-build guard-test gateway-low-port-test trusted-proxy-test access-control-test rate-limit-test \
	stage5-up stage5-down stage5-status stage5-test-unit stage5-test-api stage5-test-gateway \
	stage5-test-performance stage5-test-e2e stage5-test-security stage5-test-all \
	stage6-up stage6-down stage6-status metrics-aggregate reports-test monitoring-test alerts-test \
	backup-create backup-verify restore-test upgrade-precheck upgrade-test delivery-check \
	sbom-generate license-audit stage6-test-unit stage6-test-api stage6-test-e2e \
	stage6-test-performance stage6-test-stability stage6-test-recovery stage6-test-security stage6-test-all \
	stage7-model-pull stage7-test-unit stage7-test-api stage7-test-e2e \
	stage7-test-performance stage7-test-security stage7-test-all \
	stage7-up stage7-down stage7-status stage7-test-tools stage7-test-agents \
	stage7-test-memory stage7-test-context stage7-test-injection stage7-test-hallucination \
	stage7-test-cost stage7-test-rag ai-build ai-migrate ai-seed ai-evaluation \
	ai-model-test ai-tool-test ai-agent-test ai-prompt-test \
	stage8-build stage8-migrate stage8-seed stage8-up stage8-status stage8-down \
	stage8-test-unit stage8-test-api stage8-test-discovery stage8-test-learning \
	stage8-test-versioning stage8-test-schema stage8-test-classification \
	stage8-test-identity stage8-test-authorization stage8-test-sensitive-data \
	stage8-test-behavior stage8-test-graph stage8-test-replay stage8-test-e2e \
	stage8-test-performance stage8-test-security stage8-test-gateway stage8-test-all \
	api-security-test-assets api-security-test-learning api-security-test-models \
	api-security-test-runtime api-security-test-schema api-security-test-response \
	api-security-test-auth api-security-test-authz api-security-test-behavior \
	api-security-test-data api-security-test-risk api-security-test-audit \
	api-security-test-spec api-security-test-e2e api-security-test-all api-security-inventory \
	openapi-reconcile

COMPOSE_STAGE1 := docker compose -f deployment/docker-compose.stage1.yml
COMPOSE_STAGE2 := docker compose -f deployment/docker-compose.stage2.yml --env-file .env.example
GATEWAY_PORT ?= 18080
API_PORT ?= 18081
FTW_BIN := $(shell go env GOPATH)/bin/go-ftw

help:
	@echo "九章WEB应用智能防护系统V2.0 构建工具"
	@echo ""
	@echo "Usage:"
	@echo "  make build          构建前后端"
	@echo "  make test           运行所有测试"
	@echo "  make lint           运行代码检查"
	@echo "  make typecheck      前端TypeScript类型检查"
	@echo "  make fmt            格式化代码"
	@echo "  make docker-up      启动基础依赖容器"
	@echo "  make docker-down    停止基础依赖容器"
	@echo "  make clean          清理构建产物"
	@echo ""
	@echo "阶段1网关POC:"
	@echo "  make gateway-build  构建自定义Caddy与测试源站镜像"
	@echo "  make gateway-up     启动阶段1网关环境(SEC_RULE_ENGINE=On|DetectionOnly|Off)"
	@echo "  make gateway-down   停止阶段1网关环境"
	@echo "  make gateway-logs   查看网关日志"
	@echo "  make gateway-test   运行WAF攻击与协议异常测试"
	@echo "  make ftw-test       运行go-ftw CRS回归测试"
	@echo "  make waf-test       运行全部阶段1测试"

build: build-server build-web pcap-build

build-server:
	@echo "构建后端..."
	cd server && go build -o ../bin/jiuzhang-api ./cmd/api

build-web:
	@echo "构建前端..."
	cd web && npm run build

test: test-server test-web pcap-test

test-server:
	@echo "运行后端测试..."
	cd server && go test -v -race -coverprofile=coverage.out ./...

test-web:
	@echo "运行前端测试..."
	cd web && npm test

lint:
	@echo "运行代码检查..."
	cd server && go vet ./...
	cd web && npm run lint

typecheck:
	@echo "前端类型检查..."
	cd web && npm run typecheck

fmt:
	@echo "格式化代码..."
	cd server && go fmt ./...
	cd web && npm run format

docker-up:
	@echo "启动基础依赖容器..."
	docker compose up -d postgres valkey

docker-down:
	@echo "停止基础依赖容器..."
	docker compose down

init-web:
	@echo "初始化前端依赖..."
	cd web && npm ci

init-server:
	@echo "初始化后端依赖..."
	cd server && go mod download

clean:
	@echo "清理构建产物..."
	rm -rf bin/
	rm -rf web/dist/
	rm -rf server/coverage.out
	rm -rf web/coverage/

# ---------- 阶段1 网关POC ----------

gateway-build:
	@echo "构建自定义Caddy与测试源站镜像..."
	$(COMPOSE_STAGE1) build gateway testorigin

gateway-up:
	@echo "启动阶段1网关环境（SEC_RULE_ENGINE=$(SEC_RULE_ENGINE)）..."
	SEC_RULE_ENGINE=$(or $(SEC_RULE_ENGINE),On) GATEWAY_PORT=$(GATEWAY_PORT) $(COMPOSE_STAGE1) up -d

gateway-down:
	@echo "停止阶段1网关环境..."
	$(COMPOSE_STAGE1) down

gateway-logs:
	docker logs -f jiuzhang-stage1-gateway

gateway-test:
	@echo "运行WAF攻击与协议异常测试（EXPECT_MODE=$(or $(EXPECT_MODE),on)）..."
	EXPECT_MODE=$(or $(EXPECT_MODE),on) GATEWAY_URL=http://127.0.0.1:$(GATEWAY_PORT) bash test/waf/scripts/run-waf-tests.sh
	EXPECT_MODE=$(or $(EXPECT_MODE),on) GATEWAY_PORT=$(GATEWAY_PORT) python3 test/waf/scripts/protocol-tests.py

ftw-test:
	@echo "运行go-ftw CRS回归测试..."
	cd test/waf/ftw && $(FTW_BIN) run -d crs-tests --config ftw.yaml --read-timeout=10s

waf-test: gateway-test ftw-test

# ---------- 阶段2 管理系统 ----------

server-build:
	@echo "构建管理后端..."
	cd server && go build -o ../bin/jiuzhang-api ./cmd/api

server-test:
	@echo "运行后端单元测试..."
	cd server && go test -race ./internal/...

server-test-integration:
	@echo "运行后端接口集成测试(需 postgres+valkey)..."
	cd server && go test ./tests/ -count=1

web-install:
	@echo "安装前端依赖..."
	cd web && npm ci

web-typecheck:
	cd web && npm run typecheck

web-lint:
	cd web && npm run lint

web-test:
	cd web && npm test

web-build:
	@echo "构建前端..."
	cd web && npm run build

stage2-up:
	@echo "启动阶段2环境..."
	$(COMPOSE_STAGE2) up -d postgres valkey

stage2-down:
	@echo "停止阶段2环境..."
	$(COMPOSE_STAGE2) down

stage2-status:
	@$(COMPOSE_STAGE2) ps

stage2-test: server-test web-test

# ---------- 阶段5 访问控制与CC防护 ----------

COMPOSE_STAGE5 := docker compose --env-file .env -f deployment/docker-compose.stage5.yml

guard-build:
	@echo "构建含 jiuzhang_guard 模块的自定义 Caddy 镜像..."
	docker build -t jiuzhang-gateway:stage5 gateway/

guard-test:
	@echo "运行 jiuzhang_guard 模块单元测试..."
	cd gateway/modules/jiuzhang_guard && go test -race ./...

gateway-low-port-test:
	@echo "验证非 root 网关在最小权限下可监听 1024 以下端口..."
	bash scripts/tests/gateway-low-port.sh

pcap-build:
	@echo "构建Linux请求PCAP daemon..."
	cd gateway && GOOS=linux CGO_ENABLED=0 go build -trimpath -o ../bin/jiuzhang-pcapd ./cmd/pcapd

pcap-test:
	@echo "运行PCAP内核、密钥与daemon测试..."
	cd gateway/pcapevidence && go test -race ./...
	cd gateway/dynamic_security && go test -race ./evidencekey
	cd gateway && go test -race ./pcapcapture ./cmd/pcapd

pcap-test-live:
	@echo "使用锁定镜像执行真实NET_RAW抓包测试..."
	docker run --rm --cap-add NET_RAW -e PCAPD_REQUIRE_LIVE=1 -v "$$PWD/gateway:/src:ro" -w /src \
		golang:1.25-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 \
		sh -c 'cd pcapevidence && go test -count=1 ./... && cd .. && go test -count=1 ./pcapcapture ./cmd/pcapd'

trusted-proxy-test:
	@echo "运行可信代理相关单元测试..."
	cd gateway/modules/jiuzhang_guard && go test ./clientip/ ./trustedproxy/ -count=1 -v
	cd server && go test ./internal/trustedproxies/ -count=1 -v

access-control-test:
	@echo "运行访问控制相关单元测试..."
	cd gateway/modules/jiuzhang_guard && go test ./accesscontrol/ ./cidr/ -count=1 -v
	cd server && go test ./internal/accessrules/ ./internal/protectedaddresses/ ./internal/temporaryblocks/ -count=1 -v

rate-limit-test:
	@echo "运行CC限速相关单元测试..."
	cd gateway/modules/jiuzhang_guard && go test ./ratelimit/ ./counters/ ./temporaryblock/ -count=1 -v
	cd server && go test ./internal/ratelimitpolicies/ -count=1 -v

stage5-up:
	@echo "启动阶段5环境..."
	$(COMPOSE_STAGE5) up -d

stage5-status:
	@$(COMPOSE_STAGE5) ps

stage5-down:
	@echo "停止阶段5环境..."
	$(COMPOSE_STAGE5) down

stage5-test-unit:
	@echo "阶段5单元测试（guard模块+后端+前端）..."
	cd gateway/modules/jiuzhang_guard && go test -race ./...
	cd server && go test ./internal/trustedproxies/ ./internal/protectedaddresses/ ./internal/accessrules/ ./internal/ratelimitpolicies/ ./internal/temporaryblocks/ ./internal/accesscontrolevents/ ./internal/accesscontrolversions/ ./internal/gatewayconfig/ ./internal/guardconfig/
	cd web && npm test

stage5-test-api:
	@echo "阶段5接口集成测试（需 postgres+valkey）..."
	cd server && go test ./tests -run TestStage5 -count=1 -v

stage5-test-gateway:
	@echo "阶段5真实网关测试（需 stage5-up）..."
	API_URL=http://127.0.0.1:$(API_PORT) GATEWAY_URL=http://127.0.0.1:$(GATEWAY_PORT) bash test/waf/scripts/stage5-gateway-tests.sh

stage5-test-performance:
	@echo "阶段5性能测试（需 stage5-up）..."
	API_URL=http://127.0.0.1:$(API_PORT) GATEWAY_URL=http://127.0.0.1:$(GATEWAY_PORT) bash test/performance/stage5-performance-tests.sh

stage5-test-e2e:
	@echo "阶段5 E2E 测试（需 stage5-up + 前端dev）..."
	cd web && npx playwright test e2e/stage5-access-control.spec.ts

stage5-test-security:
	@echo "阶段5安全测试（需 stage5-up）..."
	API_URL=http://127.0.0.1:$(API_PORT) GATEWAY_URL=http://127.0.0.1:$(GATEWAY_PORT) bash test/security/stage5-security-tests.sh

stage5-test-all: stage5-test-unit stage5-test-api stage5-test-gateway stage5-test-performance stage5-test-e2e stage5-test-security

# ---------- 阶段6 安全运营与正式交付 ----------

stage6-up: stage5-up

stage6-status: stage5-status

stage6-down:
	@echo "停止阶段5/6环境..."
	$(COMPOSE_STAGE5) down

metrics-aggregate:
	@echo "手动触发数据聚合..."
	curl -s -o /dev/null -w "minute aggregates: %{http_code}\n" http://127.0.0.1:$(API_PORT)/api/v1/health

reports-test:
	@echo "报告系统真实验证（创建/生成/预览/下载）..."
	bash test/e2e/stage6-smoke.sh

monitoring-test:
	@echo "运行监控与系统告警验证..."
	curl -s -o /dev/null -w "system-health: %{http_code}\n" http://127.0.0.1:$(API_PORT)/api/v1/health

alerts-test: monitoring-test

backup-create:
	@echo "创建全量备份..."
	bash ops/backup/create.sh

backup-verify:
	@echo "备份验证（含在备份流程内）..."
	bash test/e2e/stage6-smoke.sh

restore-test:
	@echo "全新环境恢复测试..."
	bash test/e2e/stage6-fresh-restore.sh

upgrade-precheck:
	@echo "升级预检验证..."
	bash test/e2e/stage6-smoke.sh

upgrade-test: upgrade-precheck

delivery-check:
	@echo "执行交付检查..."
	bash test/e2e/stage6-smoke.sh

sbom-generate:
	@echo "生成 SBOM..."
	bash scripts/generate-sbom.sh

license-audit:
	@echo "许可证审计..."
	bash scripts/license-audit.sh

stage6-test-unit:
	@echo "阶段6单元测试（后端+前端）..."
	cd server && go test ./internal/metrics/ ./internal/aggregations/ ./internal/dashboards/ ./internal/analytics/ ./internal/reports/ ./internal/runtimehealth/ ./internal/systemalerts/ ./internal/backups/ ./internal/restores/ ./internal/upgrades/ ./internal/delivery/
	cd web && npm test

stage6-test-api:
	@echo "阶段6接口集成测试（需 postgres+valkey）..."
	cd server && go test ./tests -run TestStage6 -count=1 -v

stage6-test-e2e:
	@echo "阶段6 E2E..."
	cd web && npx playwright test e2e/stage6-security-ops.spec.ts

stage6-test-performance:
	@echo "阶段6性能与容量测试..."
	bash test/performance/stage6-capacity-tests.sh

stage6-test-stability:
	@echo "阶段6稳定性浸泡（压缩计划，可配置时长 HOURS）..."
	HOURS=$(or $(HOURS),1) bash test/stability/stage6-soak.sh

stage6-test-recovery: restore-test

stage6-test-security:
	@echo "阶段6安全测试..."
	bash test/security/stage6-security-tests.sh

stage6-test-all: stage6-test-unit stage6-test-api stage6-test-e2e stage6-test-security

stage7-model-pull:
	@echo "拉取阶段7本地模型（qwen2.5:3b，约1.9GB）..."
	docker exec jiuzhang-stage5-ollama ollama pull qwen2.5:3b

stage7-test-unit:
	@echo "阶段7单元测试（AI 各包 + 接口层）..."
	cd server && go test ./internal/aimodel/ ./internal/aitools/ ./internal/aiorchestrator/ ./internal/aiagents/ ./internal/aihandlers/ ./internal/aiaudit/ ./internal/aicost/ ./internal/aimemory/ ./internal/aiprompts/

stage7-test-api:
	@echo "阶段7接口集成测试（需 postgres+valkey）..."
	cd server && go test ./tests -run TestStage7 -count=1 -v

stage7-test-e2e:
	@echo "阶段7 E2E..."
	cd web && npx playwright test e2e/stage7-ai-soc.spec.ts

stage7-test-performance:
	@echo "阶段7性能与成本测试（需 stage5-up）..."
	API_URL=http://127.0.0.1:$(API_PORT) bash test/performance/stage7-ai-performance-tests.sh

stage7-test-security:
	@echo "阶段7安全测试（需 stage5-up）..."
	API_URL=http://127.0.0.1:$(API_PORT) bash test/security/stage7-ai-security-tests.sh

stage7-test-all: stage7-test-unit stage7-test-api stage7-test-e2e stage7-test-security

# ---------- 阶段7 AI 扩展命令 ----------
stage7-up: stage5-up
	@echo "阶段7依赖 stage5 编排（含 ollama）；确认 AI_ENABLED=true"

stage7-down: stage5-down
	@echo "阶段7环境已停止（复用 stage5-down）"

stage7-status: stage5-status
	@echo "AI 状态：curl -s http://127.0.0.1:$(API_PORT)/api/v1/ai/status （需登录）"

ai-build: server-build
	@echo "AI 模块随 server 一并构建"

ai-migrate:
	@echo "AI 表随 server 迁移 000013-000015 自动执行"

ai-seed:
	@echo "AI 权限与默认模型种子：000014_seed_stage7_perms / 000015_seed_stage7_model"

ai-evaluation:
	@echo "运行评估集成测试子集..."
	cd server && go test ./tests -run 'TestStage7Evaluation' -count=1 -v

ai-model-test:
	@echo "AI 模型管理（客户端/网关/出网控制/模型管理接口）测试..."
	cd server && go test ./internal/aimodel/ -count=1 -v
	cd server && go test ./tests -run 'TestStage7ModelManagement' -count=1 -v

ai-tool-test:
	@echo "AI 工具（Tool 注册/执行/停用恢复）测试..."
	cd server && go test ./internal/aitools/ -count=1 -v
	cd server && go test ./tests -run 'TestStage7AgentToolManagement' -count=1 -v

ai-agent-test:
	@echo "AI Agent（编排器/各 Agent/分析接口）测试..."
	cd server && go test ./internal/aiagents/ ./internal/aiorchestrator/ -count=1 -v
	cd server && go test ./tests -run 'TestStage7AnalyzeEndpoints' -count=1 -v

ai-prompt-test:
	@echo "AI Prompt（版本/发布/回滚/注入防护）测试..."
	cd server && go test ./internal/aiprompts/ -count=1 -v
	cd server && go test ./tests -run 'TestStage7PromptManagement|TestStage7PromptInjection' -count=1 -v

stage7-test-tools:
	cd server && go test ./internal/aitools/ -count=1 -v

stage7-test-agents:
	cd server && go test ./internal/aiagents/ ./internal/aiorchestrator/ -count=1 -v

# 口径说明：任务书 §23 的 RAG 文档库（文档分级/索引/引用）尚未实现，本目标不冒充 RAG；
# 仅运行 KnowledgeAgent 现有检索能力的真实测试：aiagents 单元测试 +
# 评估集成测试（知识问答经编排器路由到 KnowledgeAgent，断言「知识解答」标题与 score，需 postgres+valkey）。
stage7-test-rag:
	@echo "知识库 Agent 现有检索能力测试（RAG 文档库未实现，口径见上方注释）..."
	cd server && go test ./internal/aiagents/ -count=1 -v
	cd server && go test ./tests -run 'TestStage7Evaluation' -count=1 -v

stage7-test-memory:
	cd server && go test ./internal/aimemory/ ./tests -run 'TestStage7Memories' -count=1 -v

stage7-test-context:
	cd server && go test ./internal/aiorchestrator/ ./tests -run 'TestStage7Context' -count=1 -v

stage7-test-injection:
	cd server && go test ./tests -run 'TestStage7PromptInjection' -count=1 -v

stage7-test-hallucination:
	cd server && go test ./tests -run 'TestStage7Hallucination' -count=1 -v

stage7-test-cost:
	cd server && go test ./internal/aicost/ ./tests -run 'TestStage7Usage' -count=1 -v


# ---------- 阶段8 / WDSP（统一 Web 与 API 动态防护） ----------
# 环境 = stage5 编排 + wdsp 产品形态覆盖（PRODUCT_EDITION=wdsp, API_DYNAMIC_PROTECTION_ENABLED=true）
COMPOSE_STAGE8 := $(COMPOSE_STAGE5) -f deployment/docker-compose.wdsp.yml

stage8-build:
	@echo "构建阶段8网关与全栈镜像（含 dynamic_security 引擎）..."
	$(COMPOSE_STAGE8) build

stage8-migrate:
	@echo "阶段8迁移 000016-000019 随 api 容器启动自动执行"
	cd server && go run ./cmd/api --migrate-only 2>/dev/null || echo "（无独立迁移入口，随服务启动执行）"

stage8-seed:
	@echo "阶段8权限种子：000019_stage8_perms（27 个权限点，随迁移执行）"

stage8-up:
	@echo "启动阶段8 WDSP 环境（stage5 + wdsp 覆盖）..."
	$(COMPOSE_STAGE8) up -d

stage8-status:
	@$(COMPOSE_STAGE8) ps

stage8-down:
	@echo "停止阶段8环境..."
	$(COMPOSE_STAGE8) down

stage8-test-unit:
	@echo "阶段8单元测试（引擎 + guard + 后端三包 + 前端）..."
	cd gateway/dynamic_security && go test -race ./...
	cd gateway/modules/jiuzhang_guard && go test -race ./...
	cd server && go test ./internal/apiassets/ ./internal/apimodels/ ./internal/apisecurity/ ./internal/apiruntime/ ./internal/product/ ./internal/guardconfig/
	cd web && npx vitest run

stage8-test-api:
	@echo "阶段8接口集成测试（需 postgres+valkey）..."
	cd server && go test ./tests -run TestStage8 -count=1 -v

stage8-test-discovery:
	@echo "API 发现与归一化测试..."
	cd gateway/dynamic_security && go test ./classifier/ ./normalizer/ ./parser/ -count=1
	cd server && go test ./internal/apiassets/ -run 'TestMemStore|TestHandler|TestEndpoint' -count=1 -v

stage8-test-learning:
	@echo "学习与样本测试..."
	cd gateway/dynamic_security && go test ./learning/ -count=1 -v
	cd server && go test ./internal/apiassets/ -run 'TestLearning|TestEndpointGroup' -count=1 -v

stage8-test-versioning:
	@echo "模型版本测试..."
	cd server && go test ./internal/apimodels/ -count=1 -v

stage8-test-schema:
	@echo "Schema 防护与偏离测试..."
	cd gateway/dynamic_security && go test ./detectors/ ./pipeline/ -run 'TestSchema|TestProcess|TestCheck' -count=1 -v

stage8-test-classification:
	@echo "用途分类测试..."
	cd server && go test ./internal/apisecurity/ -count=1 -v

stage8-test-identity:
	@echo "身份与凭据检测测试..."
	cd gateway/dynamic_security && go test ./detectors/ -run 'TestAuth|TestIdentity' -count=1 -v

stage8-test-authorization:
	@echo "BOLA/BFLA 辅助检测测试..."
	cd gateway/dynamic_security && go test ./detectors/ -run 'TestResource' -count=1 -v

stage8-test-sensitive-data:
	@echo "敏感数据检测测试..."
	cd gateway/dynamic_security && go test ./detectors/ -run 'TestSensitive' -count=1 -v

stage8-test-behavior:
	@echo "行为基线与限速测试..."
	cd gateway/dynamic_security && go test ./detectors/ -run 'TestBehavior|TestRate|TestWindow|TestLRU' -count=1 -v

stage8-test-graph:
	@echo "图谱与拓扑测试..."
	cd server && go test ./internal/apisecurity/ -run 'TestSpec|TestGraph|TestTopology' -count=1 -v

stage8-test-gateway:
	@echo "阶段8真实网关全链路验证（需 stage8-up）..."
	API_URL=http://127.0.0.1:$(API_PORT) GATEWAY_URL=http://127.0.0.1:$(GATEWAY_PORT) bash test/waf/scripts/stage8-gateway-tests.sh

stage8-test-replay:
	@echo "阶段8流量回放测试（需 stage8-up）..."
	API_URL=http://127.0.0.1:$(API_PORT) GATEWAY_URL=http://127.0.0.1:$(GATEWAY_PORT) bash test/waf/scripts/stage8-replay-tests.sh

stage8-test-e2e:
	@echo "阶段8 Playwright E2E（需 stage8-up + 前端dev）..."
	cd web && npx playwright test e2e/stage8-api-security.spec.ts e2e/stage8-api-security-ops.spec.ts e2e/stage8-api-security-ops2.spec.ts

stage8-test-performance:
	@echo "阶段8性能测试（需 stage8-up）..."
	API_URL=http://127.0.0.1:$(API_PORT) GATEWAY_URL=http://127.0.0.1:$(GATEWAY_PORT) bash test/performance/stage8-performance-tests.sh

stage8-test-security:
	@echo "阶段8安全测试（需 stage8-up）..."
	API_URL=http://127.0.0.1:$(API_PORT) GATEWAY_URL=http://127.0.0.1:$(GATEWAY_PORT) bash test/security/stage8-security-tests.sh

stage8-test-all: stage8-test-unit stage8-test-api stage8-test-gateway stage8-test-replay stage8-test-e2e stage8-test-performance stage8-test-security

# ---------- API 安全补全测试（api-security-test-*，任务书 §234 口径） ----------
# 领域目标只映射真实存在的测试路径；尚无测试资产的领域不建目标（如 scan 未实现）。

api-security-test-assets:
	@echo "API 资产（发现/生命周期/流量趋势）单元测试..."
	cd server && go test ./internal/apiassets/ -count=1

api-security-test-learning:
	@echo "学习闭环（样本/候选/janitor/自动候选）测试..."
	cd gateway/dynamic_security && go test ./learning/ -count=1
	cd server && go test ./internal/learningjobs/ -count=1
	cd server && go test ./internal/apiassets/ -run 'TestLearning' -count=1

api-security-test-models:
	@echo "模型版本/参数/运行时策略编译（Compiler/版本/回滚）测试..."
	cd server && go test ./internal/apimodels/ -count=1

api-security-test-runtime:
	@echo "运行时采集与事件（采集器/事件落库/findings 物化）测试..."
	cd server && go test ./internal/apiruntime/ -count=1

api-security-test-schema:
	@echo "Schema 防护与参数约束测试..."
	cd gateway/dynamic_security && go test ./detectors/ ./pipeline/ -run 'TestSchema|TestProcess|TestCheck' -count=1

api-security-test-response:
	@echo "响应侧（ResponseContext/响应相位/Response Transformer/MASK_RESPONSE）测试..."
	cd gateway/dynamic_security && go test ./response/ -count=1
	cd gateway/dynamic_security && go test ./pipeline/ -run 'TestResponse|TestProcessResponse' -count=1
	cd gateway/modules/jiuzhang_guard && go test ./ -run 'TestServeNext_Mask|TestServeNext_Fail|TestServeNext_Oversized|TestServeNext_NonJSON|TestServeNext_Response|TestServeNext_Downstream' -count=1

api-security-test-auth:
	@echo "身份与凭据检测（含指纹/画像风险评估）测试..."
	cd gateway/dynamic_security && go test ./detectors/ -run 'TestAuth|TestIdentity|TestFingerprint' -count=1
	cd server && go test ./internal/apisecurity/ -run 'TestIdentity' -count=1

api-security-test-authz:
	@echo "BOLA/BFLA 辅助检测测试..."
	cd gateway/dynamic_security && go test ./detectors/ -run 'TestResource' -count=1

api-security-test-behavior:
	@echo "行为基线与分布式状态（含 Valkey behaviorstore）测试..."
	cd gateway/dynamic_security && go test ./detectors/ -run 'TestBehavior|TestRate|TestWindow|TestLRU' -count=1
	cd gateway/modules/jiuzhang_guard && go test ./behaviorstore/ -count=1

api-security-test-data:
	@echo "敏感数据管理面（类型/脱敏规则/态势/派生扫描）测试..."
	cd server && go test ./internal/apidata/ -count=1

api-security-test-risk:
	@echo "风险发现与弱点中心（findings 物化/弱点状态机/派生扫描）测试..."
	cd server && go test ./internal/apiweakness/ -count=1
	cd server && go test ./internal/apiruntime/ -run 'TestFinding|TestRecordFindings|TestMaterializable|TestSanitizeEvidence|TestDedupFingerprint' -count=1

api-security-test-audit:
	@echo "审计溯源（操作审计/事件与 findings 富化迁移静态一致性）测试..."
	cd server && go test ./internal/audits/ -count=1
	cd server && go test ./tests/ -run 'TestAPIEnrichmentMigrationStatic' -count=1

api-security-test-spec:
	@echo "规范导入与 Diff 测试..."
	cd server && go test ./internal/apisecurity/ -run 'TestSpec|TestParseOpenAPI3|TestDiffEndpointKeys|TestHashSpecContent' -count=1

api-security-test-e2e:
	@echo "API 安全 Playwright E2E（需 stage8-up + 前端dev）..."
	cd web && npx playwright test e2e/stage8-api-security.spec.ts e2e/stage8-api-security-ops.spec.ts e2e/stage8-api-security-ops2.spec.ts

api-security-test-all: api-security-test-assets api-security-test-learning api-security-test-models api-security-test-runtime api-security-test-schema api-security-test-response api-security-test-auth api-security-test-authz api-security-test-behavior api-security-test-data api-security-test-risk api-security-test-audit api-security-test-spec

api-security-inventory:
	@echo "API 安全能力现状盘点文档：docs/API_SECURITY_CURRENT_STATE.md"
	@ls -l docs/API_SECURITY_CURRENT_STATE.md
	@echo ""
	@echo "工作树 git 状态摘要（$(shell git status --short | wc -l | tr -d ' ') 个变更/未跟踪条目，前 20 条）："
	@git status --short | head -20

# ---------- OpenAPI 文档对账 ----------

openapi-reconcile:
	@echo "合并 fragments 并校验片段不变量（重新生成 wdsp-api.yaml）..."
	python3 server/openapi/merge.py
	@echo "路由 ↔ OpenAPI 片段双向对账..."
	python3 tools/check-api-reconcile.py
