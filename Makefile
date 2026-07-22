.PHONY: help build test lint fmt typecheck clean docker-up docker-down init-web init-server \
	gateway-build gateway-up gateway-down gateway-logs gateway-test waf-test ftw-test \
	server-build server-test server-test-integration web-install web-typecheck web-lint web-test web-build \
	stage2-up stage2-down stage2-test stage2-status \
	guard-build guard-test trusted-proxy-test access-control-test rate-limit-test \
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
	stage7-test-cost ai-build ai-migrate ai-seed ai-evaluation

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

build: build-server build-web

build-server:
	@echo "构建后端..."
	cd server && go build -o ../bin/jiuzhang-server ./cmd/server

build-web:
	@echo "构建前端..."
	cd web && npm run build

test: test-server test-web

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

stage7-test-tools:
	cd server && go test ./internal/aitools/ -count=1 -v

stage7-test-agents:
	cd server && go test ./internal/aiagents/ ./internal/aiorchestrator/ -count=1 -v

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

