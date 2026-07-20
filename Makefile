.PHONY: help build test lint fmt typecheck clean docker-up docker-down init-web init-server \
	gateway-build gateway-up gateway-down gateway-logs gateway-test waf-test ftw-test

COMPOSE_STAGE1 := docker compose -f deployment/docker-compose.stage1.yml
GATEWAY_PORT ?= 18080
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
