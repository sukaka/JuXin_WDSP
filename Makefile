.PHONY: help build test lint fmt typecheck clean docker-up docker-down init-web init-server

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
