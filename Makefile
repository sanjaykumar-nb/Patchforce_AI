.PHONY: help infra-up infra-down backend-dev frontend-dev test verify lint clean

help:
	@echo "PatchForge AI - Development Automation"
	@echo "  make infra-up      Start PostgreSQL, Redis & Ollama services"
	@echo "  make infra-down    Stop all background infrastructure services"
	@echo "  make backend-dev   Run FastAPI development server with hot-reload"
	@echo "  make frontend-dev  Run React Vite development server"
	@echo "  make test          Run full pytest test suite"
	@echo "  make verify        Run environment inspection script"
	@echo "  make lint          Run Ruff linter and formatter checks"
	@echo "  make clean         Remove cache files, pyc, and temp artifacts"

infra-up:
	docker compose up -d postgres redis

infra-down:
	docker compose down

backend-dev:
	cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

frontend-dev:
	cd frontend && npm run dev

test:
	cd backend && pytest -v

verify:
	python scripts/verify_env.py

lint:
	cd backend && ruff check .

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
