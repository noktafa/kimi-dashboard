.PHONY: help setup certs test start stop clean docker-build docker-up docker-down

help: ## Show this help message
	@echo "Kimi Ecosystem Security - Available Commands:"
	@echo
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: ## Run initial setup (install deps, generate certs)
	./setup.sh

certs: ## Generate TLS certificates
	python3 shared/generate_certs.py --output-dir certs

test: ## Run security tests
	python3 tests/test_security.py

start-security-auditor: ## Start Security Auditor service
	cd kimi-security-auditor/src && python3 main.py

start-sysadmin-ai: ## Start SysAdmin AI service
	cd kimi-sysadmin-ai/src && python3 main.py

start-convergence-loop: ## Start Convergence Loop service
	cd kimi-convergence-loop/src && python3 main.py

start-dashboard: ## Start Dashboard service
	cd kimi-dashboard/src && python3 main.py

docker-build: ## Build all Docker images
	docker-compose build

docker-up: ## Start all services with Docker Compose
	docker-compose up -d

docker-down: ## Stop all Docker Compose services
	docker-compose down

docker-logs: ## View Docker Compose logs
	docker-compose logs -f

clean: ## Clean up generated files and certificates
	rm -rf certs/
	rm -rf venv/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

api-key: ## Generate a new API key (usage: make api-key KEY_ID=my-service ROLE=operator)
	@if [ -z "$(KEY_ID)" ]; then echo "Usage: make api-key KEY_ID=my-service ROLE=operator"; exit 1; fi
	python3 shared/generate_api_key.py $(KEY_ID) --role $(ROLE) --no-save

health-check: ## Check health of all services
	@echo "Checking Security Auditor..."
	@curl -ks https://localhost:8000/health | jq . 2>/dev/null || echo "  Not running"
	@echo "Checking SysAdmin AI..."
	@curl -ks https://localhost:8001/health | jq . 2>/dev/null || echo "  Not running"
	@echo "Checking Convergence Loop..."
	@curl -ks https://localhost:8002/health | jq . 2>/dev/null || echo "  Not running"
	@echo "Checking Dashboard..."
	@curl -ks https://localhost:8766/health 2>/dev/null | jq . 2>/dev/null || echo "  Not running"