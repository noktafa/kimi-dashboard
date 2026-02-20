.PHONY: install install-dev test lint format build dashboard clean

install:
	pip install -e ./kimi-security-auditor
	pip install -e ./kimi-sysadmin-ai
	pip install -e ./kimi-convergence-loop
	pip install -e ./kimi-dashboard

install-dev: install
	pip install -r requirements-dev.txt

test:
	pytest */tests/ -v

test-cov:
	pytest */tests/ --cov=src --cov-report=html

lint:
	ruff check */src
	mypy */src

format:
	black */src
	ruff format */src

build:
	python -m build */pyproject.toml

dashboard:
	cd kimi-dashboard && python3 -m kimi_dashboard.server --port 8766

demo:
	cd demo && ./run_demo.sh

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf */build */dist */*.egg-info

docker-up:
	cd docker && ./start.sh

docker-down:
	cd docker && docker-compose down
