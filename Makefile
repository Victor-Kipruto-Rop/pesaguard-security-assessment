.PHONY: install test lint security run
install:
	python -m pip install -e '.[dev]'
test:
	pytest -q
lint:
	ruff check .
security:
	bandit -q -r src
run:
	uvicorn pg_assess.api:app --host 127.0.0.1 --port 8080
