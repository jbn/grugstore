.PHONY: all
all: lint test

.PHONY: test
test:
	uv run pytest src/tests

.PHONY: format
format:
	uv run black src/

.PHONY: lint
lint:
	uv run ruff check src/

.PHONY: lint-fix
lint-fix:
	uv run ruff check --fix src/

.PHONY: check
check: lint test