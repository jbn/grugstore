.PHONY: all
all: lint typecheck test

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

.PHONY: typecheck
typecheck:
	uv run ty check

.PHONY: check
check: lint typecheck test

.PHONY: build
build:
	# First bump the version - you can use: uv version --bump patch/minor/major
	uv build

.PHONY: publish
publish: build
	uv publish