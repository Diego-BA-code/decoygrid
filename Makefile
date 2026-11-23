.PHONY: up down logs ps build backup restore-test test update breadcrumbs-sync

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f --tail=200

ps:
	docker compose ps

build:
	docker compose build

backup:
	./scripts/backup.sh

restore-test:
	./scripts/restore-test.sh

test:
	docker compose exec app python -m pytest -q

update:
	docker compose pull
	docker compose up -d

breadcrumbs-sync:
	./scripts/sync-breadcrumbs.sh
