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
	docker compose exec app python -c "import sqlite3,time; src=sqlite3.connect('/data/decoygrid.db'); dst=sqlite3.connect('/data/backup-'+time.strftime('%Y%m%d-%H%M%S')+'.db'); src.backup(dst); dst.close(); src.close(); print('backup ok')"

restore-test:
	docker compose exec app python -c "import sqlite3,glob,os; f=sorted(glob.glob('/data/backup-*.db'))[-1]; c=sqlite3.connect(f); c.execute('select count(*) from events'); print('eventos en backup:', c.fetchone()[0]); c.close()"

test:
	docker compose exec app python -m pytest -q

update:
	docker compose pull
	docker compose up -d

breadcrumbs-sync:
	./scripts/sync-breadcrumbs.sh
