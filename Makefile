.PHONY: help build up down logs ps shell scan list bundle clean

help:
	@echo "NetMon — network discovery and analysis"
	@echo ""
	@echo "  make build         Build the collector image"
	@echo "  make up            Start the stack (collector + postgres)"
	@echo "  make down          Stop the stack"
	@echo "  make logs          Tail collector logs"
	@echo "  make ps            Show container status"
	@echo "  make shell         Shell into the collector container"
	@echo "  make scan IFACE=ethX [REASON=manual]"
	@echo "                     Trigger a one-off scan on an interface"
	@echo "  make list          List recent scan runs"
	@echo "  make bundle ID=N   Export an evidence bundle ZIP for scan id N"
	@echo "  make clean         Remove containers and volumes (DESTROYS DATA)"

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f collector

ps:
	docker compose ps

shell:
	docker compose exec collector bash

scan:
	@test -n "$(IFACE)" || (echo "usage: make scan IFACE=ethX [REASON=manual]" && exit 1)
	docker compose exec collector python -m collector scan $(IFACE) --reason $(or $(REASON),manual)

list:
	docker compose exec collector python -m collector list

bundle:
	@test -n "$(ID)" || (echo "usage: make bundle ID=N" && exit 1)
	docker compose exec collector python -m collector bundle $(ID)
	@echo ""
	@echo "Bundle written to /var/lib/netmon/bundles/  — upload the ZIP to Claude for analysis."

clean:
	@echo "This stops containers and removes the postgres volume."
	@echo "Config in /etc/netmon and bundles in /var/lib/netmon are PRESERVED."
	@echo "To wipe everything including config, see README 'start completely over'."
	docker compose down -v
