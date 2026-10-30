.PHONY: install test report incidents verify
install:
	pip install -r requirements.txt --break-system-packages
test:
	python3 -m pytest -q
	cd target/treasury-rs && cargo test --offline
	cd target/treasury-ts && node --test "test/*.test.ts"
report:
	python3 -m portcullis
incidents:
	python3 scripts/incidents.py
verify:
	python3 scripts/verify_incidents.py
