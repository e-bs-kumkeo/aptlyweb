container:
	docker build -t aptlyweb .

run:
	docker compose up

.PHONY: container run