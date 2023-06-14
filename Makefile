TAG?=latest
NS?=dorkamotorka

.PHONY: build-gateway
build-gateway:
	(cd gateway;  docker buildx build --load --platform linux/amd64 -t ${NS}/gateway:0.4 .)

# .PHONY: test-ci
# test-ci:
# 	./contrib/ci.sh
