export DOCKER_CLI_EXPERIMENTAL=enabled

PLATFORM := "linux/amd64,linux/arm/v7,linux/arm64"

TAG?=0.373
OWNER?=dorkamotorka
NAME=gateway

.PHONY: local-docker
build-local:
	@echo $(OWNER)/$(NAME):$(TAG) \
	&& docker buildx create --use --name=multiarch --node multiarch \
	&& docker buildx build \
		--progress=plain \
		--platform linux/amd64 \
		--output "type=docker,push=false" \
		--tag $(OWNER)/$(NAME):$(TAG) .

.PHONY: push-docker
push-docker:
	@echo $(SERVER)/$(OWNER)/$(NAME):$(TAG) \
	&& docker buildx create --use --name=multiarch --node multiarch \
	&& docker buildx build \
		--progress=plain \
		--platform $(PLATFORM) \
		--output "type=image,push=true" \
		--tag $(OWNER)/$(NAME):$(TAG) .
