
DOCKER=docker
IMGTAG=petroud/stelar-tuc:data-api-dev
IMGPATH=.
DOCKERFILE=$(IMGPATH)/Dockerfile.dev
.PHONY: all build push


all: build push

build:
	$(DOCKER) build -f $(DOCKERFILE) $(IMGPATH) -t $(IMGTAG)

push:
	$(DOCKER) push $(IMGTAG)

