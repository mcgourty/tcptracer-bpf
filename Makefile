DEBUG=1
UID=$(shell id -u)
PWD=$(shell pwd)

DOCKER_FILE?=Dockerfile
DOCKER_IMAGE?=weaveworks/tcptracer-bpf-builder

# If you can use docker without being root, you can do "make SUDO="
SUDO=$(shell docker info >/dev/null 2>&1 || echo "sudo -E")

all: build-docker-image build-ebpf-object install-generated-go

build-docker-image:
	$(SUDO) docker build -t $(DOCKER_IMAGE) -f $(DOCKER_FILE) .

build-ebpf-object:
	$(SUDO) docker run -e DEBUG=$(DEBUG) -e CIRCLE_BUILD_URL=$(CIRCLE_BUILD_URL) $(DOCKER_IMAGE) bash

install-generated-go:
	cp ebpf/tcptracer-ebpf.go pkg/tracer/tcptracer-ebpf.go

delete-docker-image:
	$(SUDO) docker rmi -f $(DOCKER_IMAGE)

lint:
	./tools/lint -ignorespelling "agre " -ignorespelling "AGRE " .
	./tools/shell-lint .

# run the test suite in docker.
test-in-docker: all
	docker run -ti --privileged --net=host --pid=host $(DOCKER_IMAGE) make -f docker.mk docker-test

# start the test tracer in docker.
# enter the docker image and start tcp connections to test.
start-in-docker: all
	docker run -ti --privileged --net=host --pid=host $(DOCKER_IMAGE) make -f docker.mk docker-start

# enter the docker image in another tab to test the tracer.
# try wget google.com, etc.
enter-docker-image: all
	docker run -ti --privileged --net=host --pid=host $(DOCKER_IMAGE) bash
