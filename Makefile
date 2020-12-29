SOURCE = $(wildcard *.go)
TAG ?= $(shell git describe --tags)
GOBUILD = go build -ldflags '-w'

ALL = \
	$(foreach arch,64 32,\
	$(foreach suffix,linux osx,\
		build/go-syslogd-$(arch)-$(suffix))) \
	$(foreach arch,arm arm64,\
		build/go-syslogd-$(arch)-linux)

all: test build

docker:
	docker build . -t webdevops/go-syslogd

docker-dev:
	cp build/go-syslogd-64-linux go-syslogd
	docker build -f Dockerfile.develop . -t webdevops/go-syslogd:develop

docker-run-dev: docker-dev
	docker run -ti --rm -w "$$(pwd)" -v "$$(pwd):$$(pwd):ro" --name go-syslogd webdevops/go-syslogd:develop sh


build: clean test $(ALL)

# cram is a python app, so 'easy_install/pip install cram' to run tests
test:
	echo "No tests"
	#cram tests/*.test

clean:
	rm -f $(ALL)

# os is determined as thus: if variable of suffix exists, it's taken, if not, then
# suffix itself is taken
osx = darwin
build/go-syslogd-64-%: $(SOURCE)
	@mkdir -p $(@D)
	CGO_ENABLED=0 GOOS=$(firstword $($*) $*) GOARCH=amd64 $(GOBUILD) -o $@

build/go-syslogd-32-%: $(SOURCE)
	@mkdir -p $(@D)
	CGO_ENABLED=0 GOOS=$(firstword $($*) $*) GOARCH=386 $(GOBUILD) -o $@

build/go-syslogd-arm-linux: $(SOURCE)
	@mkdir -p $(@D)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 $(GOBUILD) -o $@

build/go-syslogd-arm64-linux: $(SOURCE)
	@mkdir -p $(@D)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBUILD) -o $@

release: build
	github-release release -u webdevops -r go-syslogd -t "$(TAG)" -n "$(TAG)" --description "$(TAG)"
	@for x in $(ALL); do \
		echo "Uploading $$x" && \
		github-release upload -u webdevops \
                              -r go-syslogd \
                              -t $(TAG) \
                              -f "$$x" \
                              -n "$$(basename $$x)"; \
	done
