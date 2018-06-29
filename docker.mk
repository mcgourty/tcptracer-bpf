# debugfs needs to be mounted manually to work in docker.
mount-debugfs:
	mkdir -p /sys/kernel/debug && mount -t debugfs debugfs /sys/kernel/debug

# make sure the tracer rebuilds each time.
build:
	cd tests && rm -f ./tracer && go build -o tracer tracer.go

docker-test: build mount-debugfs
	cd tests && ./run

docker-start: build mount-debugfs
	cd tests && ./tracer
