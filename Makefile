VERSION=$(shell git describe | sed 's/^v//')

all: deps container

.PHONY: deps

deps: wheels common

FORCE:

common: wheels FORCE
	(cd wheels; pip3 wheel git+ssh://git@github.com/TrustNetworks/PyAnalyticsCommon3@master)

wheels: Makefile
	-rm -rf wheels wheels.tmp
	mkdir wheels.tmp
	(cd wheels.tmp; pip3 wheel git+git://github.com/cybermaggedon/pygaffer)
	(cd wheels.tmp; pip3 wheel git+ssh://git@github.com/trustnetworks/pythreatgraph)	
	mv wheels.tmp wheels

container: src/ja3-window.py
	docker build  --no-cache -t \
		gcr.io/trust-networks/analytics-ja3-window:${VERSION} \
	 	-f Dockerfile .

ALWAYS:

push:
	gcloud docker -- push \
	  gcr.io/trust-networks/analytics-ja3-window:${VERSION}

VERSION=$(shell git describe | sed 's/^v//')
