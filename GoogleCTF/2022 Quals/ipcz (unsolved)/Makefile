# Please use docker for building your challenges so that SREs can rebuild it
# if necessary without installing any dependencies.
broker: build.dockerfile broker.cc BUILD.gn flag_bearer.cc poc.cc 0001-Allow-embedder-to-choose-node-name.patch 0002-Remove-locking-code.patch 0003-Add-build-targets-for-challenge-binaries.patch 0001-My-Code.patch 0001-Logging-to-cout.patch
	- docker rm tmp-chal-container 2>/dev/null
	docker build -t tmp-chal-image -f build.dockerfile .
	docker run --name tmp-chal-container tmp-chal-image /bin/true
	docker cp tmp-chal-container:/build/ipcz/out/broker .
	docker cp tmp-chal-container:/build/ipcz/out/flag_bearer .
	docker cp tmp-chal-container:/build/ipcz/out/poc .
	docker cp tmp-chal-container:/build/ipcz/out/libabsl.so .
	docker cp tmp-chal-container:/build/ipcz/out/libc++.so .
	- docker rm tmp-chal-container 2>/dev/null
	touch broker
