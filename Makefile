# Convenience wrapper around CMake (the real build system). Usage: make | make test | make run-server ...
BUILD_DIR ?= build
JOBS ?= $(shell nproc)

.PHONY: all nogui test clean distclean deps seed run-server run-client run-gui demo help

all:
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake .. && cmake --build . -j$(JOBS)

nogui:
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake .. -DLINSFT_BUILD_GUI=OFF && cmake --build . -j$(JOBS)

test: all
	cd $(BUILD_DIR) && ctest --output-on-failure

deps:
	sudo apt-get update
	sudo apt-get install -y build-essential cmake pkg-config libsqlite3-dev sqlite3 qt6-base-dev

seed: all
	./network-file-server --seed-demo

run-server: all
	./file_server 5000

run-client: all
	./file_client 127.0.0.1 5000

run-gui: all
	./network-file-gui

demo:
	./scripts/run_demo.sh

clean:
	rm -rf $(BUILD_DIR)
	rm -f network-file-server network-file-client network-file-gui file_server file_client

distclean: clean
	rm -rf database/*.db database/*.db-wal database/*.db-shm server_storage/* logs/* config/demo-credentials.txt
	touch server_storage/.gitkeep logs/.gitkeep

help:
	@echo "make [all|nogui|test|deps|seed|run-server|run-client|run-gui|demo|clean|distclean]"
