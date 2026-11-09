# Host/static test build of aohp-containerd (no AOSP tree): glibc, -static, so the binary also runs on an
# Android device as a test daemon:  ./aohp-containerd-hosttest --bind /data/local/tmp/aohp_test.sock
# (then --client 'UNIT oc list' --socket /data/local/tmp/aohp_test.sock). Logs go to stderr / $AOHP_LOG_FILE.
# Needs zlib static (zlib-static / zlib-devel), libutil is in glibc.
CXX ?= g++
CXXFLAGS ?= -std=c++17 -O1 -g -Wall -Wno-unused-parameter -Wno-unused-function -pthread -I stubs -I ..
SRCS = ../main.cpp ../bridge_net.cpp ../container_manager.cpp ../cgroup_controller.cpp ../session.cpp ../tar_gz_extract.cpp ../unit_file.cpp ../unit_manager.cpp
all: aohp-containerd-hosttest unit_file_test
aohp-containerd-hosttest: $(SRCS) stubs/android-base/logging.h stubs/android-base/strings.h stubs/cutils/sockets.h
	$(CXX) $(CXXFLAGS) -static -o $@ $(SRCS) -lz -lutil -pthread
unit_file_test: unit_file_test.cpp ../unit_file.cpp
	$(CXX) $(CXXFLAGS) -o $@ unit_file_test.cpp ../unit_file.cpp
test: unit_file_test
	./unit_file_test
clean:
	rm -f aohp-containerd-hosttest unit_file_test
.PHONY: all test clean
