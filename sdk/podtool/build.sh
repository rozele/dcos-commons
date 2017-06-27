#!/usr/bin/env bash

# exit immediately on failure
set -e

CUR_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $CUR_DIR
source ../../tools/init_paths.sh

EXE_PATH=sdk/podtool

if [ ! -f mesos/mesos.pb.go ]; then
    # check for protoc
    if [ "$(which protoc)" == "" ]; then
        echo "'protoc' must be installed in order to build this tool"
        echo "Download the latest 'protoc-X.Y.Z-YOUROS.zip' release from https://github.com/google/protobuf/releases, then put 'protoc' in your PATH"
        exit 1
    fi

    # check for protoc-gen-go plugin
    if [ ! -f $GOPATH/bin/protoc-gen-go ]; then
        go get -u github.com/golang/protobuf/protoc-gen-go
    fi

    # generate mesos.pb.go
    mkdir -p mesos
    pushd mesos
    curl -O https://raw.githubusercontent.com/apache/mesos/master/include/mesos/mesos.proto
    PATH=$PATH:$GOPATH/bin protoc --go_out=. mesos.proto
    popd
fi

$TOOLS_DIR/build_go_exe.sh $EXE_PATH windows
$TOOLS_DIR/build_go_exe.sh $EXE_PATH darwin
$TOOLS_DIR/build_go_exe.sh $EXE_PATH linux
