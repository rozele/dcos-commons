package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/aryann/difflib"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/mesosphere/dcos-commons/sdk/podtool/mesos"
	"os"
	"strings"
)

func convertProtobufToJson(relZkPath string, data []byte) []byte {
	mesosProto := getMesosProtoFromRaw(data)
	if mesosProto == nil {
		return nil
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "Autodetected protobuf type: %s\n", proto.MessageName(mesosProto))
	}
	marshaler := jsonpb.Marshaler{
		EnumsAsInts: false,
		EmitDefaults: false,
		Indent: "  ",
		OrigName: true,
	}
	var buf bytes.Buffer
	// TODO set a type metafield?
	err := marshaler.Marshal(&buf, mesosProto)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate %s JSON: %s\n", proto.MessageName(mesosProto), err)
		return nil
	}
	return buf.Bytes()
}

func convertJsonToProtobuf(relZkPath string, data []byte) []byte {
	mesosProto := getMesosProtoFromJson(data)
	if mesosProto == nil {
		return nil
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "Autodetected protobuf type: %s\n", proto.MessageName(mesosProto))
	}
	data, err := proto.Marshal(mesosProto)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate %s protobuf: %s\n", proto.MessageName(mesosProto), err)
		return nil
	}
	return data
}

func getMesosProtoFromRaw(data []byte) proto.Message {
	taskInfo := &mesos.TaskInfo{}
	err := proto.Unmarshal(data, taskInfo)
	if err == nil {
		return taskInfo
	}

	taskStatus := &mesos.TaskStatus{}
	err = proto.Unmarshal(data, taskStatus)
	if err == nil {
		return taskStatus
	}

	return nil
}

func getMesosProtoFromJson(data []byte) proto.Message {
	unmarshaler := jsonpb.Unmarshaler{
		AllowUnknownFields: false,
	}
	buf := bytes.NewBuffer(data)

	taskInfo := &mesos.TaskInfo{}
	err := unmarshaler.Unmarshal(buf, taskInfo)
	if err == nil {
		return taskInfo
	}

	taskStatus := &mesos.TaskStatus{}
	err = unmarshaler.Unmarshal(buf, taskStatus)
	if err == nil {
		return taskStatus
	}

	return nil
}

// Called by "get" to convert e.g. protobuf to json
func convertZkToDisk(relZkPath string, data []byte) []byte {
	jsonResult := convertProtobufToJson(relZkPath, data)
	if jsonResult != nil {
		return jsonResult
	}
	return data // fall back to raw data
}

// Called by "put" to convert e.g. json back to protobuf
func convertDiskToZk(relZkPath string, data []byte) []byte {
	protobufResult := convertJsonToProtobuf(relZkPath, data) // TODO with 'put' calls this isn't detecting a TaskStatus JSON, and we're uploading it as-is!!
	if protobufResult != nil {
		return protobufResult
	}
	return data
}

// Called by "delete" and "put" to convert zk data to some user-displayable format (e.g. for diffs)
func convertZkToPrint(relZkPath string, data []byte) string {
	// Case 1: Data is a protobuf. Return the JSON version.
	jsonResult := convertProtobufToJson(relZkPath, data)
	if jsonResult != nil {
		return string(jsonResult)
	}
	// Case 2: Data is some other binary. Return a hex dump.
	for _, c := range data {
		// Had thought of just using unicode.isPrint() but it may miss many binary cases and excludes \n, \r, and \t.
		// Lets just do something relatively simple based on ASCII ranges:
		if c >= 32 && c <= 126 {
			// ascii letters, numbers, punctuation
			continue
		}
		if c == '\t' || c == '\n' || c == '\r' {
			// allow tabs and newlines to get through as well
			continue
		}
		return hex.Dump(data)
	}
	// Case 3: Data is a printable string. Return as-is, with newline added if necessary.
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	return string(data)
}

// Called by "put" to show changes to a ZK node
func getDiff(relZkPath string, absZkPath string, oldDataZk []byte, newDataZk []byte) string {
	if oldDataZk == nil {
		return fmt.Sprintf("New node %s (%d bytes):\n%s",
			absZkPath, len(newDataZk), convertZkToPrint(relZkPath, newDataZk))
	}

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("Changes to %s (%d bytes -> %d bytes):\n", absZkPath, len(oldDataZk), len(newDataZk)))
	for _, diffRec := range difflib.Diff(
		strings.Split(convertZkToPrint(relZkPath, oldDataZk), "\n"),
		strings.Split(convertZkToPrint(relZkPath, newDataZk), "\n")) {
		buf.WriteString(fmt.Sprintf("%s\n", diffRec))
	}
	return buf.String()
}
