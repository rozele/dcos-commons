package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/aryann/difflib"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/mesosphere/dcos-commons/sdk/podtool/mesos"
	"log"
	"os"
	"strings"
)

type Format int

const (
	Proto Format = iota
	Binary
	Text
	Foo
)

// Called by "get" to convert e.g. protobuf to json. Inverse of convertDiskToZk.
func convertZkToDisk(relZkPath string, zkData []byte, zkFormat Format) []byte {
	switch zkFormat {
	case Proto:
		// Convert the protobuf to json
		return convertProtobufToJson(relZkPath, zkData)
	case Binary:
		fallthrough
	case Text:
		// Return original data as-is in both cases
		return zkData
	}
	log.Fatalf("Unsupported format: %s", zkFormat)
	return nil // arbitrary value for happy compiler
}

// Called by "put" to convert e.g. json back to protobuf. Inverse of convertZkToDisk.
func convertDiskToZk(relZkPath string, diskData []byte, zkFormat Format) []byte {
	// Inverse of convertZkToDisk():
	switch zkFormat {
	case Proto:
		mesosProto := convertJsonToProtobuf(relZkPath, diskData)
		if mesosProto == nil {
			log.Fatalf("Unable to parse provided JSON data (%d bytes) to a Protobuf", len(diskData))
		}
		return mesosProto
	case Binary:
		fallthrough
	case Text:
		// Return original data as-is in both cases
		return diskData
	}
	log.Fatalf("Unsupported format: %s", zkFormat)
	return nil // arbitrary value for happy compiler
}

// Called by "delete" and "put" to convert zk data to some user-displayable format (e.g. for diffs)
func convertZkToPrint(relZkPath string, zkData []byte, zkFormat Format) string {
	switch zkFormat {
	case Proto:
		// Convert the protobuf to json
		jsonData := convertProtobufToJson(relZkPath, zkData)
		if jsonData == nil {
			log.Fatalf("Unable to convert provided protobuf data (%d bytes) to JSON", len(zkData))
		}
		return string(jsonData)
	case Binary:
		// Render hexdump of binary data
		return hex.Dump(zkData)
	case Text:
		return string(zkData)
	}
	log.Fatalf("Unsupported format: %s", zkFormat)
	return "" // arbitrary value for happy compiler
}

// Infers the format of the provided data, based on its content.
func autodetectFormat(relZkPath string, data []byte) Format {
	// Case 1: Protobuf
	mesosProto := getMesosProtoFromRaw(data)
	if mesosProto != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "Autodetected data for %s as %s", relZkPath, proto.MessageName(mesosProto))
		}
		return Proto
	}
	// Case 2: Non-protobuf binary data.
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
		if verbose {
			fmt.Fprintf(os.Stderr, "Autodetected data for %s as binary data", relZkPath)
		}
		return Binary
	}
	// Case 3: Printable ASCII string (see whitelist check above).
	if verbose {
		fmt.Fprintf(os.Stderr, "Autodetected data for %s as printable string data", relZkPath)
	}
	return Text
}

// Called by "put" to show changes to a ZK node.
// The format is expected to match between oldDataZk and newDataZk.
func getDiff(relZkPath string, absZkPath string, oldDataZk []byte, newDataZk []byte, format Format) string {
	if oldDataZk == nil {
		return fmt.Sprintf("New node %s (%d bytes):\n%s",
			absZkPath, len(newDataZk), convertZkToPrint(relZkPath, newDataZk, format))
	}

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("Changes to %s (%d bytes -> %d bytes):\n", absZkPath, len(oldDataZk), len(newDataZk)))
	for _, diffRec := range difflib.Diff(
		strings.Split(convertZkToPrint(relZkPath, oldDataZk, format), "\n"),
		strings.Split(convertZkToPrint(relZkPath, newDataZk, format), "\n")) {
		buf.WriteString(fmt.Sprintf("%s\n", diffRec))
	}
	return buf.String()
}

// Converts the provided protobuf message to a JSON formatted string.
func convertProtobufToJson(relZkPath string, data []byte) []byte {
	mesosProto := getMesosProtoFromRaw(data)
	if mesosProto == nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "Unable to detect a protobuf type for data from %s\n", relZkPath)
		}
		return nil
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "Autodetected protobuf type for data from %s: %s\n", relZkPath, proto.MessageName(mesosProto))
	}
	marshaler := jsonpb.Marshaler{
		EnumsAsInts: false,
		EmitDefaults: false,
		Indent: "  ",
		OrigName: true,
	}
	var buf bytes.Buffer
	err := marshaler.Marshal(&buf, mesosProto)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate %s JSON: %s\n", proto.MessageName(mesosProto), err)
		return nil
	}
	return buf.Bytes()
}

// Converts the provided JSON formatted string to a protobuf message.
func convertJsonToProtobuf(relZkPath string, data []byte) []byte {
	mesosProto := getMesosProtoFromJson(data)
	if mesosProto == nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "Unable to detect a protobuf type for data to %s\n", relZkPath)
		}
		return nil
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "Autodetected protobuf type for data to %s: %s\n", relZkPath, proto.MessageName(mesosProto))
	}
	data, err := proto.Marshal(mesosProto)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate %s protobuf: %s\n", proto.MessageName(mesosProto), err)
		return nil
	}
	return data
}


// Attempts to convert the provided raw serialized data to a supported Mesos Protobuf message.
// Returns nil if none of the expected types work.
func getMesosProtoFromRaw(data []byte) proto.Message {
	// NOTE: conveniently, TaskInfo and TaskStatus messages have required fields which are mutually exclusive across the two types.
	// Therefore we can simply try to parse them as-is and if they work then we're probably good.
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

// Attempts to convert the provided JSON data to a supported Mesos Protobuf message.
// Returns nil if none of the expected types work.
func getMesosProtoFromJson(data []byte) proto.Message {
	// NOTE: conveniently, TaskInfo and TaskStatus messages have required fields which are mutually exclusive across the two types.
	// Therefore we can simply try to parse them as-is and if they work then we're probably good.
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
