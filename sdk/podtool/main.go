package main

import (
	"bytes"
	"fmt"
	zklib "github.com/samuel/go-zookeeper/zk"
	"gopkg.in/alecthomas/kingpin.v2"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

var verbose bool

type zkHandler struct {
	// args
	service   string
	zkPath    string
	localPath string

	// flags
	servers []string
	recurse bool
	raw     bool
	force   bool
}

func (cmd *zkHandler) connect() *ZkAccess {
	zk, err := ZkConnect(cmd.service, cmd.servers, verbose)
	if err != nil {
		log.Fatalf("Unable to connect to zookeeper at %v+: %s", cmd.servers, err)
	}
	return zk
}

func printChildrenRecursive(zk *ZkAccess, path string, indent int) error {
	children, err := zk.Children(path)
	if err != nil {
		return err
	}
	pathElems := strings.Split(path, "/")
	nodeName := pathElems[len(pathElems)-1]
	if len(children) > 0 {
		nodeName += "/"
	}
	fmt.Printf("%s%s\n", strings.Repeat(" ", indent), nodeName)
	for _, child := range children {
		printChildrenRecursive(zk, path + "/" + child, indent+2) // RECURSE
	}
	return nil
}

// list <service> <path> -- nested tree
func (cmd *zkHandler) runList(c *kingpin.ParseContext) error {
	zk := cmd.connect()
	defer zk.Close()
	if cmd.recurse {
		err := printChildrenRecursive(zk, cmd.zkPath, 0)
		if err != nil {
			log.Fatalf("Unable to get all recursive children of %s: %s", zk.AbsPath(cmd.zkPath), err)
		}
	} else {
		children, err := zk.Children(cmd.zkPath)
		if err != nil {
			log.Fatalf("Unable to get immediate children of %s: %s", zk.AbsPath(cmd.zkPath), err)
		}
		fmt.Printf("%s/\n", strings.TrimSuffix(cmd.zkPath, "/"))
		for _, child := range children {
			fmt.Printf("  %s\n", child)
		}
	}
	return nil
}

// save <service> <path> -- content
func (cmd *zkHandler) runGet(c *kingpin.ParseContext) error {
	zk := cmd.connect()
	defer zk.Close()
	data, _, err := zk.Get(cmd.zkPath)
	if err != nil {
		log.Fatalf("Unable to get content of %s: %s", zk.AbsPath(cmd.zkPath), err)
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "Received %d bytes from %s\n", len(data), zk.AbsPath(cmd.zkPath))
	}
	if len(cmd.localPath) > 0 {
		err = ioutil.WriteFile(cmd.localPath, data, 0644)
		if err != nil {
			log.Fatalf("Unable to write %d bytes from %s to local file %s: %s",
				len(data), zk.AbsPath(cmd.zkPath), cmd.localPath, err)
		}
	} else if cmd.raw {
		fmt.Print(string(data))
	} else {
		fmt.Printf("%s", string(convertZkToDisk(cmd.zkPath, data)))
	}
	fmt.Fprintf(os.Stderr, "\n")
	return nil
}

// put|set <service> <path> [file] -- confirm/backup/write content
func (cmd *zkHandler) runPut(c *kingpin.ParseContext) error {
	zk := cmd.connect()
	defer zk.Close()
	oldDataZk, version, err := zk.Get(cmd.zkPath)
	if err != nil && err != zklib.ErrNoNode {
		log.Fatalf("Failed to retrieve data from %s: %s", zk.AbsPath(cmd.zkPath), err)
		oldDataZk = nil
	}

	var newDataDisk []byte
	if len(cmd.localPath) > 0 {
		newDataDisk, err = ioutil.ReadFile(cmd.localPath)
		if err != nil {
			log.Fatalf("Failed to access local file %s: %s", cmd.localPath, err)
		}
	} else {
		newDataDisk, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("Failed to read from stdin for zk put. Did you mean to provide a filename to read from?: %s", err)
		}
	}

	var newDataZk []byte
	if cmd.raw {
		newDataZk = newDataDisk
	} else {
		newDataZk = convertDiskToZk(cmd.zkPath, newDataDisk)
	}

	if bytes.Equal(oldDataZk, newDataZk) {
		fmt.Printf("Content of %s matches requested value. Nothing to do, exiting.\n", zk.AbsPath(cmd.zkPath))
		return nil
	}
	fmt.Print(getDiff(cmd.zkPath, zk.AbsPath(cmd.zkPath), oldDataZk, newDataZk))
	if !cmd.force && !confirmationPrompt(fmt.Sprintf("Apply the above changes to %s?", zk.AbsPath(cmd.zkPath))) {
		return nil
	}

	if oldDataZk != nil {
		backupPath, err := backupZkData(zk.AbsPath(cmd.zkPath), oldDataZk)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Backed up previous contents of %s to: %s\n", zk.AbsPath(cmd.zkPath), backupPath)
		_, err = zk.Set(cmd.zkPath, newDataZk, version)
	} else {
		err = zk.Create(cmd.zkPath, newDataZk)
	}
	if err != nil {
		log.Fatalf("Failed to write %d bytes to %s: %s", len(newDataZk), zk.AbsPath(cmd.zkPath), err)
	}

	fmt.Printf("Stored %d bytes in %s.\n", len(newDataZk), zk.AbsPath(cmd.zkPath))
	fmt.Printf("You must restart the '%s' Marathon app for this change to take effect.\n", cmd.service)
	return nil
}

// delete <service> <path> -- confirm/backup/rm nested
func (cmd *zkHandler) runDelete(c *kingpin.ParseContext) error {
	zk := cmd.connect()
	defer zk.Close()

	data, version, err := zk.Get(cmd.zkPath)
	if err != nil {
		if err == zklib.ErrNoNode {
			fmt.Printf("Requested node %s already doesn't exist. Exiting.\n", zk.AbsPath(cmd.zkPath))
			return nil
		}
		log.Fatalf("Failed to retrieve current data from %s (skip read with --force): %s", zk.AbsPath(cmd.zkPath), err)
	}
	fmt.Printf("Current content of %s:\n", cmd.zkPath)
	fmt.Print(convertZkToPrint(cmd.zkPath, data))

	if !cmd.force && !confirmationPrompt(fmt.Sprintf(
		"Delete all data in %s including any nested children?", zk.AbsPath(cmd.zkPath))) {
		return nil
	}

	backupPath, err := backupZkData(zk.AbsPath(cmd.zkPath), data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Backed up previous contents of %s to: %s\n", zk.AbsPath(cmd.zkPath), backupPath)

	err = zk.Delete(cmd.zkPath, version)
	if err != nil {
		log.Fatalf("Failed to delete data from %s: %s", zk.AbsPath(cmd.zkPath), err)
	}
	fmt.Printf("You must restart the '%s' process in Marathon for this change to take effect.\n", cmd.service)
	return nil
}

func confirmationPrompt(message string) bool {
	fmt.Printf("%s (use --force to skip this prompt) [y/N] ", message)
	var response string
	_, err := fmt.Scanln(&response)
	if err != nil {
		fmt.Printf("\n")
		log.Fatalf("Failed to read response. Consider using --force to skip confirmation prompts: %s", err)
	}
	confirmed := len(response) > 0 && (response[0] == 'y' || response[0] == 'Y')
	if confirmed {
		fmt.Printf("Confirmed.\n")
	} else {
		fmt.Printf("Aborted.\n")
	}
	return confirmed
}

func handleZkSection(app *kingpin.Application) {
	// config <list, show, target, target_id>
	cmd := &zkHandler{}
	zk := app.Command("zk", "Access and overwrite zookeeper data")
	// TODO master.mesos:
	zk.Flag("servers", "Zookeeper hostname").Default("localhost:2181").StringsVar(&cmd.servers)
	zk.Flag("service", "DC/OS Service to be operated against").Envar("DCOS_SERVICE").Required().StringVar(&cmd.service)

	listCmd := zk.Command("list", "List entries within a given path").Alias("ls").Action(cmd.runList)
	listCmd.Flag("recursive", "Recurses the full tree").Short('r').BoolVar(&cmd.recurse)
	listCmd.Arg("path", "ZK path to list children of (default: /).").StringVar(&cmd.zkPath)

	getCmd := zk.Command("get", "Downloads the content of a given entry").Action(cmd.runGet)
	getCmd.Flag("raw", "Skips automatic JSON or hexdump conversion").BoolVar(&cmd.raw)
	getCmd.Arg("path", "ZK path to retrieve").Required().StringVar(&cmd.zkPath)
	getCmd.Arg("filepath", "Local to write raw data to (implies --raw)").StringVar(&cmd.localPath)

	putCmd := zk.Command("set", "Stores the content of a file to a given entry, overwriting existing data if any").Alias("put").Action(cmd.runPut)
	putCmd.Flag("force", "Force the operation without confirmation").BoolVar(&cmd.force)
	putCmd.Flag("raw", "Skips automatic conversion from JSON").BoolVar(&cmd.raw)
	putCmd.Arg("path", "ZK path to write or overwrite").Required().StringVar(&cmd.zkPath)
	putCmd.Arg("filepath", "Local file containing data to be written").StringVar(&cmd.localPath)

	deleteCmd := zk.Command("delete", "Deletes a single entry").Action(cmd.runDelete)
	deleteCmd.Flag("force", "Force the operation without confirmation").BoolVar(&cmd.force)
	deleteCmd.Arg("path", "ZK path to delete").Required().StringVar(&cmd.zkPath)
}

func main() {
	app := kingpin.New("podtool", "")
	app.HelpFlag.Short('h') // in addition to default '--help'
	app.Flag("verbose", "Enable extra logging of requests/responses").Short('v').BoolVar(&verbose)

	handleZkSection(app)

	kingpin.MustParse(app.Parse(os.Args[1:]))
}
