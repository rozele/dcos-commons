package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/user"
	"path"
	"sort"
	"strings"
	"time"
)

// Path (within user's HOME) where backups are stored
const backupDirSuffix = ".podtool/backup/"

// ZK limits nodes to 1MB
const maxZkNodeSize = 1024 * 1024

// Limit to most recent 100 items
// (combined with the above, this means a theoretical max size of 100MB)
const maxBackupCount = 100

func backupDir() (string, error) {
	// Allow customizing backup directory if e.g. we're unable to write to the default location.
	envsetting := os.Getenv("BACKUP_DIR")
	if len(envsetting) > 0 {
		return envsetting, nil
	}

	// Default: a directory within HOME
	curuser, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("Unable to determine current user: %s", err)
	}
	if len(curuser.HomeDir) == 0 {
		return "", fmt.Errorf("User %v+ lacks a home directory for storing backups. Refusing to delete data without backups.", curuser)
	}
	return path.Join(curuser.HomeDir, backupDirSuffix), nil
}

// Utility for sorting FileInfos from newest to oldest
type sortByMtimeIncreasing []os.FileInfo

func (s sortByMtimeIncreasing) Len() int {
	return len(s)
}
func (s sortByMtimeIncreasing) Swap(i int, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s sortByMtimeIncreasing) Less(i int, j int) bool {
	//TODO is this right? (or should it be After()?)
	return s[i].ModTime().Before(s[j].ModTime())
}

// Deletes files in backup directory to fit maxBackupCount
func pruneDir(dir string) error {
	backupFiles, err := ioutil.ReadDir(dir)
	if err != nil {
		// Note: directory should exist at this point as we're being called after a backup was written
		return fmt.Errorf("Unable to list contents of backup directory %s: %s", dir, err)
	}
	regularFiles := make([]os.FileInfo, 0)
	for _, backupFile := range backupFiles {
		if !backupFile.Mode().IsRegular() {
			continue
		}
		regularFiles = append(regularFiles, backupFile)
	}
	sort.Sort(sortByMtimeIncreasing(regularFiles))
	for len(regularFiles) > maxBackupCount {
		filePath := path.Join(dir, regularFiles[0].Name())
		err = os.Remove(filePath)
		if err != nil {
			return fmt.Errorf("Unable to prune old backup file %s: %s", filePath, err)
		}
		regularFiles = regularFiles[1:]
	}
	return nil
}

// Backs up the provided content to a backup directory
func backupZkData(absZkPath string, data []byte) (string, error) {
	dir, err := backupDir()
	if err != nil {
		return "", fmt.Errorf("Unable to determine backup directory: %s", err)
	}

	randBytes := make([]byte, 4)
	_, err = rand.Read(randBytes)
	if err != nil {
		return "", fmt.Errorf("Unable to get random data for backup filename: %s", err)
	}

	outFilename := fmt.Sprintf("%s_%s_%s.bak",
		strings.Replace(strings.TrimLeft(absZkPath, "/"), "/", "-", -1),
		time.Now().Format("20060102-150405"), // YYYYMMDD-HHMMSS
		hex.EncodeToString(randBytes))
	outFilepath := path.Join(dir, outFilename)

	err = os.MkdirAll(dir, 0700)
	if err != nil {
		return "", fmt.Errorf("Unable to initialize backup directory %s. Refusing to continue without backup destination.", err)
	}

	err = ioutil.WriteFile(outFilepath, data, 0600)
	if err != nil {
		return "", fmt.Errorf("Unable to write backup of %d bytes from %s to %s: %s", len(data), absZkPath, outFilepath, err)
	}

	err = pruneDir(dir)
	if err != nil {
		return "", fmt.Errorf("Failed to prune backup directory %s: %s", dir, err)
	}

	return outFilepath, nil
}
