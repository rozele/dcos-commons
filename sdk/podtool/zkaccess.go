package main

import (
	"fmt"
	"github.com/samuel/go-zookeeper/zk"
	"strings"
	"time"
)

const ZkNoVersion int32 = -1

type ZkAccess struct {
	c    *zk.Conn
	root string
}

type noopLogger struct {}
func (noopLogger) Printf(format string, a ...interface{}) { }

func ZkConnect(service string, servers []string, verbose bool) (*ZkAccess, error) {
	c, _, err := zk.Connect(servers, time.Second*10)
	if err != nil {
		return nil, err
	}
	if !verbose {
		// ZK library is noisy by default. Pass it a noop logger to keep it quiet:
		c.SetLogger(&noopLogger{})
	}
	return &ZkAccess{
		c:    c,
		root: fmt.Sprintf("/dcos-service-%s", strings.Replace(service, "/", "__", -1)),
	}, nil
}

func (z *ZkAccess) AbsPath(path string) string {
	// Note: ZK doesn't support '..' so we can avoid worrying about that here.
	if len(path) == 0 {
		return z.root
	}
	// Trailing '/' is also undesirable: ZK dislikes it
	return z.root + "/" + strings.Trim(path, "/")
}

func (z *ZkAccess) Close() {
	z.c.Close()
}

func (z *ZkAccess) Children(path string) ([]string, error) {
	children, _, err := z.c.Children(z.AbsPath(path))
	return children, err
}

func (z *ZkAccess) Get(path string) ([]byte, int32, error) {
	data, stat, err := z.c.Get(z.AbsPath(path))
	if err != nil {
		return nil, ZkNoVersion, err
	}
	return data, stat.Version, err
}

func (z *ZkAccess) Set(path string, data []byte, version int32) (int32, error) {
	stat, err := z.c.Set(z.AbsPath(path), data, version)
	if err != nil {
		return ZkNoVersion, err
	}
	return stat.Version, err
}

func (z *ZkAccess) Create(path string, data []byte) error {
	_, err := z.c.Create(z.AbsPath(path), data, 0, zk.WorldACL(zk.PermAll))
	return err
}

func (z *ZkAccess) SetForce(path string, data []byte) (int32, error) {
	return z.Set(path, data, ZkNoVersion)
}

func (z *ZkAccess) Delete(path string, version int32) error {
	return z.c.Delete(z.AbsPath(path), version)
}
