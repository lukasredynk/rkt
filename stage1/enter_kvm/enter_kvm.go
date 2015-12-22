// Copyright 2015 The rkt Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/dsa"
	"crypto/rand"
	"encoding/gob"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/coreos/rkt/common"
	"github.com/coreos/rkt/networking/netinfo"
	"github.com/coreos/rkt/pkg/lock"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
)

const (
	kvmSettingsDir        = "/var/lib/rkt-stage1-kvm"
	kvmPrivateKeyFilename = "ssh_kvm_key"
	// TODO: overwrite below default by environment value + generate .socket unit just before pod start
	kvmSSHPort = "122" // hardcoded value in .socket file
)

var (
	podPid  string
	appName string
	u, _    = user.Current()
)

func init() {
	flag.StringVar(&podPid, "pid", "", "podPID")
	flag.StringVar(&appName, "appname", "", "application to use")
}

// fileAccessible checks if the given path exists and is a regular file
func fileAccessible(path string) bool {
	if info, err := os.Stat(path); err == nil {
		return info.Mode().IsRegular()
	}
	return false
}

func sshPrivateKeyPath() string {
	return filepath.Join(kvmSettingsDir, kvmPrivateKeyFilename)
}

func sshPublicKeyPath() string {
	return sshPrivateKeyPath() + ".pub"
}

// generateKeyPair calls ssh-keygen with private key location for key generation purpose
func generateKeyPair(private string) error {
	params := new(dsa.Parameters)
	if err := dsa.GenerateParameters(params, rand.Reader, dsa.L1024N160); err != nil {
		return fmt.Errorf("error in generate params for keys. ret_val: %v", err)
	}
	privateKey := new(dsa.PrivateKey)
	privateKey.PublicKey.Parameters = *params
	dsa.GenerateKey(privateKey, rand.Reader) // Generate public and private keys
	publicKey := privateKey.PublicKey

	privateKeyFile, err := os.Create(sshPrivateKeyPath())
	if err != nil {
		return fmt.Errorf("error in keygen private key. ret_val: %v", err)
	}

	gob.NewEncoder(privateKeyFile).Encode(privateKey)
	defer privateKeyFile.Close()

	publicKeyFile, err := os.Create(sshPublicKeyPath())
	if err != nil {
		return fmt.Errorf("error in keygen public key. ret_val: %v", err)
	}
	gob.NewEncoder(publicKeyFile).Encode(publicKey)
	defer publicKeyFile.Close()

	return nil
}

func ensureKeysExistOnHost() error {
	private, public := sshPrivateKeyPath(), sshPublicKeyPath()
	if !fileAccessible(private) || !fileAccessible(public) {
		if err := os.MkdirAll(kvmSettingsDir, 0700); err != nil {
			return err
		}

		if err := generateKeyPair(private); err != nil {
			return err
		}
	}
	return nil
}

func ensureAuthorizedKeysExist(keyDirPath string) error {
	fout, err := os.OpenFile(
		filepath.Join(keyDirPath, "/authorized_keys"),
		os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
		0600,
	)
	if err != nil {
		return err
	}
	defer fout.Close()

	fin, err := os.Open(sshPublicKeyPath())
	if err != nil {
		return err
	}
	defer fin.Close()

	if _, err := io.Copy(fout, fin); err != nil {
		return err
	}
	return fout.Sync()
}

func ensureKeysExistInPod(workDir string) error {
	destRootfs := common.Stage1RootfsPath(workDir)
	keyDirPath := filepath.Join(destRootfs, u.HomeDir, "/.ssh")
	if err := os.MkdirAll(keyDirPath, 0700); err != nil {
		return err
	}
	return ensureAuthorizedKeysExist(keyDirPath)
}

func kvmCheckSSHSetup(workDir string) error {
	if err := ensureKeysExistOnHost(); err != nil {
		return err
	}
	return ensureKeysExistInPod(workDir)
}

func getPodDefaultIP(workDir string) (string, error) {
	// get pod lock
	l, err := lock.NewLock(workDir, lock.Dir)
	if err != nil {
		return "", err
	}

	// get file descriptor for lock
	fd, err := l.Fd()
	if err != nil {
		return "", err
	}

	// use this descriptor as method of reading pod network configuration
	nets, err := netinfo.LoadAt(fd)
	if err != nil {
		return "", err
	}
	// kvm flavored container must have at first position default vm<->host network
	if len(nets) == 0 {
		return "", fmt.Errorf("pod has no configured networks")
	}

	for _, net := range nets {
		if net.NetName == "default" || net.NetName == "default-restricted" {
			return net.IP.String(), nil
		}
	}

	return "", fmt.Errorf("pod has no default network!")
}

func getAppexecArgs() string {
	// Documentation/devel/stage1-implementors-guide.md#arguments-1
	// also from ../enter/enter.c
	args := []string{
		"/appexec",
		fmt.Sprintf("/opt/stage2/%s/rootfs", appName),
		"/", // as in ../enter/enter.c - this should be app.WorkingDirectory
		fmt.Sprintf("/rkt/env/%s", appName),
		string(u.Uid), // uid
		string(u.Gid), // gid
	}
	return strings.Join(append(args, flag.Args()...), " ")
}

func getKeyFile() (key ssh.Signer, err error) {
	buf, err := ioutil.ReadFile(sshPrivateKeyPath())
	if err != nil {
		return
	}
	key, err = ssh.ParsePrivateKey(buf)
	if err != nil {
		return
	}
	return
}

func execSSH() error {
	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("cannot get working directory: %v", err)
	}

	if err := kvmCheckSSHSetup(workDir); err != nil {
		return fmt.Errorf("error setting up ssh keys: %v", err)
	}

	podDefaultIP, err := getPodDefaultIP(workDir)
	if err != nil {
		return fmt.Errorf("cannot load networking configuration: %v", err)
	}

	var key ssh.Signer
	if key, err = getKeyFile(); err != nil {
		return fmt.Errorf("error setting up ssh keys: %v", err)
	}

	config := &ssh.ClientConfig{
		User: u.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
	}
	client, err := ssh.Dial("tcp", strings.Join([]string{podDefaultIP, kvmSSHPort}, ":"), config)
	if err != nil {
		return fmt.Errorf("Failed to dial: %v", err)
	}

	session, err := client.NewSession()
	defer session.Close()
	if err != nil {
		return fmt.Errorf("Failed to create session: %v", err)
	} else {
		for _, v := range os.Environ() {
			session.Setenv(string(v[0]), string(v[1]))
		}
		err = session.Run(getAppexecArgs())
	}

	return fmt.Errorf("cannot enter through ssh: %v", err)
}

func main() {
	flag.Parse()
	if appName == "" {
		fmt.Fprintf(os.Stderr, "--appname not set to correct value\n")
		os.Exit(1)
	}

	// execSSH should returns only with error
	fmt.Fprintf(os.Stderr, "%v\n", execSSH())
	os.Exit(2)
}
