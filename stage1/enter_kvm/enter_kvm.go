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
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"github.com/coreos/rkt/Godeps/_workspace/src/golang.org/x/crypto/ssh"

	"github.com/coreos/rkt/common"
	"github.com/coreos/rkt/networking/netinfo"
	"github.com/coreos/rkt/pkg/lock"
)

const (
	kvmSettingsDir            = "/var/lib/rkt-stage1-kvm"
	kvmPrivateKeyFilenamePath = "/var/lib/rkt-stage1-kvm/ssh_kvm_key"
	kvmPublicKeyFilenamePath  = "/var/lib/rkt-stage1-kvm/ssh_kvm_key.pub"
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

// generateKeyPair calls ssh-keygen with private key location for key generation purpose
func generateKeyPair() error {
	if err := os.MkdirAll(kvmSettingsDir, 0700); err != nil {
		return err
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return err
	}
	privateKeyRaw := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyRaw,
	}
	privateKeyPem := pem.EncodeToMemory(&privateKeyBlock)

	err = ioutil.WriteFile(kvmPrivateKeyFilenamePath, privateKeyPem, 0600)
	if err != nil {
		return fmt.Errorf("error in keygen private key. ret_val: %v", err)
	}

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	marshaledPubKey := ssh.MarshalAuthorizedKey(publicKey)
	err = ioutil.WriteFile(kvmPublicKeyFilenamePath, marshaledPubKey, 0644)
	if err != nil {
		return fmt.Errorf("error in keygen public key. ret_val: %v", err)
	}

	return nil
}

func ensureAuthorizedKeysExist(workDir string) error {
	destRootfs := common.Stage1RootfsPath(workDir)
	keyDirPath := filepath.Join(destRootfs, u.HomeDir, "/.ssh")
	if err := os.MkdirAll(keyDirPath, 0700); err != nil {
		return err
	}
	authorizedKeysFile := filepath.Join(keyDirPath, "authorized_keys")
	if _, err := os.Stat(authorizedKeysFile); os.IsNotExist(err) {
		buf, err := ioutil.ReadFile(kvmPublicKeyFilenamePath)
		err = ioutil.WriteFile(authorizedKeysFile, buf, 0644)
		if err != nil {
			return fmt.Errorf("error during copy authorized_keys. ret_val: %v", err)
		}
	}
	return nil
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
		u.Uid, // uid
		u.Gid, // gid
	}
	args = append(args, flag.Args()...)
	return strings.Join(args, " ")
}

func getKeyFile(key *ssh.Signer) (err error) {
	if _, err := os.Stat(kvmPrivateKeyFilenamePath); os.IsNotExist(err) {
		generateKeyPair()
	}
	buf, err := ioutil.ReadFile(kvmPrivateKeyFilenamePath)
	*key, err = ssh.ParsePrivateKey(buf)
	return
}

func execSSH() error {
	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("cannot get working directory: %v", err)
	}

	podDefaultIP, err := getPodDefaultIP(workDir)
	if err != nil {
		return fmt.Errorf("cannot load networking configuration: %v", err)
	}

	var key ssh.Signer
	if err = getKeyFile(&key); err != nil {
		return fmt.Errorf("error setting up ssh keys on host: %v", err)
	}

	if err := ensureAuthorizedKeysExist(workDir); err != nil {
		return fmt.Errorf("error setting up ssh keys on pod: %v", err)
	}

	config := &ssh.ClientConfig{
		User: u.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
	}

	client, err := ssh.Dial("tcp", podDefaultIP+":"+kvmSSHPort, config)
	if err != nil {
		return fmt.Errorf("Failed to dial: %v", err)
	}
	// escape from running pod directory into base directory

	session, err := client.NewSession()
	defer session.Close()
	if err != nil {
		return fmt.Errorf("Failed to create session: %v", err)
	} else {
		for _, e := range os.Environ() {
			pair := strings.Split(e, "=")
			session.Setenv(pair[0], pair[1])
		}
	}
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.ECHOCTL:       0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		return fmt.Errorf("request for pseudo terminal failed: %v", err)
	}

	cmd := getAppexecArgs()
	if err = session.Run(cmd); err != nil {
		return fmt.Errorf("cannot enter through ssh: %v", err)
	}

	return nil
}

func main() {
	flag.Parse()
	if appName == "" {
		fmt.Fprintf(os.Stderr, "--appname not set to correct value\n")
		os.Exit(1)
	}

	// execSSH should returns only with error
	if err := execSSH(); err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}
