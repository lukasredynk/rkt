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
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/coreos/rkt/Godeps/_workspace/src/github.com/steveeJ/gexpect"
)

const (
	noappManifestStr = `{"acKind":"ImageManifest","acVersion":"0.6.1","name":"coreos.com/rkt-inspect","labels":[{"name":"version","value":"1.0.0"},{"name":"arch","value":"amd64"},{"name":"os","value":"linux"}]}`
)

func TestRunOverrideExec(t *testing.T) {
	noappManifestFile := "noapp-manifest.json"
	if err := ioutil.WriteFile(noappManifestFile, []byte(noappManifestStr), 0600); err != nil {
		t.Fatalf("Cannot write noapp manifest: %v", err)
	}
	defer os.Remove(noappManifestFile)
	noappImage := patchTestACI("rkt-image-without-exec.aci", fmt.Sprintf("--manifest=%s", noappManifestFile))
	defer os.Remove(noappImage)
	execImage := patchTestACI("rkt-exec-override.aci", "--exec=/inspect")
	defer os.Remove(execImage)
	ctx := newRktRunCtx()
	defer ctx.cleanup()
	if ctx.getFlavor() == "kvm" {
		t.Skip("TODO: exec not-implemented yet!")
	}

	for _, tt := range []struct {
		rktCmd       string
		expectedLine string
	}{
		{
			// Sanity check - make sure no --exec override prints the expected exec invocation
			rktCmd:       fmt.Sprintf("%s %s %s -- --print-exec", ctx.cmd(), ctx.defaultRunCommand(), execImage),
			expectedLine: "inspect execed as: /inspect",
		},
		{
			// Now test overriding the entrypoint (which is a symlink to /inspect so should behave identically)
			rktCmd:       fmt.Sprintf("%s %s %s --exec /inspect-link -- --print-exec", ctx.cmd(), ctx.defaultRunCommand(), execImage),
			expectedLine: "inspect execed as: /inspect-link",
		},
		{
			// Test overriding the entrypoint with a missing app section
			rktCmd:       fmt.Sprintf("%s --insecure-skip-verify run --mds-register=false %s --exec /inspect -- --print-exec", ctx.cmd(), noappImage),
			expectedLine: "inspect execed as: /inspect",
		},
	} {
		runRktAndCheckOutput(t, tt.rktCmd, tt.expectedLine)
	}
}

func TestRunPreparedOverrideExec(t *testing.T) {
	execImage := patchTestACI("rkt-exec-override.aci", "--exec=/inspect")
	defer os.Remove(execImage)
	ctx := newRktRunCtx()
	defer ctx.cleanup()

	var rktCmd, uuid, expected string

	// Sanity check - make sure no --exec override prints the expected exec invocation
	rktCmd = fmt.Sprintf("%s prepare --insecure-skip-verify %s -- --print-exec", ctx.cmd(), execImage)
	uuid = runRktAndGetUUID(t, rktCmd)

	rktCmd = fmt.Sprintf("%s run-prepared --mds-register=false %s", ctx.cmd(), uuid)
	expected = "inspect execed as: /inspect"
	runRktAndCheckOutput(t, rktCmd, expected)

	// Now test overriding the entrypoint (which is a symlink to /inspect so should behave identically)
	rktCmd = fmt.Sprintf("%s prepare --insecure-skip-verify %s --exec /inspect-link -- --print-exec", ctx.cmd(), execImage)
	uuid = runRktAndGetUUID(t, rktCmd)

	rktCmd = fmt.Sprintf("%s run-prepared --mds-register=false %s", ctx.cmd(), uuid)
	expected = "inspect execed as: /inspect-link"
	runRktAndCheckOutput(t, rktCmd, expected)
}

func runRktAndCheckOutput(t *testing.T, rktCmd, expectedLine string) {
	child, err := gexpect.Spawn(rktCmd)
	if err != nil {
		t.Fatalf("cannot exec rkt: %v", err)
	}

	if err = expectWithOutput(child, expectedLine); err != nil {
		t.Fatalf("didn't receive expected output %q: %v", expectedLine, err)
	}

	if err = child.Wait(); err != nil {
		t.Fatalf("rkt didn't terminate correctly: %v", err)
	}
}
