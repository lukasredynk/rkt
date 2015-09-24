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
	"log"
	"strings"
	"testing"

	"github.com/coreos/rkt/Godeps/_workspace/src/github.com/steveeJ/gexpect"
)

var envTests = []struct {
	runCmd    string
	runExpect string
	sleepCmd  string
	enterCmd  string
}{
	{
		`^RKT_BIN^  ^RUN_CMD^ ^PRINT_VAR_FROM_MANIFEST^`,
		"VAR_FROM_MANIFEST=manifest",
		`^RKT_BIN^  ^RUN_CMD^ --interactive ^SLEEP^`,
		`/bin/sh -c "^RKT_BIN^  enter $(^RKT_BIN^ list --full|grep running|awk '{print $1}') /inspect --print-env=VAR_FROM_MANIFEST"`,
	},
	{
		`^RKT_BIN^ --debug ^RUN_CMD^ --set-env=VAR_OTHER=setenv ^PRINT_VAR_OTHER^`,
		"VAR_OTHER=setenv",
		`^RKT_BIN^ --debug ^RUN_CMD^ --interactive --set-env=VAR_OTHER=setenv ^SLEEP^`,
		`/bin/sh -c "^RKT_BIN^ --debug enter $(^RKT_BIN^ list --full|grep running|awk '{print $1}') /inspect --print-env=VAR_OTHER"`,
	},
	{
		`^RKT_BIN^ --debug ^RUN_CMD^ --set-env=VAR_FROM_MANIFEST=setenv ^PRINT_VAR_FROM_MANIFEST^`,
		"VAR_FROM_MANIFEST=setenv",
		`^RKT_BIN^ --debug ^RUN_CMD^ --interactive --set-env=VAR_FROM_MANIFEST=setenv ^SLEEP^`,
		`/bin/sh -c "^RKT_BIN^ --debug enter $(^RKT_BIN^ list --full|grep running|awk '{print $1}') /inspect --print-env=VAR_FROM_MANIFEST"`,
	},
	{
		`/bin/sh -c "export VAR_OTHER=host ; ^RKT_BIN^ --debug ^RUN_CMD^ --inherit-env=true ^PRINT_VAR_OTHER^"`,
		"VAR_OTHER=host",
		`/bin/sh -c "export VAR_OTHER=host ; ^RKT_BIN^ --debug ^RUN_CMD^ --interactive --inherit-env=true ^SLEEP^"`,
		`/bin/sh -c "export VAR_OTHER=host ; ^RKT_BIN^ --debug enter $(^RKT_BIN^ list --full|grep running|awk '{print $1}') /inspect --print-env=VAR_OTHER"`,
	},
	{
		`/bin/sh -c "export VAR_FROM_MANIFEST=host ; ^RKT_BIN^ --debug ^RUN_CMD^ --inherit-env=true ^PRINT_VAR_FROM_MANIFEST^"`,
		"VAR_FROM_MANIFEST=manifest",
		`/bin/sh -c "export VAR_FROM_MANIFEST=host ; ^RKT_BIN^ --debug ^RUN_CMD^ --interactive --inherit-env=true ^SLEEP^"`,
		`/bin/sh -c "export VAR_FROM_MANIFEST=host ; ^RKT_BIN^ --debug enter $(^RKT_BIN^ list --full|grep running|awk '{print $1}') /inspect --print-env=VAR_FROM_MANIFEST"`,
	},
	{
		`/bin/sh -c "export VAR_OTHER=host ; ^RKT_BIN^ --debug ^RUN_CMD^ --inherit-env=true --set-env=VAR_OTHER=setenv ^PRINT_VAR_OTHER^"`,
		"VAR_OTHER=setenv",
		`/bin/sh -c "export VAR_OTHER=host ; ^RKT_BIN^ --debug ^RUN_CMD^ --interactive --inherit-env=true --set-env=VAR_OTHER=setenv ^SLEEP^"`,
		`/bin/sh -c "export VAR_OTHER=host ; ^RKT_BIN^ --debug enter $(^RKT_BIN^ list --full|grep running|awk '{print $1}') /inspect --print-env=VAR_OTHER"`,
	},
}

func TestEnv(t *testing.T) {
	printVarFromManifestImage := patchTestACI("rkt-inspect-print-var-from-manifest.aci", "--exec=/inspect --print-env=VAR_FROM_MANIFEST")
	// defer os.Remove(printVarFromManifestImage)
	printVarOtherImage := patchTestACI("rkt-inspect-print-var-other.aci", "--exec=/inspect --print-env=VAR_OTHER")
	// defer os.Remove(printVarOtherImage)
	sleepImage := patchTestACI("rkt-inspect-sleep.aci", "--exec=/inspect --read-stdin")
	// defer os.Remove(sleepImage)
	ctx := newRktRunCtx()
	// defer ctx.cleanup()

	replacePlaceholders := func(cmd string) string {
		fixed := cmd
		fixed = strings.Replace(fixed, "^RKT_BIN^", ctx.cmd(), -1)
		fixed = strings.Replace(fixed, "^PRINT_VAR_FROM_MANIFEST^", printVarFromManifestImage, -1)
		fixed = strings.Replace(fixed, "^PRINT_VAR_OTHER^", printVarOtherImage, -1)
		fixed = strings.Replace(fixed, "^SLEEP^", sleepImage, -1)
		fixed = strings.Replace(fixed, "^RUN_CMD^", ctx.defaultRunCommand(), -1)
		return fixed
	}
	for i, tt := range envTests {
		// 'run' tests
		/*
			runCmd := replacePlaceholders(tt.runCmd)
			log.Printf("Running 'run' test #%v: %v\n\n", i, runCmd)
			child, err := gexpect.Spawn(runCmd)
			if err != nil {
				t.Fatalf("Cannot exec rkt #%v: %v", i, err)
			}

			err = expectWithOutput(child, tt.runExpect)
			if err != nil {
				t.Fatalf("Expected %q but not found: %v", tt.runExpect, err)
			}

			err = child.Wait()
			if err != nil {
				t.Fatalf("rkt didn't terminate correctly: %v", err)
			}
		*/

		// 'enter' tests
		sleepCmd := replacePlaceholders(tt.sleepCmd)
		log.Printf("Running 'enter' test #%v: sleep: %v\n\n", i, sleepCmd)
		child, err := gexpect.Spawn(sleepCmd)
		if err != nil {
			t.Fatalf("Cannot exec rkt #%v: %v", i, err)
		}

		err = expectWithOutput(child, "Enter text:")
		if err != nil {
			t.Fatalf("Waited for the prompt but not found #%v: %v", i, err)
		}
		// sshd needs a time to boot up!
		// time.Sleep(5 * time.Second)

		enterCmd := replacePlaceholders(tt.enterCmd)
		log.Printf("Running 'enter' test #%v: enter: %v\n\n", i, enterCmd)
		enterChild, err := gexpect.Spawn(enterCmd)
		if err != nil {
			t.Fatalf("Cannot exec rkt #%v: %v", i, err)
		}

		err = expectWithOutput(enterChild, tt.runExpect)
		if err != nil {
			t.Fatalf("Expected %q but not found: %v", tt.runExpect, err)
		}

		err = enterChild.Wait()
		if err != nil {
			t.Fatalf("rkt didn't terminate correctly: %v", err)
		}
		err = child.SendLine("Bye")
		if err != nil {
			t.Fatalf("rkt couldn't write to the container: %v", err)
		}
		err = expectWithOutput(child, "Received text: Bye")
		if err != nil {
			t.Fatalf("Expected Bye but not found #%v: %v", i, err)
		}

		err = child.Wait()
		if err != nil {
			t.Fatalf("rkt didn't terminate correctly: %v", err)
		}
		ctx.reset()
	}
}
