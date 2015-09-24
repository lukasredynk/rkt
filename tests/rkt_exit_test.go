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
	"os"
	"testing"

	"github.com/coreos/rkt/Godeps/_workspace/src/github.com/steveeJ/gexpect"
)

func TestExitCode(t *testing.T) {
	for i := 0; i < 3; i++ {
		t.Logf("%d\n", i)
		imageFile := patchTestACI("rkt-inspect-exit.aci", fmt.Sprintf("--exec=/inspect --print-msg=Hello --exit-code=%d", i))
		defer os.Remove(imageFile)
		ctx := newRktRunCtx()
		defer ctx.cleanup()

		cmd := fmt.Sprintf(`/bin/sh -c "`+
			`%s --debug %s %s ;`+
			`UUID=$(%s list --full|grep exited|awk '{print $1}') ;`+
			`echo -n 'status=' ;`+
			`%s status $UUID|grep '^app-rkt-inspect.*=[0-9]*$'|cut -d= -f2"`,
			ctx.cmd(), ctx.defaultRunCommand(), imageFile,
			ctx.cmd(),
			ctx.cmd())
		t.Logf("%s\n", cmd)
		child, err := gexpect.Spawn(cmd)
		if err != nil {
			t.Fatalf("Cannot exec rkt")
		}

		err = expectWithOutput(child, fmt.Sprintf("status=%d", i))
		if err != nil {
			t.Fatalf("Failed to get the status: %v", err)
		}

		err = child.Wait()
		if err != nil {
			t.Fatalf("rkt didn't terminate correctly: %v", err)
		}
	}
}
