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

package kvm

import (
	"strings"
	"math"

	"github.com/coreos/rkt/Godeps/_workspace/src/github.com/appc/spec/schema/types"
)

// FindCapabilities reads all capabilitites from app isolators
// returned int64 contain an information about required capabilities
func FindCapabilities(isolators types.Isolators) (caps int64) {
	for _, i := range isolators {
		switch v := i.Value().(type) {
		case types.LinuxCapabilitiesSet:
			for _, c := range v.Set() {
				caps += encodeCapability(string(c))
			}
			if i.Name != types.LinuxCapabilitiesRetainSetName {
				//revert flags
				caps = int64(math.Pow(2, 35.0)) -1 - caps
			}

		}
	}

	return caps
}
// encodeCapability encode capability
func encodeCapability(cap string) int64 {
	CapNames := []string {
		"cap_chown",
		"cap_dac_override",
		"cap_dac_read_search",
		"cap_fowner",
		"cap_fsetid",
		"cap_kill",
		"cap_setgid",
		"cap_setuid",
		"cap_setpcap",
		"cap_linux_immutable",
		"cap_net_bind_service",
		"cap_net_broadcast",
		"cap_net_admin",
		"cap_net_raw",
		"cap_ipc_lock",
		"cap_ipc_owner",
		"cap_sys_module",
		"cap_sys_rawio",
		"cap_sys_chroot",
		"cap_sys_ptrace",
		"cap_sys_pacct",
		"cap_sys_admin",
		"cap_sys_boot",
		"cap_sys_nice",
		"cap_sys_resource",
		"cap_sys_time",
		"cap_sys_tty_config",
		"cap_mknod",
		"cap_lease",
		"cap_audit_write",
		"cap_audit_control",
		"cap_setfcap",
		"cap_mac_override",
		"cap_mac_admin",
		"cap_syslog",
		}
	for i := 0; i < 35; i++ {
		if strings.EqualFold(cap, CapNames[i]) {
			return int64(math.Pow(2, float64(i)))
		}
	}
	return 0
}	

