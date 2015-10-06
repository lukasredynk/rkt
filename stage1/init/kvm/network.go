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
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"path/filepath"

	"github.com/coreos/rkt/networking"

	"github.com/coreos/rkt/Godeps/_workspace/src/github.com/appc/cni/pkg/types"
	"github.com/coreos/rkt/Godeps/_workspace/src/github.com/coreos/go-systemd/unit"
)

// GetNetworkDescriptions explicitly convert slice of activeNets to slice of netDescribers
// which is slice required by GetKVMNetArgs
func GetNetworkDescriptions(n *networking.Networking) []netDescriber {
	nds := []netDescriber{}
	for _, an := range n.GetActiveNetworks() {
		nds = append(nds, an)
	}
	return nds
}

// netDescriber is something that describes network configuration
type netDescriber interface {
	GuestIP() net.IP
	Mask() net.IP
	IfName() string
	IPMasq() bool
	Name() string
	Gateway() net.IP
	Routes() []types.Route
}

// GetKVMNetArgs returns additional arguments that need to be passed
// to lkvm tool to configure networks properly.
// Logic is based on Network configuration extracted from Networking struct
// and essentially from activeNets that expose netDescriber behavior
func GetKVMNetArgs(nds []netDescriber) ([]string, error) {

	lkvmArgs := []string{}

	for _, nd := range nds {
		lkvmArgs = append(lkvmArgs, "--network")
		lkvmArg := fmt.Sprintf("mode=tap,tapif=%s,host_ip=%s,guest_ip=%s", nd.IfName(), nd.Gateway(), nd.GuestIP())
		lkvmArgs = append(lkvmArgs, lkvmArg)
	}

	return lkvmArgs, nil
}

func generateMacAddress() (net.HardwareAddr, error) {
	mac := make([]byte, 6)
	_, err := rand.Read(mac)
	if err != nil {
		return nil, fmt.Errorf("cannot generate random mac address: %v", err)
	}

	mac[0] = 2
	mac[1] = 21
	mac[2] = 21
	return mac, nil
}

func setMacCommand(ifName, mac string) string {
	return fmt.Sprintf("/bin/ip l set dev %s address %s", ifName, mac)
}

func addAddressCommand(address, ifName string) string {
	return fmt.Sprintf("/bin/ip a a %s dev %s", address, ifName)
}

func addRouteCommand(destination, router string) string {
	return fmt.Sprintf("/bin/ip r a %s via %s", destination, router)
}

func downInterfaceCommand(ifName string) string {
	return fmt.Sprintf("/bin/ip l se dev %s down", ifName)
}

func upInterfaceCommand(ifName string) string {
	return fmt.Sprintf("/bin/ip l se dev %s up", ifName)
}

func GenerateNetworkInterfaceUnits(unitsPath string, netDescriptions []netDescriber) error {

	for i, netDescription := range netDescriptions {
		ifName := fmt.Sprintf(networking.IfNamePattern, i)
		netAddress := net.IPNet{
			IP:   netDescription.GuestIP(),
			Mask: net.IPMask(netDescription.Mask()),
		}

		address := netAddress.String()

		mac, err := generateMacAddress()
		if err != nil {
			return err
		}

		opts := []*unit.UnitOption{
			unit.NewUnitOption("Unit", "Description", fmt.Sprintf("Network configuration for device: %v", ifName)),
			unit.NewUnitOption("Unit", "DefaultDependencies", "false"),
			unit.NewUnitOption("Service", "Type", "oneshot"),
			unit.NewUnitOption("Service", "RemainAfterExit", "true"),
			unit.NewUnitOption("Service", "ExecStartPre", downInterfaceCommand(ifName)),
			unit.NewUnitOption("Service", "ExecStartPre", setMacCommand(ifName, mac.String())),
			unit.NewUnitOption("Service", "ExecStartPre", upInterfaceCommand(ifName)),
			unit.NewUnitOption("Service", "ExecStart", addAddressCommand(address, ifName)),
			unit.NewUnitOption("Install", "RequiredBy", "default.target"),
		}

		for _, route := range netDescription.Routes() {
			gw := route.GW
			if gw == nil {
				gw = netDescription.Gateway()
			}

			opts = append(
				opts,
				unit.NewUnitOption(
					"Service",
					"ExecStartPost",
					addRouteCommand(route.Dst.String(), gw.String()),
				),
			)
		}

		unitName := unit.UnitNamePathEscape(fmt.Sprintf("interface-%s", ifName) + ".service")
		unitBytes, err := ioutil.ReadAll(unit.Serialize(opts))
		if err != nil {
			return fmt.Errorf("failed to serialize network unit file to bytes %q: %v", unitName, err)
		}

		err = ioutil.WriteFile(filepath.Join(unitsPath, unitName), unitBytes, 0644)
		if err != nil {
			return fmt.Errorf("failed to create network unit file %q: %v", unitName, err)
		}

		log.Printf("network unit created: %q in %q (iface=%q, addr=%q)", unitName, unitsPath, ifName, address)
	}
	return nil
}
