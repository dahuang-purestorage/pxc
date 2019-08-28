/*
Copyright © 2019 Portworx

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package portworx

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	api "github.com/libopenstorage/openstorage-sdk-clients/sdk/golang"
	"github.com/stretchr/testify/assert"
)

var (
	attachedState = map[string]string{
		"pvc-34d0f15c-65b9-4229-8b3e-b7bb912e382f": "on ip-70-0-87-200.brbnca.spcsdns.net",
		"tp2": "Detached",
		"pvc-6fc1fe2d-25f4-40b0-a616-04c019572154": "on ip-70-0-87-200.brbnca.spcsdns.net",
		"tp3":      "on ip-70-0-87-200.brbnca.spcsdns.net",
		"tp1":      "Detached",
		"tp2-snap": "Detached",
	}

	podToVolume = map[string]string{
		"wordpress-mysql-684ddbbb55-zjs7b": "pvc-6fc1fe2d-25f4-40b0-a616-04c019572154",
		"wordpress-7f6d665c6f-5wpm6":       "pvc-34d0f15c-65b9-4229-8b3e-b7bb912e382f",
		"wordpress-7f6d665c6f-7qcch":       "pvc-34d0f15c-65b9-4229-8b3e-b7bb912e382f",
		"wordpress-7f6d665c6f-ddjj6":       "pvc-34d0f15c-65b9-4229-8b3e-b7bb912e382f",
	}

	volumeToReplicationInfo = map[string]string{
		`tp1`:      `{"Rsi":[{"Id":0,"NodeInfo":["ip-70-0-87-200.brbnca.spcsdns.net (Pool 0)"],"HaIncrease":"","ReAddOn":[]}],"Status":"Detached"}`,
		`tp2`:      `{"Rsi":[{"Id":0,"NodeInfo":["ip-70-0-87-200.brbnca.spcsdns.net (Pool 1)"],"HaIncrease":"","ReAddOn":[]},{"Id":1,"NodeInfo":["ip-70-0-87-203.brbnca.spcsdns.net (Pool 1)"],"HaIncrease":"","ReAddOn":[]}],"Status":"UP"}`,
		`tp2-snap`: `{"Rsi":[{"Id":0,"NodeInfo":["ip-70-0-87-200.brbnca.spcsdns.net (Pool 1)"],"HaIncrease":"","ReAddOn":[]},{"Id":1,"NodeInfo":["ip-70-0-87-203.brbnca.spcsdns.net (Pool 1)"],"HaIncrease":"","ReAddOn":[]}],"Status":"Detached"}`,
		`pvc-6fc1fe2d-25f4-40b0-a616-04c019572154`: `{"Rsi":[{"Id":0,"NodeInfo":["ip-70-0-87-200.brbnca.spcsdns.net (Pool 1)","ip-70-0-87-203.brbnca.spcsdns.net (Pool 1)"],"HaIncrease":"","ReAddOn":[]}],"Status":"UP"}`,
		`tp3`: `{"Rsi":[{"Id":0,"NodeInfo":["ip-70-0-87-233.brbnca.spcsdns.net (Pool 0)"],"HaIncrease":"","ReAddOn":[]},{"Id":1,"NodeInfo":["ip-70-0-87-200.brbnca.spcsdns.net (Pool 1)"],"HaIncrease":"","ReAddOn":[]},{"Id":2,"NodeInfo":["ip-70-0-87-203.brbnca.spcsdns.net (Pool 0)"],"HaIncrease":"","ReAddOn":[]}],"Status":"UP"}`,
		`pvc-34d0f15c-65b9-4229-8b3e-b7bb912e382f`: `{"Rsi":[{"Id":0,"NodeInfo":["ip-70-0-87-200.brbnca.spcsdns.net (Pool 1)","ip-70-0-87-233.brbnca.spcsdns.net (Pool 1)"],"HaIncrease":"","ReAddOn":[]}],"Status":"UP"}`,
	}

	pvcInfo = map[string]string{
		"pvc-6fc1fe2d-25f4-40b0-a616-04c019572154": "mysql-pvc-1",
		"pvc-34d0f15c-65b9-4229-8b3e-b7bb912e382f": "wp-pv-claim",
	}

	expectedNodes = []string{
		"ip-70-0-87-233.brbnca.spcsdns.net",
		"ip-70-0-87-200.brbnca.spcsdns.net",
		"ip-70-0-87-203.brbnca.spcsdns.net",
	}
)

func testGetPxVolumeOps(t *testing.T) PxVolumeOps {
	volOps := &pxVolumeOps{}
	// Fill the PxVolumeOps with dummy data
	// so we  dont need connections to pxc and k8s
	// We can test all public interfaces of PxVolumeOps except for GetStats
	err := json.Unmarshal([]byte(dummyInputJson), volOps)
	assert.Equal(t, err, nil, "Error Unmarshalling string")
	return volOps
}

func testPxVolumeOps(t *testing.T, volOps PxVolumeOps, v *api.Volume) {
	name := v.GetLocator().GetName()
	state, err := volOps.GetAttachedState(v)
	assert.Equal(t, err, nil, "Got error getting attached state")
	expectedState := attachedState[name]
	assert.Equalf(t, state, expectedState, "Attached state is not correct for %s", name)
	pods, err := volOps.PodsUsingVolume(v)
	assert.Equal(t, err, nil, "Got error getting pods using volume")
	for _, pod := range pods {
		vn := podToVolume[pod.Name]
		assert.Equalf(t, vn, name, "%s should be using %s", pod.Name, name)
	}
	replInfo, err := volOps.GetReplicationInfo(v)
	assert.Equal(t, err, nil, "Got error getting replication info")
	ejson := volumeToReplicationInfo[name]
	eReplInfo := &ReplicationInfo{}
	err = json.Unmarshal([]byte(ejson), eReplInfo)
	assert.Equal(t, err, nil, "Got error unmarshalling replication info")
	b := reflect.DeepEqual(replInfo, eReplInfo)
	assert.Equalf(t, b, true, "ReplicationInfo is not same for %s", name)
}

func TestPxVolumeOps(t *testing.T) {
	volOps := testGetPxVolumeOps(t)
	svols, err := volOps.GetVolumes()
	assert.Equal(t, err, nil, "Could not get volumes")
	nodeNames := make(map[string]bool)
	for _, sv := range svols {
		v := sv.GetVolume()
		testPxVolumeOps(t, volOps, v)
		err := volOps.GetAllNodesForVolume(v, nodeNames)
		assert.NoError(t, err)
		cinfo, err := volOps.GetContainerInfoForVolume(v)
		for _, ci := range cinfo {
			volName := podToVolume[ci.Pod.Name]
			assert.Equal(t, volName, v.GetLocator().GetName())
			assert.Equal(t, ci.Pod.Namespace, "wp1")
			if ci.Container == "mysql" {
				assert.Equal(t, ci.Pod.Name, "wordpress-mysql-684ddbbb55-zjs7b")
			} else {
				assert.Equal(t, ci.Container, "wordpress")
			}
		}
	}
	assert.Equal(t, len(expectedNodes), len(nodeNames))
	for _, n := range expectedNodes {
		_, ok := nodeNames[n]
		assert.Equal(t, ok, true)
	}

	pxPvcs, err := volOps.GetPxPvcs()
	assert.Equal(t, err, nil, "Got error while trying to get PxPvcs")
	for _, pxPvc := range pxPvcs {
		vname := pxPvc.PxVolume.GetLocator().GetName()
		assert.Equal(t, pxPvc.Name, pxPvc.Pvc.GetName(), "pvc names don't match")
		assert.Equal(t, vname, pxPvc.Pvc.Spec.VolumeName, "Volume name does not match")
		assert.Equal(t, pxPvc.Namespace, pxPvc.Pvc.GetNamespace(), "pxPvc's namespace does not match with pxPvc.Pvc's namespace")
		ePvcName := pvcInfo[vname]
		assert.Equal(t, pxPvc.Name, ePvcName, "pvc names don't match")
		podNames := pxPvc.PodNames
		for _, p := range podNames {
			n := strings.Split(p, "/")
			assert.Equalf(t, pxPvc.Namespace, n[0], "namespace of pod not correct %s", p)
			vn := podToVolume[n[1]]
			assert.Equalf(t, vn, vname, "%s should be using %s", n[1], vname)
		}
	}
}
