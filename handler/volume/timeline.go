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

package volume

import (
	"github.com/portworx/pxc/pkg/commander"
	"github.com/portworx/pxc/pkg/portworx"
	"github.com/portworx/pxc/pkg/util"
	"github.com/spf13/cobra"
)

var volumeTimelineCmd *cobra.Command

var _ = commander.RegisterCommandVar(func() {
	volumeTimelineCmd = &cobra.Command{
		Use:   "timeline",
		Short: "shows volume timeline",
		Example: `
  # Shows cluster timeline
  pxc volume timeline <vol-id>`,
		RunE: volumeTimelineExec,
	}
})

var _ = commander.RegisterCommandInit(func() {
	VolumeAddCommand(volumeTimelineCmd)

})

func volumeTimelineExec(cmd *cobra.Command, args []string) error {
	ctx, conn, err := portworx.PxConnectDefault()
	_ = ctx
	if err != nil {
		return err
	}
	defer conn.Close()
	util.Printf("In volumeTimelineExec")
	return nil
}
