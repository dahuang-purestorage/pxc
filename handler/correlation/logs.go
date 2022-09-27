// Copyright © 2019 Portworx
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

package correlation

import (
	"bytes"
	"fmt"
	"regexp"
	"time"

	"github.com/portworx/pxc/pkg/cliops"
	"github.com/portworx/pxc/pkg/commander"
	"github.com/portworx/pxc/pkg/kubernetes"
	"github.com/spf13/cobra"
)

var logsCorrelationCmd *cobra.Command

var _ = commander.RegisterCommandVar(func() {
	logsCorrelationCmd = &cobra.Command{
		Use:   "logs [NAME]",
		Short: "Print Portworx logs related to the input correlation ID",
		Example: `
  # Return Portworx logs related to volume abc
  pxc correlation logs 123

  # Begin streaming the Portworx logs related to volume abc
  pxc correlation logs -f 123 

  # Apply the volume filters  and the filters specified in --filters to the most recent 20 log lines of each relevant pod  and display only lines that match
  pxc correlation logs --tail=20 abc

  # Display all log lines that is related to volume abc or has either error or warning in the log lines
  pxc correlation logs 123 --filter "error,warning"

  # Show all Portworx logs related to volume abc written in the last hour
  pxc correlation 123 --since=1h volume`,
		RunE: logsCorrelationExec,
	}
})

// logsCmd represents the logs command
var _ = commander.RegisterCommandInit(func() {
	CorrelationAddCommand(logsCorrelationCmd)
	cliops.AddCommonLogOptions(logsCorrelationCmd)
	logsCorrelationCmd.Flags().Bool("all-logs", false, "If specified all logs from the pods related to the volume are displayed. Otherwise only log lines that reference the volume or its id is displayed ")
	logsCorrelationCmd.Flags().StringP("selector", "l", "", "Selector (label query) comma-separated name=value pairs")
})

func getCorrelationLogOptions(
	cmd *cobra.Command,
	args []string,
	cliOps cliops.CliOps,
) (*kubernetes.COpsLogOptions, error) {
	err := cliops.ValidateCliInput(cmd, args)
	if err != nil {
		return nil, err
	}

	lo, err := cliops.GetCommonLogOptions(cmd)
	if err != nil {
		return nil, err
	}

	p, err := cliops.GetRequiredPortworxPods(cliOps, []string{}, lo.PortworxNamespace)
	if err != nil {
		return nil, err
	}
	lo.CInfo = p
	// for _, arg := range args {
	// 	lo.Filters = append(lo.Filters, arg)
	// }
	// lo.ApplyFilters = true
	return lo, nil
}

func logsCorrelationExec(cmd *cobra.Command, args []string) error {
	cvi := cliops.NewCliInputs(cmd, args)
	// if len(cvi.Labels) == 0 && len(args) == 0 {
	// 	return fmt.Errorf("Please specify either --selector or volume name")
	// }

	// Create a cliVolumeOps object
	cliOps := cliops.NewCliOps(cvi)

	// Connect to pxc and k8s (if needed)
	err := cliOps.Connect()
	if err != nil {
		return err
	}
	defer cliOps.Close()

	lo, err := getCorrelationLogOptions(cmd, args, cliOps)
	if err != nil {
		return err
	}

	if lo == nil || len(lo.CInfo) == 0 {
		return nil
	}
	buf := new(bytes.Buffer)
	if err = cliOps.COps().GetLogs(lo, buf); err != nil {
		return err
	}
	// line, _ := buf.ReadString('\n')
	fmt.Println(buf)
	// c := parseCorrelation(line)
	// fmt.Println(c.String())

	return nil
}

type CorrelationData struct {
	time     time.Time
	logLevel string
	cid      string
	node     string
	msg      string
	fullLog  string
}

func parseCorrelation(line string) CorrelationData {

	timeRegex := `time=\"(.*?)\"`
	cidRegex := `correlation-id=(.*?) `
	logLevelRegex := `level=(.*?) `
	nodeRegex := `node=(.*?) `
	msgRegex := `msg=(.*?) `

	tStr := callRegex(line, timeRegex)
	t, _ := time.Parse(time.RFC3339, tStr)

	cid := callRegex(line, cidRegex)

	logLevel := callRegex(line, logLevelRegex)
	node := callRegex(line, nodeRegex)
	msg := callRegex(line, msgRegex)
	c := CorrelationData{
		time:     t,
		cid:      cid,
		logLevel: logLevel,
		node:     node,
		msg:      msg,
		fullLog:  line,
	}

	fmt.Println(c.String())

	return c
}

func callRegex(line string, regex string) string {
	re := regexp.MustCompile(regex)
	matches := re.FindStringSubmatch(line)
	return matches[1]

}

func (c *CorrelationData) String() string {
	return fmt.Sprintf("%s %s %s %s %s", c.time.String(), c.cid, c.logLevel, c.node, c.msg)
}
