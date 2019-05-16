package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter"
	"istio.io/pkg/log"
)

// args represents args consumed by IBMCloudAppID OOP adapter.
type args struct {
	// port to start the grpc adapter on
	adapterPort uint16
	// verbosity of logs
	verbose bool
}

func defaultArgs() *args {
	return &args{
		adapterPort: uint16(47304),
		verbose:     false,
	}
}

// GetCmd returns the cobra command-tree.
func getCmd() *cobra.Command {
	sa := defaultArgs()
	cmd := &cobra.Command{
		Use:   "ibmcloudappid",
		Short: "IBM Cloud App ID out of process adapter.",
		Run: func(cmd *cobra.Command, args []string) {
			runServer(sa)
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("'%s' is an invalid argument", args[0])
			}
			return nil
		},
	}

	f := cmd.PersistentFlags()
	f.Uint16VarP(&sa.adapterPort, "port", "p", sa.adapterPort, "TCP port to use for gRPC Adapter API")
	f.BoolVarP(&sa.verbose, "verbose", "v", sa.verbose, "Use verbose logging")

	return cmd
}

func runServer(args *args) {
	// Set logs
	if args.verbose {
		scope := log.Scopes()["default"]
		scope.SetOutputLevel(log.DebugLevel)
	}

	// Configure Adapter
	addr := fmt.Sprintf(":%d", args.adapterPort)
	s, err := adapter.NewAppIDAdapter(addr)
	if err != nil {
		log.Errorf("Failed to create ibmcloudappid.NewAppIDAdapter: %s", err)
		os.Exit(-1)
	}

	shutdown := make(chan error, 1)
	go func() {
		s.Run(shutdown)
	}()
	_ = <-shutdown
}

func main() {
	log.Info("Starting ibmcloudappid adapter")
	cmd := getCmd()
	if err := cmd.Execute(); err != nil {
		os.Exit(-1)
	}
}
