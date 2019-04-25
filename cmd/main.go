package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"istio.io/istio/mixer/adapter/ibmcloudappid"
	"istio.io/istio/pkg/log"
	"os"
)

// args represents args consumed by IBMCloudAppID OOP adapter.
type args struct {
	// Port to start the grpc adapter on
	adapterPort uint16
}

func defaultArgs() *args {
	return &args{
		adapterPort: uint16(47304),
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

	return cmd
}

func runServer(args *args) {
	s, err := ibmcloudappid.NewAppIDAdapter(args.adapterPort)
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
