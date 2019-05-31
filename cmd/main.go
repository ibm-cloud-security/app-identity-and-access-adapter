package main

import (
	"fmt"
	"os"

	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/adapter"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// args represents args consumed by IBMCloudAppID OOP adapter.
type args struct {
	// port to start the grpc adapter on
	adapterPort uint16
	// JSON style logs
	json bool
	// Log level - models zapcore.Level
	level int8
}

func defaultArgs() *args {
	return &args{
		adapterPort: uint16(47304),
		json:        false,
		level:       0,
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
	f.BoolVarP(&sa.json, "json", "j", sa.json, "Use JSON style logging")
	f.Int8VarP(&sa.level, "level", "l", sa.level, "Set output log level")

	return cmd
}

func configureLogger(args *args) {
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zapcore.Level(args.level))
	config.InitialFields = map[string]interface{}{"source": "ibmcloudappid-adapter"}
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	if !args.json {
		config.Encoding = "console"
	}
	logger, _ := config.Build()
	zap.ReplaceGlobals(logger)
}

func runServer(args *args) {
	configureLogger(args)

	// Configure Adapter
	addr := fmt.Sprintf(":%d", args.adapterPort)
	s, err := adapter.NewAppIDAdapter(addr)
	if err != nil {
		zap.L().Fatal("Failed to create ibmcloudappid.NewAppIDAdapter: %s", zap.Error(err))
	}

	shutdown := make(chan error, 1)
	go func() {
		s.Run(shutdown)
	}()
	<-shutdown
}

func main() {
	cmd := getCmd()
	if err := cmd.Execute(); err != nil {
		os.Exit(-1)
	}
}
