package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter"
	"github.com/ibm-cloud-security/app-identity-and-access-adapter/adapter/config"
)

// GetCmd returns the cobra command-tree.
func getCmd() *cobra.Command {
	sa := config.NewConfig()
	cmd := &cobra.Command{
		Use:   "Starts the App Identity and Access out-of-process Mixer adapter",
		Short: "Starts the App Identity and Access out-of-process Mixer adapter",
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
	f.Uint16VarP(&sa.AdapterPort, "port", "p", sa.AdapterPort, "TCP port to use for gRPC Adapter API.")
	f.BoolVarP(&sa.Json, "json", "j", sa.Json, "Use JSON style logging.")
	f.Int8VarP(&sa.Level, "level", "l", sa.Level, "Set output log level. Range [-1, 7].")
	f.VarP(&sa.HashKeySize, "hash-key", "", "The size of the HMAC signature key. It is recommended to use a key with 32 or 64 bytes.")
	f.VarP(&sa.BlockKeySize, "block-key", "", "The size of the AES blockKey size used to encrypt the cookie value. Valid lengths are 16, 24, or 32.")
	f.BoolVarP(&sa.SecureCookies, "secure-cookies", "", sa.SecureCookies, "Use Secure attribute for session cookies to ensure they are sent over HTTPS only.")

	return cmd
}

func configureLogger(args *config.Config) {
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zapcore.Level(args.Level))
	config.InitialFields = map[string]interface{}{"source": "appidentityandaccessadapter-adapter"}
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	if !args.Json {
		config.Encoding = "console"
	}
	logger, _ := config.Build()
	zap.ReplaceGlobals(logger)
}

func runServer(args *config.Config) {
	configureLogger(args)

	// Configure Adapter
	s, err := adapter.NewAppIDAdapter(args)
	if err != nil {
		zap.L().Fatal("Failed to create appidentityandaccessadapter.NewAppIDAdapter: %s", zap.Error(err))
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
