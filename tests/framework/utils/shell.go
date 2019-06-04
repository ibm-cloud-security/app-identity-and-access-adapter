package utils

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Shell run command on shell and get back output and error if get one
func Shell(format string, args ...interface{}) (string, error) {
	return sh(context.Background(), format, true, true, true, args...)
}

// Shell run command on shell and get back output and error if get one
func ShellMuteOutput(format string, args ...interface{}) (string, error) {
	return sh(context.Background(), format, false, false, false, args...)
}

// Shell run command on shell and get back output and error if get one
func Exists(executable string) bool {
	res, err := ShellMuteOutput("command -v %s", executable)
	if err != nil {
		return false
	}
	return !(res == "")
}

func sh(ctx context.Context, format string, logCommand, logOutput, logError bool, args ...interface{}) (string, error) {
	command := fmt.Sprintf(format, args...)
	if logCommand {
		fmt.Printf("Running command %s\n", command)
	}
	c := exec.CommandContext(ctx, "sh", "-c", command) // #nosec
	bytes, err := c.CombinedOutput()
	if logOutput {
		if output := strings.TrimSuffix(string(bytes), "\n"); len(output) > 0 {
			fmt.Printf("Command output: \n%s\n", output)
		}
	}

	if err != nil {
		if logError {
			fmt.Printf("Command error: %v\n", err)
		}
		return string(bytes), fmt.Errorf("command failed: %q %v", string(bytes), err)
	}
	return string(bytes), nil
}
