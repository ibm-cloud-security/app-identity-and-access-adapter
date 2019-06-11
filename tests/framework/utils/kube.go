package utils

import (
	"fmt"
)

func kubeCommand(subCommand, namespace, yamlFileName string, kubeconfig string) string {
	if kubeconfig != "" {
		kubeconfig = "--kubeconfig=" + kubeconfig
	}

	if namespace == "" {
		return fmt.Sprintf("kubectl %s -f %s %s", subCommand, yamlFileName, kubeconfig)
	}
	return fmt.Sprintf("kubectl %s -n %s -f %s %s", subCommand, namespace, yamlFileName, kubeconfig)
}

// KubeApply kubectl apply from file
func KubeApply(namespace, yamlFileName string, kubeconfig string) error {
	_, err := ShellMuteOutput(kubeCommand("apply", namespace, yamlFileName, kubeconfig))
	return err
}

// KubeDelete kubectl delete from file
func KubeDelete(namespace, yamlFileName string, kubeconfig string) error {
	_, err := ShellMuteOutput(kubeCommand("delete", namespace, yamlFileName, kubeconfig))
	return err
}
