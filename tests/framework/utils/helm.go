package utils

// HelmInit init helm with a service account
func HelmInit(serviceAccount string) error {
	_, err := Shell("helm init --upgrade --service-account %s", serviceAccount)
	return err
}

// HelmClientInit initializes the Helm client only
func HelmClientInit() error {
	_, err := Shell("helm init --client-only")
	return err
}

// HelmInstallDryRun helm install dry run from a chart for a given namespace
func HelmInstallDryRun(chartDir, chartName, valueFile, namespace, setValue string) error {
	_, err := Shell("helm install --dry-run --debug " + HelmParams(chartDir, chartName, valueFile, namespace, setValue))
	return err
}

// HelmInstall helm install from a chart for a given namespace
//       --set stringArray        set values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)
func HelmInstall(chartDir, chartName, valueFile, namespace, setValue string) error {
	_, err := Shell("helm install " + HelmParams(chartDir, chartName, valueFile, namespace, setValue))
	return err
}

// HelmTest helm test a chart release
func HelmTest(releaseName string) error {
	_, err := Shell("helm test %s", releaseName)
	return err
}

// HelmTemplate helm template from a chart for a given namespace
//      --set stringArray        set values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)
func HelmTemplate(chartDir, chartName, namespace, setValue, outfile string) error {
	_, err := Shell("helm template %s --name %s --namespace %s %s > %s", chartDir,
		chartName, namespace, setValue, outfile)
	return err
}

// HelmDelete helm del --purge a chart
func HelmDelete(chartName string) error {
	_, err := Shell("helm del --purge %s", chartName)
	return err
}

// HelmParams provides a way to construct helm params
func HelmParams(chartDir, chartName, valueFile, namespace, setValue string) string {
	helmCmd := chartDir + " --name " + chartName + " --namespace " + namespace + " " + setValue
	if valueFile != "" {
		helmCmd = chartDir + " --name " + chartName + " --values " + valueFile + " --namespace " + namespace + " " + setValue
	}

	return helmCmd
}

// Obtain the version of Helm client and server with a timeout of 10s or return an error
func helmVersion() (string, error) {
	version, err := Shell("helm version")
	return version, err
}
