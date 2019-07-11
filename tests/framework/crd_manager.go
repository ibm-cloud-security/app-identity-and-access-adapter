package framework

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"text/template"

	"github.com/ibm-cloud-security/app-identity-and-access-adapter/tests/framework/utils"
)

const (
	letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	yamlExt     = ".yaml"
)

// CRD models a Kubernetes CRD exposing name and namespace
type CRD interface {
	GetName() string
	GetNamespace() string
}

type crd struct {
	CRD
	pathToYAML string
}

// CRD Manager maintains Kubernetes CRDs locally and provides helper methods create/update/delete them
type CRDManager struct {
	crds []crd

	context *Context
}

// CleanUp delete stored CRDs from Kubernetes then purges the local store
func (m *CRDManager) CleanUp() error {
	for _, crd := range m.crds {
		err := utils.KubeDelete(crd.GetNamespace(), crd.pathToYAML, m.context.Env.KubeConfig)
		err = os.Remove(crd.pathToYAML)
		if err != nil {
			fmt.Println(err.Error())
		}
	}
	m.crds = []crd{}
	return nil
}

// AddCRD adds a custom resource definition from a given file
func (m *CRDManager) AddCRD(pathToTemplate string, data CRD) error {
	t, err := template.ParseFiles(pathToTemplate)
	if err != nil {
		return err
	}

	file := strings.Split(pathToTemplate, yamlExt)[0]

	tmpPath := file + "-" + RandString(4) + yamlExt
	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	err = t.Execute(f, &data)
	if err != nil {
		return err
	}
	_ = f.Close()

	err = utils.KubeApply(data.GetNamespace(), tmpPath, m.context.Env.KubeConfig)
	if err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	m.crds = append(m.crds, crd{
		data,
		tmpPath,
	})

	return nil
}

// DeleteCRD deletes a custom resource definition using a given CRD
func (m *CRDManager) DeleteCRD(savedCRD CRD) error {
	for i, crd := range m.crds {
		if crd.GetName() == savedCRD.GetName() && crd.GetNamespace() == savedCRD.GetNamespace() {
			err := utils.KubeDelete(crd.GetNamespace(), crd.pathToYAML, m.context.Env.KubeConfig)
			if err != nil {
				return err
			}
			err = os.Remove(crd.pathToYAML)
			if err != nil {
				return err
			}
			m.crds = remove(m.crds, i)
			return nil
		}
	}
	return fmt.Errorf("crd not found")
}

func remove(s []crd, i int) []crd {
	s[len(s)-1], s[i] = s[i], s[len(s)-1]
	return s[:len(s)-1]
}

func RandString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
