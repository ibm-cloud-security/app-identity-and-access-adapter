package framework

import (
	"fmt"
	"github.com/ibm-cloud-security/policy-enforcer-mixer-adapter/tests/framework/utils"
	"math/rand"
	"os"
	"strings"
	"text/template"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

type CRD interface {
	GetName() string
	GetNamespace() string
}

type crd struct {
	CRD
	pathToYAML string
}

type CRDManager struct {
	crds []crd

	context *Context
}

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

func (m *CRDManager) AddCRD(pathToTemplate string, data CRD) error {
	t, err := template.ParseFiles(pathToTemplate)
	if err != nil {
		return err
	}

	file := strings.Split(pathToTemplate, ".yaml")[0]

	tmpPath := file + "-" + randStringBytes(4) + "-temp.yaml"
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
	return fmt.Errorf("crd found")
}

func remove(s []crd, i int) []crd {
	s[len(s)-1], s[i] = s[i], s[len(s)-1]
	return s[:len(s)-1]
}

func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
