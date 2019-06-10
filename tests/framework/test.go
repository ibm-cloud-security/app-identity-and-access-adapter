package framework

import (
	"testing"
)

type Test struct {
	ctx *Context

	goTest *testing.T

	skipCleanup bool
}

func NewTest(t *testing.T) *Test {
	rtMu.Lock()
	defer rtMu.Unlock()

	if rt == nil {
		panic("Test framework not initialized")
	}

	runner := &Test{
		ctx:         rt,
		goTest:      t,
		skipCleanup: false,
	}

	return runner
}

func (t *Test) Run(fn func(ctx *Context)) {
	fn(t.ctx)
	if !t.skipCleanup {
		_ = t.ctx.CRDManager.CleanUp()
	}
}
