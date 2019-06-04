package framework

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// test.Run uses 0, 1, 2 exit codes. Use different exit codes for our framework.
const (

	// Indicates a framework-level init error
	exitCodeInitError = -1

	// Indicates an error due to the setup function supplied by the user
	exitCodeSetupError = -2
)

var (
	rt   *Context
	rtMu sync.Mutex
)

// mRunFn abstracts testing.M.run, so that the framework itself can be tested.
type mRunFn func() int

type ModifierFn func(ctx *Context) error

// Suite allows the test author to specify suite-related metadata and do setup in a fluent-style, before commencing execution.
type Suite struct {
	testID     string
	mRun       mRunFn
	osExit     func(int)
	setupFns   []ModifierFn
	cleanupFns []ModifierFn
	ctx        *Context
}

// NewSuite returns a new suite instance.
func NewSuite(testID string, m *testing.M) *Suite {
	return newSuite(testID, m.Run, os.Exit)
}

func newSuite(testID string, fn mRunFn, osExit func(int)) *Suite {
	s := &Suite{
		testID: testID,
		mRun:   fn,
		osExit: osExit,
	}

	return s
}

// Setup runs enqueues the given setup function to run before test execution.
func (s *Suite) Setup(fn ModifierFn) *Suite {
	s.setupFns = append(s.setupFns, fn)
	return s
}

// Cleanup runs enqueues the given cleanup function to run after test execution.
func (s *Suite) Cleanup(fn ModifierFn) *Suite {
	s.cleanupFns = append(s.cleanupFns, fn)
	return s
}

// Run the suite. This method calls os.Exit and does not return.
func (s *Suite) Run() {
	s.osExit(s.run())
}

func (s *Suite) run() (errLevel int) {
	if err := initRuntimeContext(s.testID); err != nil {
		return exitCodeInitError
	}

	s.ctx = rt

	fmt.Printf("=== Suite %q starting ===\n", s.testID)

	start := time.Now()

	if err := s.runModifierFns(rt, s.setupFns); err != nil {
		fmt.Printf("Exiting due to setup failure: %v\n", err)
		return exitCodeSetupError
	}

	defer func() {
		end := time.Now()
		fmt.Printf("=== Suite %q run time: %v ===\n", s.testID, end.Sub(start))
	}()

	errLevel = s.mRun()
	if errLevel != 0 {
		fmt.Printf("=== FAILED: Suite %q (exitCode: %v) ===\n", s.testID, errLevel)
	}

	if err := s.runModifierFns(rt, s.cleanupFns); err != nil {
		fmt.Printf("Cleanup failed %v\n", err)
	}

	return
}

func (s *Suite) runModifierFns(ctx *Context, fns []ModifierFn) (err error) {
	for _, fn := range fns {
		err := fn(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

func initRuntimeContext(testID string) error {
	rtMu.Lock()
	defer rtMu.Unlock()

	if rt != nil {
		return errors.New("framework is already initialized")
	}

	rt = NewContext(testID)
	return nil
}
