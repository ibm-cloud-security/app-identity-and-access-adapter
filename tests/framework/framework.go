package framework

import (
	"context"
	"go.uber.org/zap"
	"os"
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

// mRunFn abstracts testing.M.run, so that the framework itself can be tested.
type mRunFn func() int

type SetupFn func(ctx context.Context) error

// Suite allows the test author to specify suite-related metadata and do setup in a fluent-style, before commencing execution.
type Suite struct {
	testID   string
	mRun     mRunFn
	osExit   func(int)
	setupFns []SetupFn

	// labels label.Set
	// getSettingsFn func(string) (*core.Settings, error)
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
		// getSettingsFn: getSettingsFn,
		// labels:        label.NewSet(),
	}

	return s
}

// Setup runs enqueues the given setup function to run before test execution.
func (s *Suite) Setup(fn SetupFn) *Suite {
	s.setupFns = append(s.setupFns, fn)
	return s
}

// Run the suite. This method calls os.Exit and does not return.
func (s *Suite) Run() {
	s.osExit(s.run())
}

func (s *Suite) run() (errLevel int) {
	start := time.Now()

	if err := s.runSetupFns(context.Background()); err != nil {
		zap.S().Info("Exiting due to setup failure: %v", err)
		return exitCodeSetupError
	}

	defer func() {
		end := time.Now()
		zap.S().Info("=== Suite %q run time: %v ===", s.testID, end.Sub(start))
	}()

	zap.S().Info("=== BEGIN: Test Run: '%s' ===", s.testID)
	errLevel = s.mRun()
	if errLevel == 0 {
		zap.S().Info("=== DONE: Test Run: '%s' ===", s.testID)
	} else {
		zap.S().Info("=== FAILED: Test Run: '%s' (exitCode: %v) ===", s.testID, errLevel)
	}

	return
}

func (s *Suite) runSetupFns(ctx context.Context) (err error) {
	zap.S().Info("=== BEGIN: Setup: '%s' ===", s.testID)

	for _, fn := range s.setupFns {
		err := fn(ctx)
		if err != nil {
			zap.S().Error("Test setup error: %v", err)
			zap.S().Info("=== FAILED: Setup: '%s' (%v) ===", s.testID, err)
			return err
		}
	}
	zap.S().Info("=== DONE: Setup: '%s' ===", s.testID)
	return nil
}
