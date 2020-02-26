package config

// Config contains the
type Config struct {
	// port to start the grpc adapter on
	AdapterPort uint16
	// JSON style logs
	Json bool
	// Log level - models zapcore.Level
	Level int8
	// hashKeySize used to c.
	// It is recommended to use a key with 32 or 64 bytes.
	HashKeySize IntOptions
	// The blockKey is used to encrypt the cookie value
	// Valid lengths are 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
	BlockKeySize IntOptions
	// Use Secure attribute for session cookies.
	// That ensures they are sent over HTTPS and should be enabled for production!
	SecureCookies bool
}

// NewConfig returns the default configuration
func NewConfig() *Config {
	return &Config{
		AdapterPort: uint16(47304),
		Json:        false,
		Level:       0,
		HashKeySize: IntOptions{
			Options: map[int]struct{}{
				32: {},
				64: {},
			},
			Value: 32,
		},
		BlockKeySize: IntOptions{
			Options: map[int]struct{}{
				16: {},
				24: {},
				32: {},
			},
			Value: 16,
		},
		SecureCookies: false,
	}
}
