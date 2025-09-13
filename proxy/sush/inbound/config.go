package inbound

import "fmt"

// Validate validates the configuration
func (c *Config) Validate() error {
	if len(c.Users) == 0 {
		return fmt.Errorf("at least one user must be configured")
	}

	for i, user := range c.Users {
		if len(user.ID) == 0 {
			return fmt.Errorf("user %d: ID cannot be empty", i)
		}
	}

	if len(c.PSK) == 0 {
		return fmt.Errorf("PSK cannot be empty")
	}

	return nil
}
