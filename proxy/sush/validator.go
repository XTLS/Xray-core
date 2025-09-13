package sush

import (
	"sync"
	"sync/atomic"
)

// SushUser interface for basic user information
type SushUser struct {
	Account *Account
	Email   string
}

// MemoryValidator implements UserValidator using in-memory storage with atomic operations
type MemoryValidator struct {
	users atomic.Pointer[map[[16]byte]*SushUser] // Lock-free for reads
	mu    sync.Mutex                               // Only for writes
}

// NewMemoryValidator creates a new memory-based user validator with atomic operations
func NewMemoryValidator() *MemoryValidator {
	validator := &MemoryValidator{}
	initialUsers := make(map[[16]byte]*SushUser)
	validator.users.Store(&initialUsers)
	return validator
}

// Add adds a user to the validator with atomic copy-on-write
func (v *MemoryValidator) Add(user *SushUser) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Load current map
	currentUsers := v.users.Load()
	if currentUsers == nil {
		initialUsers := make(map[[16]byte]*SushUser)
		currentUsers = &initialUsers
	}

	// Create a copy of the map (copy-on-write)
	newUsers := make(map[[16]byte]*SushUser)
	for k, v := range *currentUsers {
		newUsers[k] = v
	}

	// Add the new user
	account := user.Account
	var userID [16]byte
	idBytes := []byte(account.Id)
	if len(idBytes) > 16 {
		idBytes = idBytes[:16]
	}
	copy(userID[:], idBytes)
	newUsers[userID] = user

	// Atomically replace the map
	v.users.Store(&newUsers)
}

// Get retrieves a user by ID using atomic load (lock-free read)
func (v *MemoryValidator) Get(userID [16]byte) *SushUser {
	// Atomic load - no locking needed for reads!
	currentUsers := v.users.Load()
	if currentUsers == nil {
		return nil
	}

	return (*currentUsers)[userID]
}

// ValidateUser validates if a user ID exists using atomic load (lock-free!)
func (v *MemoryValidator) ValidateUser(userID [16]byte) bool {
	// Atomic load - this is the performance-critical path!
	currentUsers := v.users.Load()
	if currentUsers == nil {
		return false
	}

	_, exists := (*currentUsers)[userID]
	return exists
}

// Remove removes a user from the validator with atomic copy-on-write
func (v *MemoryValidator) Remove(userID [16]byte) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Load current map
	currentUsers := v.users.Load()
	if currentUsers == nil {
		return
	}

	// Create a copy of the map (copy-on-write)
	newUsers := make(map[[16]byte]*SushUser)
	for k, v := range *currentUsers {
		if k != userID { // Skip the user to be removed
			newUsers[k] = v
		}
	}

	// Atomically replace the map
	v.users.Store(&newUsers)
}
