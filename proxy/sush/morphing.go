// package sush implements advanced traffic morphing for steganographic communication
package sush

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// AdvancedTrafficMorpher implements sophisticated traffic shaping and morphing
type AdvancedTrafficMorpher struct {
	config           *TrafficShapingConfig
	profile          *AdvancedTrafficProfile
	cryptoRand       *CryptoRandSource
	timingController *TimingController
	sizeController   *SizeController
	burstController  *BurstController
	stats            *MorphingStats
	enabled          bool
	closed           chan struct{}
	mu               sync.RWMutex
}

// AdvancedTrafficProfile defines enhanced traffic characteristics for morphing
type AdvancedTrafficProfile struct {
	Name           string
	MinPacketSize  int
	MaxPacketSize  int
	AvgPacketSize  int
	IntervalMean   time.Duration
	IntervalStdDev time.Duration
	BurstSize      int
	BurstInterval  time.Duration
	PaddingRatio   float64
}

// CryptoRandSource provides cryptographically secure random numbers
type CryptoRandSource struct {
	mu sync.Mutex
}

// TimingController manages timing delays and patterns
type TimingController struct {
	profile    *AdvancedTrafficProfile
	cryptoRand *CryptoRandSource
	lastDelay  time.Duration
	mu         sync.Mutex
}

// SizeController manages packet size morphing
type SizeController struct {
	profile       *AdvancedTrafficProfile
	cryptoRand    *CryptoRandSource
	totalPadding  uint64
	totalOriginal uint64
	mu            sync.Mutex
}

// BurstController manages burst pattern generation
type BurstController struct {
	profile        *AdvancedTrafficProfile
	cryptoRand     *CryptoRandSource
	burstActive    bool
	burstRemaining int
	lastBurstTime  time.Time
	mu             sync.Mutex
}

// MorphingStats tracks morphing effectiveness
type MorphingStats struct {
	TotalFrames        uint64
	MorphedFrames      uint64
	TotalPadding       uint64
	TimingVariance     float64
	SizeVariance       float64
	BurstCount         uint64
	EffectivenessScore float64
	mu                 sync.RWMutex
}

// Predefined advanced traffic profiles
var (
	WebAdvancedTrafficProfile = &AdvancedTrafficProfile{
		Name:           "web",
		MinPacketSize:  64,
		MaxPacketSize:  1500,
		AvgPacketSize:  800,
		IntervalMean:   50 * time.Millisecond,
		IntervalStdDev: 20 * time.Millisecond,
		BurstSize:      5,
		BurstInterval:  2 * time.Second,
		PaddingRatio:   0.15,
	}

	VideoAdvancedTrafficProfile = &AdvancedTrafficProfile{
		Name:           "video",
		MinPacketSize:  200,
		MaxPacketSize:  1500,
		AvgPacketSize:  1200,
		IntervalMean:   33 * time.Millisecond, // ~30 FPS
		IntervalStdDev: 10 * time.Millisecond,
		BurstSize:      10,
		BurstInterval:  1 * time.Second,
		PaddingRatio:   0.10,
	}

	BulkAdvancedTrafficProfile = &AdvancedTrafficProfile{
		Name:           "bulk",
		MinPacketSize:  1000,
		MaxPacketSize:  1500,
		AvgPacketSize:  1400,
		IntervalMean:   10 * time.Millisecond,
		IntervalStdDev: 5 * time.Millisecond,
		BurstSize:      20,
		BurstInterval:  500 * time.Millisecond,
		PaddingRatio:   0.05,
	}

	ChatAdvancedTrafficProfile = &AdvancedTrafficProfile{
		Name:           "chat",
		MinPacketSize:  32,
		MaxPacketSize:  200,
		AvgPacketSize:  80,
		IntervalMean:   500 * time.Millisecond,
		IntervalStdDev: 200 * time.Millisecond,
		BurstSize:      3,
		BurstInterval:  5 * time.Second,
		PaddingRatio:   0.25,
	}
)

// GetAdvancedTrafficProfile returns an advanced traffic profile by name
func GetAdvancedTrafficProfile(name string) *AdvancedTrafficProfile {
	switch name {
	case "web":
		return WebAdvancedTrafficProfile
	case "video":
		return VideoAdvancedTrafficProfile
	case "bulk":
		return BulkAdvancedTrafficProfile
	case "chat":
		return ChatAdvancedTrafficProfile
	default:
		return WebAdvancedTrafficProfile // Default to web traffic
	}
}

// NewCryptoRandSource creates a new cryptographically secure random source
func NewCryptoRandSource() *CryptoRandSource {
	return &CryptoRandSource{}
}

// Float64 returns a cryptographically secure random float64 in [0.0, 1.0)
func (crs *CryptoRandSource) Float64() float64 {
	crs.mu.Lock()
	defer crs.mu.Unlock()

	// Generate 8 random bytes
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to time-based pseudo-random
		return float64(time.Now().UnixNano()%1000000) / 1000000.0
	}

	// Convert to uint64 and then to float64
	var value uint64
	for i, b := range bytes {
		value |= uint64(b) << (8 * i)
	}

	// Normalize to [0.0, 1.0)
	return float64(value) / float64(^uint64(0))
}

// Intn returns a cryptographically secure random int in [0, n)
func (crs *CryptoRandSource) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(crs.Float64() * float64(n))
}

// NewAdvancedTrafficMorpher creates a new advanced traffic morpher
func NewAdvancedTrafficMorpher(config *TrafficShapingConfig, originalProfile *TrafficProfile) *AdvancedTrafficMorpher {
	if config == nil {
		config = &TrafficShapingConfig{
			EnableMorphing: true,
			Profile:        "web",
			MinDelayMs:     10,
			MaxDelayMs:     100,
		}
	}

	// Convert TrafficProfile to AdvancedTrafficProfile
	var profile *AdvancedTrafficProfile
	if originalProfile != nil {
		profile = ConvertToAdvancedProfile(originalProfile)
	} else {
		profile = GetProfileByName(config.Profile)
	}

	cryptoRand := NewCryptoRandSource()

	morpher := &AdvancedTrafficMorpher{
		config:           config,
		profile:          profile,
		cryptoRand:       cryptoRand,
		timingController: NewTimingController(profile, cryptoRand),
		sizeController:   NewSizeController(profile, cryptoRand),
		burstController:  NewBurstController(profile, cryptoRand),
		stats:            &MorphingStats{},
		enabled:          config.EnableMorphing,
		closed:           make(chan struct{}),
	}

	return morpher
}

// ConvertToAdvancedProfile converts TrafficProfile to AdvancedTrafficProfile
func ConvertToAdvancedProfile(original *TrafficProfile) *AdvancedTrafficProfile {
	// Extract values from the original profile
	minSize := 64
	maxSize := 1500
	avgSize := 800

	if len(original.PacketSizes) > 0 {
		minSize = original.PacketSizes[0]
		maxSize = original.PacketSizes[len(original.PacketSizes)-1]

		// Calculate average
		sum := 0
		for _, size := range original.PacketSizes {
			sum += size
		}
		avgSize = sum / len(original.PacketSizes)
	}

	return &AdvancedTrafficProfile{
		Name:           original.Name,
		MinPacketSize:  minSize,
		MaxPacketSize:  maxSize,
		AvgPacketSize:  avgSize,
		IntervalMean:   50 * time.Millisecond,
		IntervalStdDev: 20 * time.Millisecond,
		BurstSize:      5,
		BurstInterval:  2 * time.Second,
		PaddingRatio:   0.15,
	}
}

// GetProfileByName returns an advanced traffic profile by name
func GetProfileByName(name string) *AdvancedTrafficProfile {
	switch name {
	case "web":
		return WebAdvancedTrafficProfile
	case "video":
		return VideoAdvancedTrafficProfile
	case "bulk":
		return BulkAdvancedTrafficProfile
	case "chat":
		return ChatAdvancedTrafficProfile
	default:
		return WebAdvancedTrafficProfile // Default to web traffic
	}
}

// NewTimingController creates a new timing controller
func NewTimingController(profile *AdvancedTrafficProfile, cryptoRand *CryptoRandSource) *TimingController {
	return &TimingController{
		profile:    profile,
		cryptoRand: cryptoRand,
	}
}

// NewSizeController creates a new size controller
func NewSizeController(profile *AdvancedTrafficProfile, cryptoRand *CryptoRandSource) *SizeController {
	return &SizeController{
		profile:    profile,
		cryptoRand: cryptoRand,
	}
}

// NewBurstController creates a new burst controller
func NewBurstController(profile *AdvancedTrafficProfile, cryptoRand *CryptoRandSource) *BurstController {
	return &BurstController{
		profile:    profile,
		cryptoRand: cryptoRand,
	}
}

// GetTimingDelay calculates the next timing delay
func (atm *AdvancedTrafficMorpher) GetTimingDelay(ctx context.Context) time.Duration {
	if !atm.enabled {
		return 0
	}

	select {
	case <-atm.closed:
		return 0
	default:
	}

	delay := atm.timingController.GetNextDelay()

	// Update stats
	atm.stats.mu.Lock()
	atm.stats.TimingVariance = atm.updateVariance(atm.stats.TimingVariance, float64(delay.Microseconds()))
	atm.stats.mu.Unlock()

	return delay
}

// GetNextDelay calculates the next delay based on traffic profile
func (tc *TimingController) GetNextDelay() time.Duration {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Generate normal distribution around interval mean
	mean := tc.profile.IntervalMean.Nanoseconds()
	stdDev := tc.profile.IntervalStdDev.Nanoseconds()

	// Box-Muller transform for normal distribution
	u1 := tc.cryptoRand.Float64()
	u2 := tc.cryptoRand.Float64()

	z0 := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
	delay := time.Duration(mean + int64(float64(stdDev)*z0))

	// Ensure positive delay
	if delay < 0 {
		delay = time.Duration(mean / 4)
	}

	tc.lastDelay = delay
	return delay
}

// MorphFrame applies traffic morphing to a frame
func (atm *AdvancedTrafficMorpher) MorphFrame(frame *Frame) error {
	if !atm.enabled {
		return nil
	}

	select {
	case <-atm.closed:
		return fmt.Errorf("morpher is closed")
	default:
	}

	// Update total frames counter
	atomic.AddUint64(&atm.stats.TotalFrames, 1)

	// Apply size morphing
	if err := atm.sizeController.MorphSize(frame); err != nil {
		return fmt.Errorf("size morphing failed: %w", err)
	}

	// Check for burst pattern
	if atm.burstController.ShouldBurst() {
		atomic.AddUint64(&atm.stats.BurstCount, 1)
	}

	// Update morphed frames counter
	atomic.AddUint64(&atm.stats.MorphedFrames, 1)

	// Update effectiveness score
	atm.updateEffectivenessScore()

	return nil
}

// MorphSize applies size morphing to frame
func (sc *SizeController) MorphSize(frame *Frame) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	originalSize := len(frame.Payload)
	atomic.AddUint64(&sc.totalOriginal, uint64(originalSize))

	// Determine if padding should be added based on profile
	if sc.cryptoRand.Float64() < sc.profile.PaddingRatio {
		// Calculate padding size within profile bounds
		maxPadding := sc.profile.MaxPacketSize - originalSize

		if maxPadding > 0 {
			paddingSize := sc.cryptoRand.Intn(maxPadding)
			padding := make([]byte, paddingSize)

			// Generate cryptographically secure random padding
			if _, err := rand.Read(padding); err != nil {
				// Fallback to pattern-based padding
				for i := range padding {
					padding[i] = byte(sc.cryptoRand.Intn(256))
				}
			}

			// Append padding to frame
			frame.Payload = append(frame.Payload, padding...)
			atomic.AddUint64(&sc.totalPadding, uint64(paddingSize))
		}
	}

	return nil
}

// ShouldBurst determines if a burst pattern should be triggered
func (bc *BurstController) ShouldBurst() bool {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	now := time.Now()

	// Check if currently in a burst
	if bc.burstActive {
		bc.burstRemaining--
		if bc.burstRemaining <= 0 {
			bc.burstActive = false
			bc.lastBurstTime = now
		}
		return true
	}

	// Check if should start new burst
	if now.Sub(bc.lastBurstTime) >= bc.profile.BurstInterval {
		// Use crypto random for burst probability
		if bc.cryptoRand.Float64() < 0.1 { // 10% burst probability
			bc.burstActive = true
			bc.burstRemaining = bc.profile.BurstSize
			return true
		}
	}

	return false
}

// updateVariance updates running variance calculation
func (atm *AdvancedTrafficMorpher) updateVariance(currentVariance, newValue float64) float64 {
	// Simple running variance approximation
	alpha := 0.1 // Learning rate
	return currentVariance*(1-alpha) + alpha*newValue*newValue
}

// updateEffectivenessScore calculates morphing effectiveness
func (atm *AdvancedTrafficMorpher) updateEffectivenessScore() {
	atm.stats.mu.Lock()
	defer atm.stats.mu.Unlock()

	if atm.stats.TotalFrames == 0 {
		return
	}

	// Calculate effectiveness based on various factors
	morphingRatio := float64(atm.stats.MorphedFrames) / float64(atm.stats.TotalFrames)
	timingFactor := 1.0 / (1.0 + atm.stats.TimingVariance/1000000.0) // Normalize microseconds
	sizeFactor := 1.0 / (1.0 + atm.stats.SizeVariance/1000.0)        // Normalize size variance
	burstFactor := math.Min(float64(atm.stats.BurstCount)/float64(atm.stats.TotalFrames)*10, 1.0)

	// Weighted effectiveness score
	atm.stats.EffectivenessScore = 0.4*morphingRatio + 0.3*timingFactor + 0.2*sizeFactor + 0.1*burstFactor
}

// GetStats returns current morphing statistics
func (atm *AdvancedTrafficMorpher) GetStats() MorphingStats {
	atm.stats.mu.RLock()
	defer atm.stats.mu.RUnlock()
	return *atm.stats
}

// GetPaddingRatio returns current padding ratio
func (atm *AdvancedTrafficMorpher) GetPaddingRatio() float64 {
	total := atomic.LoadUint64(&atm.sizeController.totalOriginal)
	padding := atomic.LoadUint64(&atm.sizeController.totalPadding)

	if total == 0 {
		return 0
	}

	return float64(padding) / float64(total)
}

// UpdateConfig updates morphing configuration
func (atm *AdvancedTrafficMorpher) UpdateConfig(config *TrafficShapingConfig) {
	atm.mu.Lock()
	defer atm.mu.Unlock()

	atm.config = config
	atm.enabled = config.EnableMorphing

	// Update profile if changed
	if config.Profile != atm.profile.Name {
		atm.profile = GetAdvancedTrafficProfile(config.Profile)
		atm.timingController.profile = atm.profile
		atm.sizeController.profile = atm.profile
		atm.burstController.profile = atm.profile
	}
}

// Close stops the traffic morpher
func (atm *AdvancedTrafficMorpher) Close() error {
	close(atm.closed)
	return nil
}

// IsEnabled returns whether morphing is currently enabled
func (atm *AdvancedTrafficMorpher) IsEnabled() bool {
	atm.mu.RLock()
	defer atm.mu.RUnlock()
	return atm.enabled
}

// Advanced Steganographic Capabilities for Production-Grade Traffic Camouflage

// HTTPMimicry provides advanced HTTP traffic mimicry
type HTTPMimicry struct {
	enabled      bool
	userAgents   []string
	contentTypes []string
	cryptoRand   *CryptoRandSource
}

// NewHTTPMimicry creates advanced HTTP traffic mimicry
func NewHTTPMimicry(cryptoRand *CryptoRandSource) *HTTPMimicry {
	return &HTTPMimicry{
		enabled: true,
		userAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
		},
		contentTypes: []string{
			"application/json",
			"text/html",
			"application/javascript",
			"text/css",
			"image/png",
			"application/octet-stream",
		},
		cryptoRand: cryptoRand,
	}
}

// ProtocolMimic mimics legitimate protocol patterns
func (hm *HTTPMimicry) ProtocolMimic(data []byte) []byte {
	if !hm.enabled {
		return data
	}

	// Add realistic HTTP-like headers
	userAgent := hm.userAgents[hm.cryptoRand.Intn(len(hm.userAgents))]
	contentType := hm.contentTypes[hm.cryptoRand.Intn(len(hm.contentTypes))]

	// Create steganographic wrapper with request/response pattern
	header := fmt.Sprintf(
		"GET /api/v1/data HTTP/1.1\r\n"+
			"Host: cdn.example.com\r\n"+
			"User-Agent: %s\r\n"+
			"Accept: %s\r\n"+
			"Connection: keep-alive\r\n"+
			"Cache-Control: no-cache\r\n\r\n",
		userAgent, contentType,
	)

	// Embed actual data as base64 in fake response
	encodedData := base64.StdEncoding.EncodeToString(data)
	response := fmt.Sprintf(
		"%s"+
			"HTTP/1.1 200 OK\r\n"+
			"Content-Type: %s\r\n"+
			"Content-Length: %d\r\n\r\n%s",
		header, contentType, len(encodedData), encodedData,
	)

	return []byte(response)
}

// TrafficNormalization provides statistical traffic normalization
type TrafficNormalization struct {
	enabled      bool
	targetMean   float64
	targetStdDev float64
	cryptoRand   *CryptoRandSource
}

// NewTrafficNormalization creates traffic normalization engine
func NewTrafficNormalization(cryptoRand *CryptoRandSource) *TrafficNormalization {
	return &TrafficNormalization{
		enabled:      true,
		targetMean:   1024.0, // Target 1KB mean packet size
		targetStdDev: 256.0,  // 256B standard deviation
		cryptoRand:   cryptoRand,
	}
}

// NormalizePacketSize creates statistically normal packet sizes
func (tn *TrafficNormalization) NormalizePacketSize(originalSize int) int {
	if !tn.enabled {
		return originalSize
	}

	// Generate normally distributed packet size
	normalValue := tn.generateNormal(tn.targetMean, tn.targetStdDev)

	// Ensure reasonable bounds
	normalizedSize := int(normalValue)
	if normalizedSize < 64 {
		normalizedSize = 64
	} else if normalizedSize > 8192 {
		normalizedSize = 8192
	}

	return normalizedSize
}

// generateNormal uses Box-Muller transform for cryptographically secure normal distribution
func (tn *TrafficNormalization) generateNormal(mean, stdDev float64) float64 {
	// Box-Muller transform with crypto rand
	u1 := tn.cryptoRand.Float64()
	u2 := tn.cryptoRand.Float64()

	z0 := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
	return z0*stdDev + mean
}

// DeepPacketInspectionEvasion provides DPI evasion techniques
type DeepPacketInspectionEvasion struct {
	enabled            bool
	fragmentationRatio float64
	cryptoRand         *CryptoRandSource
}

// NewDeepPacketInspectionEvasion creates DPI evasion system
func NewDeepPacketInspectionEvasion(cryptoRand *CryptoRandSource) *DeepPacketInspectionEvasion {
	return &DeepPacketInspectionEvasion{
		enabled:            true,
		fragmentationRatio: 0.3, // 30% of packets get fragmented
		cryptoRand:         cryptoRand,
	}
}

// EvadeDetection applies DPI evasion techniques
func (dpi *DeepPacketInspectionEvasion) EvadeDetection(data []byte) [][]byte {
	if !dpi.enabled || len(data) < 100 {
		return [][]byte{data}
	}

	// Random decision to fragment
	if dpi.cryptoRand.Float64() > dpi.fragmentationRatio {
		return [][]byte{data}
	}

	// Fragment into random sizes
	fragments := make([][]byte, 0)
	remaining := data

	for len(remaining) > 0 {
		// Random fragment size between 50-500 bytes
		fragmentSize := 50 + dpi.cryptoRand.Intn(450)
		if fragmentSize > len(remaining) {
			fragmentSize = len(remaining)
		}

		fragment := make([]byte, fragmentSize)
		copy(fragment, remaining[:fragmentSize])
		fragments = append(fragments, fragment)

		remaining = remaining[fragmentSize:]
	}

	return fragments
}
