package analysis

// Detector interface for pattern detection on call findings
type Detector interface {
	// Detect analyzes call findings and enriches them with pattern-specific information
	// It can modify existing findings or add new ones
	Detect(findings []CallFinding) []CallFinding
}

// DetectorChain runs multiple detectors in sequence
type DetectorChain struct {
	detectors []Detector
}

// NewDetectorChain creates a new detector chain
func NewDetectorChain(detectors ...Detector) *DetectorChain {
	return &DetectorChain{
		detectors: detectors,
	}
}

// Detect runs all detectors in sequence
func (dc *DetectorChain) Detect(findings []CallFinding) []CallFinding {
	result := findings
	for _, detector := range dc.detectors {
		result = detector.Detect(result)
	}
	return result
}
