// Package detectors finds XXTEA encryption keys in binaries.
// It analyzes setter functions to extract encryption keys and signatures.
package detectors

import (
	"fmt"
	"strings"

	"reverse/internal/analysis"
)

// XXTEADetector detects XXTEA encryption keys in binary files.
// It analyzes setter functions to extract keys and signatures.
type XXTEADetector struct{}

// NewXXTEADetector creates a new XXTEA detector instance.
func NewXXTEADetector() *XXTEADetector {
	return &XXTEADetector{}
}

var knownVTableOffsets = []string{
	"vtable+0xe8",
	"vtable+0x232",
	"vtable+0x90", // BaseGame::setXXTeaKey offset
}

func (d *XXTEADetector) Detect(findings []analysis.CallFinding) []analysis.CallFinding {
	result := make([]analysis.CallFinding, 0, len(findings))

	for _, finding := range findings {
		resolved := finding

		sig := d.signatureType(finding)

		// Check if we should resolve based on various conditions
		shouldResolve := false

		if d.isXXTEASetter(finding.Target) || d.isXXTEASetter(finding.Symbol) {
			shouldResolve = true
		}

		if strings.HasPrefix(finding.Symbol, "sub_") && sig != "unknown" {
			shouldResolve = true
		}

		if (strings.HasPrefix(finding.Target, "[indirect]") || strings.HasPrefix(finding.Target, "[virtual]")) && sig != "unknown" {
			shouldResolve = true
		}

		for _, offset := range knownVTableOffsets {
			if strings.Contains(finding.Target, offset) {
				shouldResolve = true
				break
			}
		}

		if shouldResolve {
			resolved = d.resolveBySignature(resolved, sig)
		}

		result = append(result, resolved)
	}

	return result
}

func (d *XXTEADetector) resolveBySignature(finding analysis.CallFinding, sig string) analysis.CallFinding {
	if finding.Metadata == nil {
		finding.Metadata = make(map[string]interface{})
	}

	finding.Metadata["signature_type"] = sig

	switch sig {
	case "key+sign":
		d.extractKeySign(&finding)
		finding.Comment = d.genKeySignComment(finding)
	case "key-only":
		d.extractKeyOnly(&finding)
		finding.Comment = d.genKeyOnlyComment(finding)
	case "std::string-single":
		d.extractStdString(&finding)
		finding.Comment = d.genStdStringComment(finding)
	case "std::string-dual":
		d.extractDualStdString(&finding)
		finding.Comment = d.genDualStdStringComment(finding)
	default:
		finding.Comment = d.genComment(finding)
	}

	return finding
}

func (d *XXTEADetector) isXXTEASetter(name string) bool {
	lower := strings.ToLower(name)

	xxteaSetters := []string{
		"setxxteakey",
		"setxxteasign",
		"setxxteakeyandsign",
		"jsb_set_xxtea_key",
		"addcryptokey",
		"editcryptokey",
	}

	for _, setter := range xxteaSetters {
		if strings.Contains(lower, setter) {
			return true
		}
	}

	hasAction := strings.Contains(lower, "set") ||
		strings.Contains(lower, "add") ||
		strings.Contains(lower, "edit")
	hasTarget := strings.Contains(lower, "xxtea") ||
		strings.Contains(lower, "cryptokey")

	return hasAction && hasTarget
}

func (d *XXTEADetector) signatureType(finding analysis.CallFinding) string {
	hasX0String := false
	hasX0Pointer := false
	hasX1String := false
	hasX1CharPtr := false
	hasX3CharPtr := false
	var keyLen, signLen int64

	for _, arg := range finding.Args {
		switch arg.Reg {
		case "x0":
			if _, ok := arg.Value.(string); ok {
				hasX0String = true
			}
			if arg.Value != nil {
				hasX0Pointer = true
			}
		case "x1":
			if _, ok := arg.Value.(string); ok {
				hasX1String = true
				hasX1CharPtr = true
			}
		case "w2", "x2":
			if val, ok := arg.Value.(int64); ok {
				keyLen = val
			} else if val, ok := arg.Value.(uint64); ok {
				keyLen = int64(val)
			}
		case "x3":
			if _, ok := arg.Value.(string); ok {
				hasX3CharPtr = true
			}
		case "w4", "x4":
			if val, ok := arg.Value.(int64); ok {
				signLen = val
			} else if val, ok := arg.Value.(uint64); ok {
				signLen = int64(val)
			}
		}
	}

	if (hasX0String || hasX0Pointer) && keyLen == 0 && signLen == 0 {
		if hasX1String {
			return "std::string-dual"
		}
		return "std::string-single"
	}

	if hasX1CharPtr && keyLen > 0 {
		if hasX3CharPtr && signLen > 0 {
			return "key+sign"
		}
		return "key-only"
	}

	return "unknown"
}

func (d *XXTEADetector) genStdStringComment(finding analysis.CallFinding) string {
	if finding.Metadata != nil {
		if key, hasKey := finding.Metadata["key"].(string); hasKey {
			if key == "" {
				return "key=(empty)"
			}
			return "key=" + key
		}
	}
	return "key=(unknown)"
}

func (d *XXTEADetector) genDualStdStringComment(finding analysis.CallFinding) string {
	var parts []string

	if finding.Metadata != nil {
		if key, hasKey := finding.Metadata["key"].(string); hasKey {
			if key == "" {
				parts = append(parts, "key=(empty)")
			} else {
				parts = append(parts, "key="+key)
			}
		} else {
			parts = append(parts, "key=(unknown)")
		}

		if sign, hasSign := finding.Metadata["sign"].(string); hasSign {
			if sign == "" {
				parts = append(parts, "sign=(empty)")
			} else {
				parts = append(parts, "sign="+sign)
			}
		} else {
			parts = append(parts, "sign=(unknown)")
		}
	} else {
		parts = append(parts, "key=(unknown)", "sign=(unknown)")
	}

	return strings.Join(parts, ", ")
}

func (d *XXTEADetector) genKeyOnlyComment(finding analysis.CallFinding) string {
	var key string
	var keyLen int64

	for _, arg := range finding.Args {
		switch arg.Reg {
		case "x1":
			if str, ok := arg.Value.(string); ok {
				key = str
			}
		case "w2", "x2":
			if val, ok := arg.Value.(int64); ok {
				keyLen = val
			} else if val, ok := arg.Value.(uint64); ok {
				keyLen = int64(val)
			}
		}
	}

	if key != "" {
		return "key=" + key
	} else if keyLen > 0 {
		return "key=(unknown,len=" + strings.TrimSpace(fmt.Sprintf("%d", keyLen)) + ")"
	}
	return "key=(unknown)"
}

func (d *XXTEADetector) genKeySignComment(finding analysis.CallFinding) string {
	var key, sign string
	var keyLen, signLen int64

	for _, arg := range finding.Args {
		switch arg.Reg {
		case "x1":
			if str, ok := arg.Value.(string); ok {
				key = str
			}
		case "w2", "x2":
			if val, ok := arg.Value.(int64); ok {
				keyLen = val
			} else if val, ok := arg.Value.(uint64); ok {
				keyLen = int64(val)
			}
		case "x3":
			if str, ok := arg.Value.(string); ok {
				sign = str
			}
		case "w4", "x4":
			if val, ok := arg.Value.(int64); ok {
				signLen = val
			} else if val, ok := arg.Value.(uint64); ok {
				signLen = int64(val)
			}
		}
	}

	var parts []string

	if key != "" {
		parts = append(parts, "key="+key)
	} else if keyLen > 0 {
		parts = append(parts, "key=(unknown,len="+strings.TrimSpace(fmt.Sprintf("%d", keyLen))+")")
	} else {
		parts = append(parts, "key=(unknown)")
	}

	if sign != "" {
		parts = append(parts, "sign="+sign)
	} else if signLen > 0 {
		parts = append(parts, "sign=(unknown,len="+strings.TrimSpace(fmt.Sprintf("%d", signLen))+")")
	} else {
		parts = append(parts, "sign=(unknown)")
	}

	return strings.Join(parts, ", ")
}

func (d *XXTEADetector) extractKeySign(finding *analysis.CallFinding) {
	for _, arg := range finding.Args {
		switch arg.Reg {
		case "x1":
			if str, ok := arg.Value.(string); ok {
				finding.Metadata["key"] = str
			}
		case "w2", "x2":
			if val, ok := arg.Value.(int64); ok {
				finding.Metadata["key_len"] = val
			} else if val, ok := arg.Value.(uint64); ok {
				finding.Metadata["key_len"] = int64(val)
			}
		case "x3":
			if str, ok := arg.Value.(string); ok {
				finding.Metadata["sign"] = str
			}
		case "w4", "x4":
			if val, ok := arg.Value.(int64); ok {
				finding.Metadata["sign_len"] = val
			} else if val, ok := arg.Value.(uint64); ok {
				finding.Metadata["sign_len"] = int64(val)
			}
		}
	}
}

func (d *XXTEADetector) extractKeyOnly(finding *analysis.CallFinding) {
	for _, arg := range finding.Args {
		switch arg.Reg {
		case "x1":
			if str, ok := arg.Value.(string); ok {
				finding.Metadata["key"] = str
			}
		case "w2", "x2":
			if val, ok := arg.Value.(int64); ok {
				finding.Metadata["key_len"] = val
			} else if val, ok := arg.Value.(uint64); ok {
				finding.Metadata["key_len"] = int64(val)
			}
		}
	}
}

func (d *XXTEADetector) extractStdString(finding *analysis.CallFinding) {
	var x0Count int
	for _, arg := range finding.Args {
		if arg.Reg == "x0" {
			x0Count++
			if str, ok := arg.Value.(string); ok {
				if x0Count == 1 {
					finding.Metadata["key"] = str
					finding.Metadata["key_len"] = int64(len(str))
					break
				}
			}
		}
	}
}

func (d *XXTEADetector) extractDualStdString(finding *analysis.CallFinding) {
	var key, sign string

	for _, arg := range finding.Args {
		switch arg.Reg {
		case "x0":
			if str, ok := arg.Value.(string); ok {
				key = str
			}
		case "x1":
			if str, ok := arg.Value.(string); ok {
				sign = str
			}
		}
	}

	if key != "" {
		finding.Metadata["key"] = key
		finding.Metadata["key_len"] = int64(len(key))
	}
	if sign != "" {
		finding.Metadata["sign"] = sign
		finding.Metadata["sign_len"] = int64(len(sign))
	}
}

func (d *XXTEADetector) genComment(finding analysis.CallFinding) string {
	var parts []string

	var key, sign string
	var keyLen, signLen int64

	for _, arg := range finding.Args {
		switch arg.Reg {
		case "x1":
			if str, ok := arg.Value.(string); ok {
				key = str
			}
		case "w2", "x2":
			if val, ok := arg.Value.(int64); ok {
				keyLen = val
			}
		case "x3":
			if str, ok := arg.Value.(string); ok {
				sign = str
			}
		case "w4", "x4":
			if val, ok := arg.Value.(int64); ok {
				signLen = val
			}
		}
	}

	if key != "" {
		parts = append(parts, "key="+key)
	} else if keyLen > 0 {
		parts = append(parts, "key=(unknown)")
	}

	if sign != "" {
		parts = append(parts, "sign="+sign)
	} else if signLen > 0 {
		parts = append(parts, "sign=(unknown)")
	}

	if len(parts) > 0 {
		return strings.Join(parts, ", ")
	}

	return ""
}
