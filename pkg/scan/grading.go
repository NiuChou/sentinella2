package scan

// ConfidenceGrade categorizes a finding's confidence level.
type ConfidenceGrade string

const (
	// GradeConfirmed means confidence > 0.7.
	GradeConfirmed ConfidenceGrade = "Confirmed"
	// GradeLikely means confidence is in [0.3, 0.7].
	GradeLikely ConfidenceGrade = "Likely"
	// GradeSuspect means confidence < 0.3.
	GradeSuspect ConfidenceGrade = "Suspect"
)

// Grade returns the confidence grade for a finding.
func (f Finding) Grade() ConfidenceGrade {
	switch {
	case f.Confidence > 0.7:
		return GradeConfirmed
	case f.Confidence >= 0.3:
		return GradeLikely
	default:
		return GradeSuspect
	}
}

// GradedResult wraps a set of findings split into confidence tiers.
type GradedResult struct {
	All       []Finding
	Confirmed []Finding // confidence > 0.7
	Likely    []Finding // 0.3 - 0.7
	Suspect   []Finding // < 0.3
}

// GradeFindings splits findings into confidence tiers.
// The returned slices are independent copies; mutations do not affect the input.
func GradeFindings(findings []Finding) GradedResult {
	result := GradedResult{
		All: make([]Finding, len(findings)),
	}
	copy(result.All, findings)

	for _, f := range findings {
		switch f.Grade() {
		case GradeConfirmed:
			result.Confirmed = append(result.Confirmed, f)
		case GradeLikely:
			result.Likely = append(result.Likely, f)
		case GradeSuspect:
			result.Suspect = append(result.Suspect, f)
		}
	}
	return result
}
