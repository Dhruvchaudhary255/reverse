package analysis

type SetterSignature int

const (
	Sig4Arg SetterSignature = iota
	Sig2Arg
	Sig1Arg
	SigUnknown
)

type CallArgs struct {
	Signature       SetterSignature
	KeyVA           uint64
	Key             string
	KeyLen          int
	SignVA          uint64
	Sign            string
	SignLen         int
	UsesStdString   bool
	RequiresRuntime bool
}
