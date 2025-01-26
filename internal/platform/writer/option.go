package writer

// WithOptions is an interface that defines the expected behavior for [gbounty.Writer] implementations on this
// package that can be configured with [Option]. It's mostly a composition of all the concrete interfaces.
type WithOptions interface {
	WithProofOfConcept
}

// WithProofOfConcept is an interface that defines the expected behavior for [gbounty.Writer] implementations on this
// package that can be configured with [WithProofOfConceptEnabled].
type WithProofOfConcept interface {
	SetProofOfConcept(enabled bool)
}

// Option is a function that can be used to configure a [WithOptions] implementation.
type Option func(WithOptions)

// WithProofOfConceptEnabled is a [ConsoleOption] that enables the proof-of-concept mode.
// When enabled, the console will print the matches in a copy & paste friendlier format.
func WithProofOfConceptEnabled(enabled bool) func(WithOptions) {
	return func(w WithOptions) {
		w.SetProofOfConcept(enabled)
	}
}
