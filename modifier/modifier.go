package modifier

import "github.com/BountySecurity/gbounty"

// Modifiers returns a list of all available modifiers
// within the `modifier` package.
func Modifiers() []gbounty.Modifier {
	return []gbounty.Modifier{
		NewHTTPMethod(),
		NewMatchAndReplace(),
		NewRandom(),
		NewTemplate(),
		NewTimeout(),
		// NewInteractionHost(), - intentionally commented, as it is created on demand.
	}
}
