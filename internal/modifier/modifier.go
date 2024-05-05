package modifier

import scan "github.com/bountysecurity/gbounty/internal"

// Modifiers returns a list of all available modifiers
// within the `modifier` package.
func Modifiers() []scan.Modifier {
	return []scan.Modifier{
		NewHTTPMethod(),
		NewMatchAndReplace(),
		NewRandom(),
		NewTemplate(),
		NewTimeout(),
		//NewInteractionHost(), - intentionally commented, as it is created on demand.
	}
}
