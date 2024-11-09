package profile

// Active must implement the Profile interface.
var _ Profile = Active{}

// Active represents an active profile.
type Active struct {
	// Basic information
	Name    string   `json:"profile_name"`
	Enabled bool     `json:"enabled"`
	Type    Type     `json:"scanner"`
	Author  string   `json:"author"`
	Tags    []string `json:"Tags"`

	Steps []Step `json:"steps"`
}

// GetName returns the name of the active profile.
func (a Active) GetName() string {
	return a.Name
}

// GetType returns the type of the active profile.
func (a Active) GetType() Type {
	return a.Type
}

// IsEnabled returns whether the active profile is enabled.
func (a Active) IsEnabled() bool {
	return a.Enabled
}

// GetTags returns the tags of the active profile.
func (a Active) GetTags() []string {
	return a.Tags
}

func (a Active) GetSteps() []Step {
	return a.Steps
}
