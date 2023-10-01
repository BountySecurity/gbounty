package profile

// Provider is the interface that defines the expected
// behavior of a profile provider.
//
// For instance, the FileProvider provides profiles from
// one or multiple file-disk location.
type Provider interface {
	Actives() []*Active
	ActivesEnabled() []*Active

	PassiveReqs() []*Request
	PassiveReqsEnabled() []*Request

	PassiveRes() []*Response
	PassiveResEnabled() []*Response

	Tags() []string

	From() []string
}

func enabled[P Profile](profiles []P) []P {
	enabled := make([]P, 0, len(profiles))
	for _, profile := range profiles {
		if !profile.IsEnabled() {
			continue
		}
		enabled = append(enabled, profile)
	}
	return enabled
}
