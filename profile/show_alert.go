package profile

const (
	ShowAlertNone   ShowAlertType = "none"
	ShowAlertOne    ShowAlertType = "one"
	ShowAlertAlways ShowAlertType = "always"
)

// ShowAlertType represents the type of alert to show.
type ShowAlertType string

// Enabled returns true if the alert type is one or always.
func (t ShowAlertType) Enabled() bool { return t.One() || t.Always() }

// None returns true if the alert type is none.
func (t ShowAlertType) None() bool { return t == ShowAlertNone }

// One returns true if the alert type is one.
func (t ShowAlertType) One() bool { return t == ShowAlertOne }

// Always returns true if the alert type is always.
func (t ShowAlertType) Always() bool { return t == ShowAlertAlways }
