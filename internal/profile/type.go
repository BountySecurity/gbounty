package profile

const (
	TypeActive     Type = "active"
	TypePassiveReq Type = "passive_request"
	TypePassiveRes Type = "passive_response"
)

// Type represents the type of profile.
type Type string

// String returns the string representation of the profile type.
func (t Type) String() string {
	switch t {
	case TypeActive:
		return "Active"
	case TypePassiveReq:
		return "Passive Request"
	case TypePassiveRes:
		return "Passive Response"
	default:
		return unknown
	}
}

// Active returns true if the profile type is active.
func (t Type) Active() bool {
	return t == TypeActive
}

// PassiveReq returns true if the profile type is passive request.
func (t Type) PassiveReq() bool {
	return t == TypePassiveReq
}

// PassiveRes returns true if the profile type is passive response.
func (t Type) PassiveRes() bool {
	return t == TypePassiveRes
}
