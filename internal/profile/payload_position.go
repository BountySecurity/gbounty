package profile

const (
	Replace PayloadPosition = "replace"
	Append  PayloadPosition = "append"
	Insert  PayloadPosition = "insert"
)

// PayloadPosition represents the position of the payload.
type PayloadPosition string
