package internal

// CustomTokens is a type that represents a collection of pairs (key, value)
// that can be used to replace certain tokens (i.e. placeholders) in a [request.Request].
type CustomTokens = map[string]string
