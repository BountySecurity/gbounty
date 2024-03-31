package jsonmap

import (
	"bytes"
	"encoding/json"
	"errors"
)

// ErrUnexpectedToken is the error returned when an unexpected
// token is found while decoding (i.e. unmarshalling) an ordered map.
var ErrUnexpectedToken = errors.New("unexpected token")

// Ordered is a structure that keeps a JSON map preserving
// the order of the keys as they were in the original JSON object.
type Ordered struct {
	Order []string
	Data  map[string]interface{}
}

// UnmarshalJSON unmarshal a JSON object into an Ordered map.
func (o *Ordered) UnmarshalJSON(b []byte) error {
	if o.Data == nil {
		o.Data = map[string]interface{}{}
	}

	err := json.Unmarshal(b, &o.Data)
	if err != nil {
		return err
	}

	dec := json.NewDecoder(bytes.NewReader(b))

	if _, err = dec.Token(); err != nil { // skip '{'
		return err
	}

	o.Order = make([]string, 0, len(o.Data))

	return decodeOrderedMap(dec, o)
}

func decodeOrderedMap(dec *json.Decoder, o *Ordered) error {
	hasKey := make(map[string]bool, len(o.Data))

	for {
		token, err := dec.Token()
		if err != nil {
			return err
		}

		if delim, ok := token.(json.Delim); ok && delim == '}' {
			return nil
		}

		key, ok := token.(string)
		if !ok {
			return ErrUnexpectedToken
		}

		if hasKey[key] {
			// duplicate key
			for j, k := range o.Order {
				if k == key {
					copy(o.Order[j:], o.Order[j+1:])
					break
				}
			}

			o.Order[len(o.Order)-1] = key
		} else {
			hasKey[key] = true
			o.Order = append(o.Order, key)
		}

		token, err = dec.Token()
		if err != nil {
			return err
		}

		if delim, ok := token.(json.Delim); ok { //nolint:nestif
			switch delim {
			case '{':
				if values, ok := o.Data[key].(map[string]interface{}); ok {
					newMap := Ordered{
						Order: make([]string, 0, len(values)),
						Data:  values,
					}

					if err = decodeOrderedMap(dec, &newMap); err != nil {
						return err
					}

					o.Data[key] = newMap
				} else if oldMap, ok := o.Data[key].(Ordered); ok {
					newMap := Ordered{
						Order: make([]string, 0, len(oldMap.Data)),
						Data:  oldMap.Data,
					}

					if err = decodeOrderedMap(dec, &newMap); err != nil {
						return err
					}

					o.Data[key] = newMap
				} else if err = decodeOrderedMap(dec, &Ordered{}); err != nil {
					return err
				}

			case '[':
				if values, ok := o.Data[key].([]interface{}); ok {
					if err = decodeSlice(dec, values); err != nil {
						return err
					}
				} else if err = decodeSlice(dec, []interface{}{}); err != nil {
					return err
				}
			}
		}
	}
}

func decodeSlice(dec *json.Decoder, s []interface{}) error {
	for index := 0; ; index++ {
		token, err := dec.Token()
		if err != nil {
			return err
		}

		if delim, ok := token.(json.Delim); ok { //nolint:nestif
			switch delim {
			case '{':
				if index < len(s) {
					if values, ok := s[index].(map[string]interface{}); ok {
						newMap := Ordered{
							Order: make([]string, 0, len(values)),
							Data:  values,
						}

						if err = decodeOrderedMap(dec, &newMap); err != nil {
							return err
						}

						s[index] = newMap
					} else if oldMap, ok := s[index].(Ordered); ok {
						newMap := Ordered{
							Order: make([]string, 0, len(oldMap.Data)),
							Data:  oldMap.Data,
						}

						if err = decodeOrderedMap(dec, &newMap); err != nil {
							return err
						}

						s[index] = newMap
					} else if err = decodeOrderedMap(dec, &Ordered{}); err != nil {
						return err
					}
				} else if err = decodeOrderedMap(dec, &Ordered{}); err != nil {
					return err
				}
			case '[':
				if index < len(s) {
					if values, ok := s[index].([]interface{}); ok {
						if err = decodeSlice(dec, values); err != nil {
							return err
						}
					} else if err = decodeSlice(dec, []interface{}{}); err != nil {
						return err
					}
				} else if err = decodeSlice(dec, []interface{}{}); err != nil {
					return err
				}
			case ']':
				return nil
			}
		}
	}
}

func (o Ordered) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer

	buf.WriteByte('{')

	encoder := json.NewEncoder(&buf)

	for i, k := range o.Order {
		if i > 0 {
			buf.WriteByte(',')
		}
		// add key
		if err := encoder.Encode(k); err != nil {
			return nil, err
		}

		buf.WriteByte(':')
		// add value
		if err := encoder.Encode(o.Data[k]); err != nil {
			return nil, err
		}
	}

	buf.WriteByte('}')

	return buf.Bytes(), nil
}
