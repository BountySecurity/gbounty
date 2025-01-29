package entrypoint

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/BountySecurity/gbounty/kit/jsonmap"
	"github.com/BountySecurity/gbounty/request"
)

// JSONParamFinder must implement the Finder interface.
var _ Finder = JSONParamFinder{}

// JSONParamFinder is used to find entrypoints in the request's JSON body.
type JSONParamFinder struct{}

// NewJSONParamFinder instantiates a new JSONParamFinder.
func NewJSONParamFinder() JSONParamFinder {
	return JSONParamFinder{}
}

func (f JSONParamFinder) Find(req request.Request) []Entrypoint {
	var body jsonmap.Ordered
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return nil
	}

	return f.parseMap(body, body)
}

func (f JSONParamFinder) parseMap(root, elems jsonmap.Ordered) []Entrypoint {
	var entrypoints []Entrypoint

	for idx, key := range elems.Order {
		elems.Order[idx] = strconv.Itoa(jsonReplacer)
		tmp := elems.Data[key]
		delete(elems.Data, key)
		elems.Data[strconv.Itoa(jsonReplacer)] = tmp

		if bytes, err := json.Marshal(root); err == nil {
			entrypoints = append(entrypoints, newJSONParamName(string(bytes), key))
		}

		elems.Order[idx] = key
		delete(elems.Data, strconv.Itoa(jsonReplacer))
		elems.Data[key] = tmp

		switch val := elems.Data[key].(type) {
		case jsonmap.Ordered:
			entrypoints = append(entrypoints, f.parseMap(root, val)...)
		case []interface{}:
			entrypoints = append(entrypoints, f.parseArray(root, key, val)...)
		default:
			tmp := elems.Data[key]

			if _, ok := tmp.(string); ok {
				elems.Data[key] = strconv.Itoa(jsonReplacer)
			} else {
				elems.Data[key] = jsonReplacer
			}

			if bytes, err := json.Marshal(root); err == nil {
				if _, ok := val.(string); ok {
					entrypoints = append(entrypoints, newJSONParamValue(string(bytes), key, fmt.Sprintf("%s", val)))
				} else if valBytes, err := json.Marshal(val); err == nil {
					entrypoints = append(entrypoints, newJSONParamValue(string(bytes), key, string(valBytes)))
				}
			}

			elems.Data[key] = tmp
		}
	}

	return entrypoints
}

func (f JSONParamFinder) parseArray(root jsonmap.Ordered, key string, elems []interface{}) []Entrypoint {
	var entrypoints []Entrypoint

	for i, elem := range elems {
		arrKey := key + "[" + strconv.Itoa(i) + "]"

		switch val := elem.(type) {
		case jsonmap.Ordered:
			entrypoints = append(entrypoints, f.parseMap(root, val)...)
		case []interface{}:
			entrypoints = append(entrypoints, f.parseArray(root, arrKey, val)...)
		default:
			if _, ok := val.(string); ok {
				elems[i] = strconv.Itoa(jsonReplacer)
			} else {
				elems[i] = jsonReplacer
			}

			if bytes, err := json.Marshal(root); err == nil {
				if _, ok := val.(string); ok {
					entrypoints = append(entrypoints, newJSONParamValue(string(bytes), arrKey, fmt.Sprintf("%s", val)))
				} else if valBytes, err := json.Marshal(val); err == nil {
					entrypoints = append(entrypoints, newJSONParamValue(string(bytes), arrKey, string(valBytes)))
				}
			}

			elems[i] = val
		}
	}

	return entrypoints
}
