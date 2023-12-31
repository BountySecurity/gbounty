package jsonmap_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bountysecurity/gbounty/kit/jsonmap"
)

func TestBlankMarshalJSON(t *testing.T) {
	t.Parallel()

	o := &jsonmap.Ordered{}
	// blank map
	b, err := json.Marshal(o)
	if err != nil {
		t.Error("Marshalling blank map to json", err)
	}

	// check json is correctly ordered
	if s := string(b); s != `{}` {
		t.Error("JSON Marshaling blank map value is incorrect", s)
	}
	// convert to indented json
	bi, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		t.Error("Marshalling indented json for blank map", err)
	}

	if si := string(bi); si != (`{}`) {
		t.Error("JSON MarshalIndent blank map value is incorrect", `{}`, si)
	}
}

func TestUnmarshalJSON(t *testing.T) {
	t.Parallel()

	s := `{
  "number": 4,
  "string": "x",
  "z": 1,
  "a": "should not break with unclosed { character in value",
  "b": 3,
  "slice": [
    "1",
    1
  ],
  "orderedmap": {
    "e": 1,
    "a { nested key with brace": "with a }}}} }} {{{ brace value",
	"after": {
		"link": "test {{{ with even deeper nested braces }"
	}
  },
  "test\"ing": 9,
  "after": 1,
  "multitype_array": [
    "test",
	1,
	{ "map": "obj", "it" : 5, ":colon in key": "colon: in value" },
	[{"inner": "map"}]
  ],
  "should not break with { character in key": 1
}`
	o := jsonmap.Ordered{}

	err := json.Unmarshal([]byte(s), &o)
	if err != nil {
		t.Error("JSON Unmarshal error", err)
	}
	// Check the root keys
	expectedKeys := []string{
		"number",
		"string",
		"z",
		"a",
		"b",
		"slice",
		"orderedmap",
		"test\"ing",
		"after",
		"multitype_array",
		"should not break with { character in key",
	}

	k := o.Order
	for i := range k {
		if k[i] != expectedKeys[i] {
			t.Error("Unmarshal root key order", i, k[i], "!=", expectedKeys[i])
		}
	}

	// Check nested maps are converted to orderedmaps
	// nested 1 level deep
	expectedKeys = []string{
		"e",
		"a { nested key with brace",
		"after",
	}

	vi, ok := o.Data["orderedmap"]
	if !ok {
		t.Error("Missing key for nested map 1 deep")
	}

	v, ok := vi.(jsonmap.Ordered)
	require.True(t, ok)

	k = v.Order

	for i := range k {
		if k[i] != expectedKeys[i] {
			t.Error("Key order for nested map 1 deep ", i, k[i], "!=", expectedKeys[i])
		}
	}
	// nested 2 levels deep
	expectedKeys = []string{
		"link",
	}

	vi, ok = v.Data["after"]
	if !ok {
		t.Error("Missing key for nested map 2 deep")
	}

	v, ok = vi.(jsonmap.Ordered)
	require.True(t, ok)

	k = v.Order

	for i := range k {
		if k[i] != expectedKeys[i] {
			t.Error("Key order for nested map 2 deep", i, k[i], "!=", expectedKeys[i])
		}
	}
	// multitype array
	expectedKeys = []string{
		"map",
		"it",
		":colon in key",
	}

	vislice, ok := o.Data["multitype_array"]
	require.True(t, ok)

	vslice, ok := vislice.([]interface{})
	require.True(t, ok)

	vmap, ok := vslice[2].(jsonmap.Ordered)
	require.True(t, ok)

	k = vmap.Order

	for i := range k {
		if k[i] != expectedKeys[i] {
			t.Error("Key order for nested map 2 deep", i, k[i], "!=", expectedKeys[i])
		}
	}
	// nested map 3 deep
	vislice = o.Data["multitype_array"]

	vslice, ok = vislice.([]interface{})
	require.True(t, ok)

	expectedKeys = []string{"inner"}

	vinnerslice, ok := vslice[3].([]interface{})
	require.True(t, ok)

	vinnermap, ok := vinnerslice[0].(jsonmap.Ordered)
	require.True(t, ok)

	k = vinnermap.Order
	for i := range k {
		if k[i] != expectedKeys[i] {
			t.Error("Key order for nested map 3 deep", i, k[i], "!=", expectedKeys[i])
		}
	}
}

func TestUnmarshalJSONDuplicateKeys(t *testing.T) {
	t.Parallel()

	s := `{
		"a": [{}, []],
		"b": {"x":[1]},
		"c": "x",
		"d": {"x":1},
		"b": [{"x":[]}],
		"c": 1,
		"d": {"y": 2},
		"e": [{"x":1}],
		"e": [[]],
		"e": [{"z":2}],
		"a": {},
		"b": [[1]]
	}`
	o := jsonmap.Ordered{}

	err := json.Unmarshal([]byte(s), &o)
	if err != nil {
		t.Error("JSON Unmarshal error with special chars", err)
	}

	expectedKeys := []string{
		"c",
		"d",
		"e",
		"a",
		"b",
	}

	keys := o.Order
	if len(keys) != len(expectedKeys) {
		t.Error("Unmarshal key count", len(keys), "!=", len(expectedKeys))
	}

	for i, key := range keys {
		if key != expectedKeys[i] {
			t.Errorf("Unmarshal root key order: %d, %q != %q", i, key, expectedKeys[i])
		}
	}

	vimap := o.Data["a"]

	_, ok := vimap.(jsonmap.Ordered)
	require.True(t, ok)

	vislice := o.Data["b"]

	_, ok = vislice.([]interface{})
	require.True(t, ok)

	vival := o.Data["c"]

	_, ok = vival.(float64)
	require.True(t, ok)

	vimap = o.Data["d"]

	m, ok := vimap.(jsonmap.Ordered)
	require.True(t, ok)

	expectedKeys = []string{"y"}
	keys = m.Order

	if len(keys) != len(expectedKeys) {
		t.Error("Unmarshal key count", len(keys), "!=", len(expectedKeys))
	}

	for i, key := range keys {
		if key != expectedKeys[i] {
			t.Errorf("Unmarshal key order: %d, %q != %q", i, key, expectedKeys[i])
		}
	}

	vislice = o.Data["e"]

	m, ok = vislice.([]interface{})[0].(jsonmap.Ordered)
	require.True(t, ok)

	expectedKeys = []string{"z"}
	keys = m.Order

	if len(keys) != len(expectedKeys) {
		t.Error("Unmarshal key count", len(keys), "!=", len(expectedKeys))
	}

	for i, key := range keys {
		if key != expectedKeys[i] {
			t.Errorf("Unmarshal key order: %d, %q != %q", i, key, expectedKeys[i])
		}
	}
}

func TestUnmarshalJSONSpecialChars(t *testing.T) {
	t.Parallel()

	s := `{ " \u0041\n\r\t\\\\\\\\\\\\ "  : { "\\\\\\" : "\\\\\"\\" }, "\\":  " \\\\ test ", "\n": "\r" }`
	o := jsonmap.Ordered{}

	err := json.Unmarshal([]byte(s), &o)
	if err != nil {
		t.Error("JSON Unmarshal error with special chars", err)
	}

	expectedKeys := []string{
		" \u0041\n\r\t\\\\\\\\\\\\ ",
		"\\",
		"\n",
	}

	keys := o.Order
	if len(keys) != len(expectedKeys) {
		t.Error("Unmarshal key count", len(keys), "!=", len(expectedKeys))
	}

	for i, key := range keys {
		if key != expectedKeys[i] {
			t.Errorf("Unmarshal root key order: %d, %q != %q", i, key, expectedKeys[i])
		}
	}
}

func TestUnmarshalJSONArrayOfMaps(t *testing.T) {
	t.Parallel()

	s := `
{
  "name": "test",
  "percent": 6,
  "breakdown": [
    {
      "name": "a",
      "percent": 0.9
    },
    {
      "name": "b",
      "percent": 0.9
    },
    {
      "name": "d",
      "percent": 0.4
    },
    {
      "name": "e",
      "percent": 2.7
    }
  ]
}
`
	o := jsonmap.Ordered{}

	err := json.Unmarshal([]byte(s), &o)
	if err != nil {
		t.Error("JSON Unmarshal error", err)
	}

	// Check the root keys
	expectedKeys := []string{
		"name",
		"percent",
		"breakdown",
	}

	k := o.Order
	for i := range k {
		if k[i] != expectedKeys[i] {
			t.Error("Unmarshal root key order", i, k[i], "!=", expectedKeys[i])
		}
	}

	// Check nested maps are converted to orderedmaps
	// nested 1 level deep
	expectedKeys = []string{
		"name",
		"percent",
	}

	vi, ok := o.Data["breakdown"]
	if !ok {
		t.Error("Missing key for nested map 1 deep")
	}

	vs, ok := vi.([]interface{})
	require.True(t, ok)

	for _, vInterface := range vs {
		v, ok := vInterface.(jsonmap.Ordered)
		require.True(t, ok)

		k = v.Order

		for i := range k {
			if k[i] != expectedKeys[i] {
				t.Error("Key order for nested map 1 deep ", i, k[i], "!=", expectedKeys[i])
			}
		}
	}
}

func TestUnmarshalJSONStruct(t *testing.T) {
	t.Parallel()

	var v struct {
		Data *jsonmap.Ordered `json:"data"`
	}

	err := json.Unmarshal([]byte(`{ "data": { "x": 1 } }`), &v)
	if err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}

	x, ok := v.Data.Data["x"]
	if !ok {
		t.Errorf("missing expected key")
	} else if x != float64(1) {
		t.Errorf("unexpected value: %#v", x)
	}
}

func TestOrderedMap_empty_array(t *testing.T) {
	t.Parallel()

	srcStr := `{"x":[]}`
	src := []byte(srcStr)
	o := jsonmap.Ordered{}

	if err := json.Unmarshal(src, &o); err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}

	bs, err := json.Marshal(&o)
	require.NoError(t, err)

	if marshalledStr := string(bs); marshalledStr != srcStr {
		t.Error("Empty array does not serialise to json correctly")
		t.Error("Expect", srcStr)
		t.Error("Got", marshalledStr)
	}
}

func TestOrderedMap_empty_map(t *testing.T) {
	t.Parallel()

	srcStr := `{"x":{}}`
	src := []byte(srcStr)
	o := jsonmap.Ordered{}

	err := json.Unmarshal(src, &o)
	require.NoError(t, err)

	bs, err := json.Marshal(&o)
	require.NoError(t, err)

	if marshalledStr := string(bs); marshalledStr != srcStr {
		t.Error("Empty map does not serialise to json correctly")
		t.Error("Expect", srcStr)
		t.Error("Got", marshalledStr)
	}
}
