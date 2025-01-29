//nolint:testpackage
package match

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/BountySecurity/gbounty/profile"
)

func Test_evaluate(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		expected  bool
		booleans  []bool
		operators []profile.GrepOperator
	}{
		"nil":   {expected: false},
		"none":  {expected: false, booleans: []bool{}},
		"true":  {expected: true, booleans: []bool{true}},
		"false": {expected: false, booleans: []bool{false}},

		"true && true":   {expected: true, booleans: []bool{true, true}, operators: []profile.GrepOperator{profile.GrepOperatorAnd}},
		"true && false":  {expected: false, booleans: []bool{true, false}, operators: []profile.GrepOperator{profile.GrepOperatorAnd}},
		"false && true":  {expected: false, booleans: []bool{false, true}, operators: []profile.GrepOperator{profile.GrepOperatorAnd}},
		"false && false": {expected: false, booleans: []bool{false, false}, operators: []profile.GrepOperator{profile.GrepOperatorAnd}},

		"true || true":   {expected: true, booleans: []bool{true, true}, operators: []profile.GrepOperator{profile.GrepOperatorOr}},
		"true || false":  {expected: true, booleans: []bool{true, false}, operators: []profile.GrepOperator{profile.GrepOperatorOr}},
		"false || true":  {expected: true, booleans: []bool{false, true}, operators: []profile.GrepOperator{profile.GrepOperatorOr}},
		"false || false": {expected: false, booleans: []bool{false, false}, operators: []profile.GrepOperator{profile.GrepOperatorOr}},

		"true && !true":   {expected: false, booleans: []bool{true, true}, operators: []profile.GrepOperator{profile.GrepOperatorAndNot}},
		"true && !false":  {expected: true, booleans: []bool{true, false}, operators: []profile.GrepOperator{profile.GrepOperatorAndNot}},
		"false && !true":  {expected: false, booleans: []bool{false, true}, operators: []profile.GrepOperator{profile.GrepOperatorAndNot}},
		"false && !false": {expected: false, booleans: []bool{false, false}, operators: []profile.GrepOperator{profile.GrepOperatorAndNot}},

		"true || !true":   {expected: true, booleans: []bool{true, true}, operators: []profile.GrepOperator{profile.GrepOperatorOrNot}},
		"true || !false":  {expected: true, booleans: []bool{true, false}, operators: []profile.GrepOperator{profile.GrepOperatorOrNot}},
		"false || !true":  {expected: false, booleans: []bool{false, true}, operators: []profile.GrepOperator{profile.GrepOperatorOrNot}},
		"false || !false": {expected: true, booleans: []bool{false, false}, operators: []profile.GrepOperator{profile.GrepOperatorOrNot}},

		"true && false || true":  {expected: true, booleans: []bool{true, false, true}, operators: []profile.GrepOperator{profile.GrepOperatorAnd, profile.GrepOperatorOr}},
		"false && false || true": {expected: true, booleans: []bool{false, false, true}, operators: []profile.GrepOperator{profile.GrepOperatorAnd, profile.GrepOperatorOr}},
		"true || true && false":  {expected: false, booleans: []bool{true, true, false}, operators: []profile.GrepOperator{profile.GrepOperatorOr, profile.GrepOperatorAnd}},
	}

	for name, tc := range tcs {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, evaluate(tc.booleans, tc.operators))
		})
	}
}
