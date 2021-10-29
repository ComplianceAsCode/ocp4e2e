package resultparser

import (
	"fmt"
	"strings"
)

type Evaluator interface {
	Eval(in string) bool
}

type evalBuilder interface {
	Eval(in string) bool
	merge(other evalBuilder) (evalBuilder, error)
	isleaf() bool
}

type leaf struct {
	target string
}

func (l *leaf) Eval(in string) bool {
	return strings.EqualFold(l.target, in)
}

func (l *leaf) isleaf() bool {
	return true
}

func (l *leaf) merge(other evalBuilder) (evalBuilder, error) {
	// nothing to do, this is the first leaf
	// that's parsed
	if other == nil {
		return l, nil
	}
	if other.isleaf() {
		return nil, fmt.Errorf("result eval syntax error: cannot merge leaf and operand")
	}
	return other.merge(l)
}

type orOperand struct {
	a evalBuilder
	b evalBuilder
}

func (oo *orOperand) Eval(in string) bool {
	return oo.a.Eval(in) || oo.b.Eval(in)
}

func (oo *orOperand) isleaf() bool {
	return false
}

func (oo *orOperand) merge(other evalBuilder) (evalBuilder, error) {
	// nothing to do, this is the first leaf
	// that's parsed
	if other == nil {
		return nil, fmt.Errorf("result eval or operand syntax error: no operand given")
	}
	oo.b = other
	return oo, nil
}

type roleResultEvalBase func(string) bool
type roleResultEval func(string, roleResultEval) bool

func ParseRoleResultEval(rawstring string) (Evaluator, error) {
	tokens := tokenizeRoleResultEval(rawstring)
	var currentOperand evalBuilder
	for _, token := range tokens {
		switch token {
		// We'll just handle "or" for now
		case "or":
			oo := orOperand{a: currentOperand}

			var err error
			currentOperand, err = oo.merge(currentOperand)
			if err != nil {
				return nil, err
			}
		default:
			l := leaf{target: token}
			var err error
			currentOperand, err = l.merge(currentOperand)
			if err != nil {
				return nil, err
			}
		}
	}
	return currentOperand, nil
}

func tokenizeRoleResultEval(rawstring string) []string {
	return strings.Split(rawstring, " ")
}
