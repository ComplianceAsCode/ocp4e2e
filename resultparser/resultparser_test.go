package resultparser

import (
	"testing"
)

func TestParseRoleResultEval(t *testing.T) {
	// Aliases for readability
	shouldEvalTrue := true
	shouldErr := true
	shouldEvalFalse := false
	noErr := false

	type parserargs struct {
		rawstring string
	}
	tests := []struct {
		name    string
		args    parserargs
		result  string
		want    bool
		wantErr bool
	}{
		{
			"Test simple case matches",
			parserargs{"FOO"},
			"FOO",
			shouldEvalTrue,
			noErr,
		},
		{
			"Test simple case doesn't match",
			parserargs{"FOO"},
			"BAR",
			shouldEvalFalse,
			noErr,
		},
		{
			"Test two operands fails with error",
			parserargs{"FOO BAR"},
			"BAR",
			shouldEvalFalse,
			shouldErr,
		},
		{
			"Test simple OR operand matches",
			parserargs{"FOO or BAR"},
			"BAR",
			shouldEvalTrue,
			noErr,
		},
		{
			"Test multiple OR operand matches",
			parserargs{"FOO or BAR or BAZ or OZZ or WALRUS"},
			"WALRUS",
			shouldEvalTrue,
			noErr,
		},
		{
			"Test multiple OR operand without matches",
			parserargs{"FOO or BAR or BAZ or OZZ or WALRUS"},
			"BEER",
			shouldEvalFalse,
			noErr,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRoleResultEval(tt.args.rawstring)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRoleResultEval() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if (err != nil) && tt.wantErr {
				return
			}

			eval := got.Eval(tt.result)
			t.Logf("Evaluated operand and got = %t", eval)
			if eval != tt.want {
				t.Errorf("ParseRoleResultEval() didn't match evaluation. Got = %t, wanted = %t",
					eval, tt.want)
				return
			}
		})
	}
}
