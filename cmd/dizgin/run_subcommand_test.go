// SPDX-License-Identifier: MIT

package main

import (
	"reflect"
	"testing"
)

func TestSplitCommandLine(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    []string
		wantErr bool
	}{
		{"empty", "", nil, false},
		{"whitespace only", "   \t\n", nil, false},
		{
			name: "MSYS-vulnerable cmd /c echo",
			in:   "cmd /c echo hello",
			want: []string{"cmd", "/c", "echo", "hello"},
		},
		{
			name: "double-quoted spaces preserved",
			in:   `node -e "console.log('hi there')"`,
			want: []string{"node", "-e", "console.log('hi there')"},
		},
		{
			name: "single quotes preserve everything",
			in:   `echo 'no $expansion'`,
			want: []string{"echo", "no $expansion"},
		},
		{
			name: "double-quoted backslash escapes",
			in:   `echo "say \"hello\""`,
			want: []string{"echo", `say "hello"`},
		},
		{
			name: "env override + tool + flag",
			in:   `ANTHROPIC_API_KEY=sk-xxx claude --print "hello world"`,
			want: []string{"ANTHROPIC_API_KEY=sk-xxx", "claude", "--print", "hello world"},
		},
		{
			name:    "unterminated single quote",
			in:      `echo 'oops`,
			wantErr: true,
		},
		{
			name:    "unterminated double quote",
			in:      `echo "oops`,
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := splitCommandLine(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got tokens %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("splitCommandLine(%q) = %#v, want %#v", c.in, got, c.want)
			}
		})
	}
}
