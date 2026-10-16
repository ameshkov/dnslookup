package main

import (
	"io"
	"reflect"
	"testing"
)

func TestParseArgs(t *testing.T) {
	testCases := []struct {
		name        string
		args        []string
		want        []string
		wantRRType  string
		wantJSON    bool
		wantVersion bool
		wantErr     bool
	}{
		{
			name: "no_args",
		},
		{
			name: "positional_only",
			args: []string{"example.org", "1.1.1.1"},
			want: []string{"example.org", "1.1.1.1"},
		},
		{
			name:       "flags_before_positional",
			args:       []string{"--rrtype", "AAAA", "example.org", "1.1.1.1"},
			want:       []string{"example.org", "1.1.1.1"},
			wantRRType: "AAAA",
		},
		{
			name:       "flags_after_positional",
			args:       []string{"example.org", "1.1.1.1", "--rrtype", "AAAA"},
			want:       []string{"example.org", "1.1.1.1"},
			wantRRType: "AAAA",
		},
		{
			name:       "flags_between_positional",
			args:       []string{"example.org", "--rrtype=AAAA", "1.1.1.1", "--json"},
			want:       []string{"example.org", "1.1.1.1"},
			wantRRType: "AAAA",
			wantJSON:   true,
		},
		{
			name: "double_dash_terminator",
			args: []string{"example.org", "--", "--json"},
			want: []string{"example.org", "--json"},
		},
		{
			name:        "version_shorthand",
			args:        []string{"-v"},
			wantVersion: true,
		},
		{
			name:    "unknown_flag",
			args:    []string{"example.org", "--unknown"},
			wantErr: true,
		},
		{
			name:    "missing_flag_value",
			args:    []string{"example.org", "--rrtype"},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fs, flags := newFlagSet()
			// Discard the error messages and the usage printed by the flag
			// set on parse errors.
			fs.SetOutput(io.Discard)
			fs.Usage = func() {}

			got, err := parseArgs(fs, tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("expected positional args %q, got %q", tc.want, got)
			}

			if *flags.rrtype != tc.wantRRType {
				t.Errorf("expected rrtype %q, got %q", tc.wantRRType, *flags.rrtype)
			}

			if *flags.json != tc.wantJSON {
				t.Errorf("expected json %t, got %t", tc.wantJSON, *flags.json)
			}

			if *flags.version != tc.wantVersion {
				t.Errorf("expected version %t, got %t", tc.wantVersion, *flags.version)
			}
		})
	}
}
