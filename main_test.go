package main

import (
	"testing"
)

func Test_nameValuePairs_Set(t *testing.T) {
	tests := []struct {
		name    string
		nvp     nameValuePairs
		wantErr bool
		input   string
	}{
		{name: "no value", nvp: nameValuePairs{}, input: "key=value", wantErr: false},
		{name: "invalid", nvp: nameValuePairs{}, input: "keyvalue", wantErr: true},
		{name: "empty", nvp: nameValuePairs{}, input: "", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.nvp.Set(tt.input); (err != nil) != tt.wantErr {
				t.Errorf("nameValuePairs.Set() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
