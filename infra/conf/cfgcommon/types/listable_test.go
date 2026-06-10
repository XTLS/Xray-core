package types_test

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/xtls/xray-core/infra/conf/cfgcommon/types"
)

type TestGroup[T any] struct {
	name     string
	input    string
	expected []T
}

// intentionally to be so chaos
var rawJson = `{
	"field": 
	["value1",
			"value2", "value3"
			]
}`

func TestListableUnmarshal(t *testing.T) {
	type TestStruct struct {
		Field types.Listable[string] `json:"field"`
	}

	tests := []TestGroup[string]{
		{
			name:     "SingleString",
			input:    `{"field": "hello"}`,
			expected: []string{"hello"},
		},
		{
			name:     "ArrayString",
			input:    `{"field": ["value1", "value2", "value3"]}`,
			expected: []string{"value1", "value2", "value3"},
		},
		{
			name:     "ComplexArray",
			input:    rawJson,
			expected: []string{"value1", "value2", "value3"},
		},
		{
			name:     "SingleStringWithSpace",
			input:    `{"field":   "hello"  }`,
			expected: []string{"hello"},
		},
		{
			name:     "ArrayWithSpace",
			input:    `{"field":   [ "a", "b" ]  }`,
			expected: []string{"a", "b"},
		},
		{
			name:     "SingleEmptyString",
			input:    `{"field": ""}`,
			expected: nil,
		},
		{
			name:     "Null",
			input:    `{"field": null}`,
			expected: nil,
		},
		{
			name:     "Missing (default)",
			input:    `{}`,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ts TestStruct
			err := json.Unmarshal([]byte(tt.input), &ts)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if !slices.Equal([]string(ts.Field), tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, ts.Field)
			}
		})
	}
}

func TestListableInt(t *testing.T) {
	tests := []TestGroup[int]{
		{
			name:     "SingleInt",
			input:    `123`,
			expected: []int{123},
		},
		{
			name:     "ArrayInt",
			input:    `[1, 2]`,
			expected: []int{1, 2},
		},
		{
			name:     "Null",
			input:    `null`,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var l types.Listable[int]
			err := json.Unmarshal([]byte(tt.input), &l)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if !slices.Equal([]int(l), tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, l)
			}
		})
	}
}

func TestListableSimpleString(t *testing.T) {
	type TestStruct struct {
		Field types.ListableSimpleString `json:"field"`
	}

	tests := []TestGroup[string]{
		{
			name:     "SingleString",
			input:    `{"field": "singleValue"}`,
			expected: []string{"singleValue"},
		},
		{
			name:     "ArrayString",
			input:    `{"field": ["value1", "value2", "value3"]}`,
			expected: []string{"value1", "value2", "value3"},
		},
		{
			name:     "SingleEmptyString",
			input:    `{"field": ""}`,
			expected: nil,
		},
		{
			name:     "WaveSplit",
			input:    `{"field": "value1~value2~value3"}`,
			expected: []string{"value1", "value2", "value3"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ts TestStruct
			err := json.Unmarshal([]byte(tt.input), &ts)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if !slices.Equal([]string(ts.Field), tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, ts.Field)
			}
		})
	}
}
