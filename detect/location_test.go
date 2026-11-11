package detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGetLocation tests the getLocation function.
func TestGetLocation(t *testing.T) {
	tests := []struct {
		linePairs    [][]int
		raw          string
		start        int
		end          int
		wantLocation Location
	}{
		{
			linePairs: [][]int{
				{0, 39},
				{40, 55},
				{56, 57},
			},
			start: 35,
			end:   38,
			wantLocation: Location{
				startLine:      1,
				startColumn:    36,
				endLine:        1,
				endColumn:      38,
				startLineIndex: 0,
				endLineIndex:   40,
			},
		},
		{
			linePairs: [][]int{
				{0, 39},
				{40, 55},
				{56, 57},
			},
			start: 40,
			end:   44,
			wantLocation: Location{
				startLine:      2,
				startColumn:    1,
				endLine:        2,
				endColumn:      4,
				startLineIndex: 40,
				endLineIndex:   56,
			},
		},
		{
			// CRLF line endings: the carriage return is excluded from the
			// line contents.
			linePairs: [][]int{
				{4, 5},
				{9, 10},
			},
			raw:   "foo\r\nbar\r\nbaz",
			start: 5,
			end:   8,
			wantLocation: Location{
				startLine:      1,
				startColumn:    2,
				endLine:        1,
				endColumn:      4,
				startLineIndex: 4,
				endLineIndex:   8,
			},
		},
		{
			// A standalone carriage return (not part of a CRLF line ending)
			// is preserved in the line contents.
			linePairs: [][]int{
				{7, 8},
			},
			raw:   "foo\rbar\nbaz",
			start: 0,
			end:   7,
			wantLocation: Location{
				startLine:      0,
				startColumn:    1,
				endLine:        0,
				endColumn:      7,
				startLineIndex: 0,
				endLineIndex:   7,
			},
		},
	}

	for _, test := range tests {
		loc := location(test.linePairs, test.raw, []int{test.start, test.end})
		assert.Equal(t, test.wantLocation, loc)
	}
}
