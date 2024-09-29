package aspack

import (
	"testing"
)

func TestASPack_Detect(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name string
		a    ASPack
		args args
		want int
	}{
		{
			name: "Test 1",
			a:    ASPack{},
			args: args{path: "Ruler.exe"},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.Detect(tt.args.path); got != tt.want {
				t.Errorf("ASPack.Detect() = %v, want %v", got, tt.want)
			}
		})
	}
}
