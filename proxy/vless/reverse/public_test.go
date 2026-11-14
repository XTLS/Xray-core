package reverse_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/proxy/vless/reverse"
)

func TestStaticPickerEmpty(t *testing.T) {
	picker := reverse.NewStaticPicker()
	worker, err := picker.Admit(context.Background(), nil)
	if err == nil {
		t.Error("expected error, but nil")
	}
	if worker != nil {
		t.Error("expected nil worker, but not nil")
	}
}
