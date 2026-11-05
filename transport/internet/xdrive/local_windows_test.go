package xdrive

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestLocalSharingViolation(t *testing.T) {
	storage, err := newLocalStorage(t.TempDir())
	if err != nil {
		t.Fatalf("newLocalStorage: %v", err)
	}
	const name = "streams/session/c2s/000000000.seg"
	if err := storage.Put(context.Background(), name, []byte("segment")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	full, err := storage.resolve(name)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	path, err := windows.UTF16PtrFromString(full)
	if err != nil {
		t.Fatalf("UTF16PtrFromString: %v", err)
	}

	// os.Rename holds the file like this until a moment after its new name
	// appears
	handle, err := windows.CreateFile(path, windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	var once sync.Once
	release := func() { once.Do(func() { windows.CloseHandle(handle) }) }
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := storage.Get(ctx, name); !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("Get returned %v while the file is held, want a sharing violation", err)
	}

	time.AfterFunc(100*time.Millisecond, release)
	data, err := storage.Get(context.Background(), name)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(data) != "segment" {
		t.Fatalf("Get returned %q, want %q", data, "segment")
	}
}
