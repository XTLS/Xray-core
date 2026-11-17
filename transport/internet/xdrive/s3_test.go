package xdrive

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestS3DeleteNonemptyDirectory(t *testing.T) {
	const root = "folder/streams/abc"
	const marker = root + "/up/"
	const segment = marker + "0"
	const sibling = "folder/streams/abcd"
	objects := map[string]bool{root: true, marker: true, segment: true, sibling: true}
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			query := r.URL.Query()
			if query.Get("prefix") != root+"/" {
				http.Error(w, "unexpected list prefix", http.StatusBadRequest)
				return
			}
			switch query.Get("continuation-token") {
			case "":
				fmt.Fprintf(w, "<ListBucketResult><Contents><Key>%s</Key></Contents><IsTruncated>true</IsTruncated><NextContinuationToken>next</NextContinuationToken></ListBucketResult>", marker)
			case "next":
				fmt.Fprintf(w, "<ListBucketResult><Contents><Key>%s</Key></Contents></ListBucketResult>", segment)
			default:
				http.Error(w, "unexpected list token", http.StatusBadRequest)
			}
		case http.MethodDelete:
			key := strings.TrimPrefix(r.URL.Path, "/bucket/")
			mu.Lock()
			defer mu.Unlock()
			for other := range objects {
				if other != key && strings.HasPrefix(other, strings.TrimSuffix(key, "/")+"/") {
					w.WriteHeader(http.StatusPreconditionFailed)
					return
				}
			}
			delete(objects, key)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(server.Close)
	storage, err := newS3Storage(nil, &Config{
		RemoteFolder: "folder",
		Secrets:      []string{"access", "secret"},
		S3:           &S3Config{Endpoint: server.URL, Bucket: "bucket", PathStyle: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Delete(t.Context(), "streams/abc"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(objects) != 1 || !objects[sibling] {
		t.Fatalf("remaining objects = %v, want only %q", objects, sibling)
	}
}
