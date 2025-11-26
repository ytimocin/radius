/*
Copyright 2024 The Radius Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package installer

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/radius-project/radius/pkg/components/database/inmemory"
	"github.com/radius-project/radius/pkg/components/queue"
	"github.com/stretchr/testify/require"
)

func TestHandleInstall_Succeeds(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	zipBytes := buildZip(t)
	sum := sha256.Sum256(zipBytes)
	checksum := "sha256:" + hex.EncodeToString(sum[:])

	store := NewStatusStore(inmemory.NewClient(), StatusStorageID)
	handler := &Handler{
		StatusStore: store,
		RootPath:    tempDir,
		HTTPClient:  &http.Client{Transport: stubTransport{body: zipBytes}},
	}

	msg := queue.NewMessage(JobMessage{
		Operation: OperationInstall,
		Version:   "1.0.0",
		SourceURL: "http://example.com/terraform.zip",
		Checksum:  checksum,
	})

	require.NoError(t, handler.Handle(ctx, msg))

	status, err := store.Get(ctx)
	require.NoError(t, err)
	require.Equal(t, "1.0.0", status.Current)
	vs := status.Versions["1.0.0"]
	require.Equal(t, VersionStateSucceeded, vs.State)
	require.FileExists(t, filepath.Join(tempDir, "versions", "1.0.0", "terraform"))
}

func TestHandleInstall_ChecksumFail(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	zipBytes := buildZip(t)

	store := NewStatusStore(inmemory.NewClient(), StatusStorageID)
	handler := &Handler{
		StatusStore: store,
		RootPath:    tempDir,
		HTTPClient:  &http.Client{Transport: stubTransport{body: zipBytes}},
	}

	msg := queue.NewMessage(JobMessage{
		Operation: OperationInstall,
		Version:   "1.0.0",
		SourceURL: "http://example.com/terraform.zip",
		Checksum:  "sha256:deadbeef",
	})

	err := handler.Handle(ctx, msg)
	require.Error(t, err)

	status, _ := store.Get(ctx)
	vs := status.Versions["1.0.0"]
	require.Equal(t, VersionStateFailed, vs.State)
	require.NotEmpty(t, vs.LastError)
	require.Empty(t, status.Current)
}

func TestHandleUninstall(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	// seed status with another current version
	store := NewStatusStore(inmemory.NewClient(), StatusStorageID)
	err := store.Put(ctx, &Status{
		Current: "2.0.0",
		Versions: map[string]VersionStatus{
			"2.0.0": {Version: "2.0.0", State: VersionStateSucceeded},
			"1.0.0": {Version: "1.0.0", State: VersionStateSucceeded},
		},
	})
	require.NoError(t, err)

	targetDir := filepath.Join(tempDir, "versions", "1.0.0")
	require.NoError(t, os.MkdirAll(targetDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(targetDir, "terraform"), []byte("tf"), 0o755))

	handler := &Handler{
		StatusStore: store,
		RootPath:    tempDir,
	}

	msg := queue.NewMessage(JobMessage{
		Operation: OperationUninstall,
		Version:   "1.0.0",
	})

	require.NoError(t, handler.Handle(ctx, msg))

	status, _ := store.Get(ctx)
	vs := status.Versions["1.0.0"]
	require.Equal(t, VersionStateUninstalled, vs.State)
	require.NoFileExists(t, filepath.Join(targetDir, "terraform"))
}

func TestHandleInstall_LockContention(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	store := NewStatusStore(inmemory.NewClient(), StatusStorageID)
	handler := &Handler{
		StatusStore: store,
		RootPath:    tempDir,
		HTTPClient:  &http.Client{Transport: stubTransport{body: buildZip(t)}},
	}

	// Pre-create lock to simulate concurrent operation.
	lockPath := filepath.Join(tempDir, ".terraform-installer.lock")
	require.NoError(t, os.MkdirAll(tempDir, 0o755))
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	require.NoError(t, err)
	defer func() {
		_ = lock.Close()
		_ = os.Remove(lockPath)
	}()

	msg := queue.NewMessage(JobMessage{
		Operation: OperationInstall,
		Version:   "1.2.3",
		SourceURL: "http://example.com/terraform.zip",
	})

	err = handler.Handle(ctx, msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "installer is busy")
}

func TestHandleInstall_StaleLockFailsBusy(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	store := NewStatusStore(inmemory.NewClient(), StatusStorageID)
	handler := &Handler{
		StatusStore: store,
		RootPath:    tempDir,
		HTTPClient:  &http.Client{Transport: stubTransport{body: buildZip(t)}},
	}

	// Create and close lock file to simulate leftover; handler should report busy.
	lockPath := filepath.Join(tempDir, ".terraform-installer.lock")
	require.NoError(t, os.MkdirAll(tempDir, 0o755))
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	require.NoError(t, err)
	_ = lock.Close()

	msg := queue.NewMessage(JobMessage{
		Operation: OperationInstall,
		Version:   "1.2.4",
		SourceURL: "http://example.com/terraform.zip",
	})

	err = handler.Handle(ctx, msg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "installer is busy")
}

func TestHandleInstall_RootPathUnwritable(t *testing.T) {
	ctx := context.Background()

	store := NewStatusStore(inmemory.NewClient(), StatusStorageID)
	handler := &Handler{
		StatusStore: store,
		RootPath:    "/dev/null/should-fail",
		HTTPClient:  &http.Client{Transport: stubTransport{body: buildZip(t)}},
	}

	msg := queue.NewMessage(JobMessage{
		Operation: OperationInstall,
		Version:   "1.2.5",
		SourceURL: "http://example.com/terraform.zip",
	})

	err := handler.Handle(ctx, msg)
	require.Error(t, err)
}

type stubTransport struct {
	body []byte
}

func (t stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewReader(t.body)),
		Header:     make(http.Header),
	}, nil
}

func buildZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("terraform")
	require.NoError(t, err)
	_, err = f.Write([]byte("binary"))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}
