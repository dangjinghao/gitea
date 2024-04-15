// Copyright 2020 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package lfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"

	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/storage"
	"code.gitea.io/gitea/modules/typesniffer"
)

var (
	// ErrHashMismatch occurs if the content has does not match OID
	ErrHashMismatch = errors.New("content hash does not match OID")
	// ErrSizeMismatch occurs if the content size does not match
	ErrSizeMismatch = errors.New("content size does not match")
)

// ContentStore provides a simple file system based storage.
type ContentStore struct {
	storage.ObjectStorage
}

// NewContentStore creates the default ContentStore
func NewContentStore() *ContentStore {
	contentStore := &ContentStore{ObjectStorage: storage.LFS}
	return contentStore
}

// Get takes a Meta object and retrieves the content from the store, returning
// it as an io.ReadSeekCloser.
func (s *ContentStore) Get(pointer Pointer) (storage.Object, error) {
	f, err := s.Open(pointer.RelativePath())
	if err != nil {
		log.Error("Whilst trying to read LFS OID[%s]: Unable to open Error: %v", pointer.Oid, err)
		return nil, err
	}
	return f, err
}

// Put takes a Meta object and an io.Reader and writes the content to the store.
func (s *ContentStore) Put(pointer Pointer, r io.Reader) error {
	_, err := s.PutExt(pointer, r)
	return err
}

// PutExt takes a Meta object and an io.Reader and writes the content to the store.
// Extended for returning file content type
func (s *ContentStore) PutExt(pointer Pointer, r io.Reader) (contentType string, err error) {
	p := pointer.RelativePath()

	// Wrap the provided reader with an inline hashing and size checker
	wrappedRd := newHashingReader(pointer.Size, pointer.Oid, r)
	fileHeaderBuffer := bytes.NewBuffer(nil)

	_, err = io.Copy(fileHeaderBuffer, io.LimitReader(wrappedRd, 512))
	if err != nil {
		log.Error("Errror copying data from wrappedRd: %v", err)
		return
	}

	ts := typesniffer.DetectContentType(fileHeaderBuffer.Bytes())
	contentType = ts.GetMimeType()
	fullFile := io.MultiReader(bytes.NewReader(fileHeaderBuffer.Bytes()), wrappedRd)
	log.Info(contentType)
	// now pass the wrapped reader to Save - if there is a size mismatch or hash mismatch then

	mS, err := storage.ConvertToMinioStorage(s.ObjectStorage)
	var written int64
	if err == nil {
		written, err = mS.SaveMExtContentType(p, fullFile, pointer.Size, contentType)
	} else {
		written, err = s.Save(p, fullFile, pointer.Size)

	}
	if err != nil {
		log.Error("Whilst putting LFS OID[%s]: Failed to copy to tmpPath: %s Error: %v", pointer.Oid, p, err)
		return
	}

	// check again whether there is any error during the Save operation
	// because some errors might be ignored by the Reader's caller
	if wrappedRd.lastError != nil && !errors.Is(wrappedRd.lastError, io.EOF) {
		err = wrappedRd.lastError
	} else if written != pointer.Size {
		err = ErrSizeMismatch
	}

	// if the upload failed, try to delete the file
	if err != nil {
		if errDel := s.Delete(p); errDel != nil {
			log.Error("Cleaning the LFS OID[%s] failed: %v", pointer.Oid, errDel)
		}
	}

	return
}

// Exists returns true if the object exists in the content store.
func (s *ContentStore) Exists(pointer Pointer) (bool, error) {
	_, err := s.ObjectStorage.Stat(pointer.RelativePath())
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Verify returns true if the object exists in the content store and size is correct.
func (s *ContentStore) Verify(pointer Pointer) (bool, error) {
	p := pointer.RelativePath()
	fi, err := s.ObjectStorage.Stat(p)
	if os.IsNotExist(err) || (err == nil && fi.Size() != pointer.Size) {
		return false, nil
	} else if err != nil {
		log.Error("Unable stat file: %s for LFS OID[%s] Error: %v", p, pointer.Oid, err)
		return false, err
	}

	return true, nil
}

// ReadMetaObject will read a git_model.LFSMetaObject and return a reader
func ReadMetaObject(pointer Pointer) (io.ReadSeekCloser, error) {
	contentStore := NewContentStore()
	return contentStore.Get(pointer)
}

type hashingReader struct {
	internal     io.Reader
	currentSize  int64
	expectedSize int64
	hash         hash.Hash
	expectedHash string
	lastError    error
}

// recordError records the last error during the Save operation
// Some callers of the Reader doesn't respect the returned "err"
// For example, MinIO's Put will ignore errors if the written size could equal to expected size
// So we must remember the error by ourselves,
// and later check again whether ErrSizeMismatch or ErrHashMismatch occurs during the Save operation
func (r *hashingReader) recordError(err error) error {
	r.lastError = err
	return err
}

func (r *hashingReader) Read(b []byte) (int, error) {
	n, err := r.internal.Read(b)

	if n > 0 {
		r.currentSize += int64(n)
		wn, werr := r.hash.Write(b[:n])
		if wn != n || werr != nil {
			return n, r.recordError(werr)
		}
	}

	if errors.Is(err, io.EOF) || r.currentSize >= r.expectedSize {
		if r.currentSize != r.expectedSize {
			return n, r.recordError(ErrSizeMismatch)
		}

		shaStr := hex.EncodeToString(r.hash.Sum(nil))
		if shaStr != r.expectedHash {
			return n, r.recordError(ErrHashMismatch)
		}
	}

	return n, r.recordError(err)
}

func newHashingReader(expectedSize int64, expectedHash string, reader io.Reader) *hashingReader {
	return &hashingReader{
		internal:     reader,
		expectedSize: expectedSize,
		expectedHash: expectedHash,
		hash:         sha256.New(),
	}
}
