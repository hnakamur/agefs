// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ageutil

import (
	"bufio"
	"io"

	"filippo.io/age"
	"filippo.io/age/armor"
	"go.uber.org/multierr"
)

func NewEncryptingWriter(recipients []age.Recipient, out io.Writer, withArmor bool) (io.WriteCloser, error) {
	var aw io.WriteCloser
	if withArmor {
		aw = armor.NewWriter(out)
		out = aw
	}

	w, err := age.Encrypt(out, recipients...)
	if err != nil {
		return nil, err
	}

	if withArmor {
		return &armoredEncryptingWriter{w: w, aw: aw}, nil
	}
	return w, nil
}

type armoredEncryptingWriter struct {
	w  io.WriteCloser
	aw io.WriteCloser
}

func (w *armoredEncryptingWriter) Write(p []byte) (int, error) {
	return w.w.Write(p)
}

func (w *armoredEncryptingWriter) Close() error {
	err := w.w.Close()
	err = multierr.Append(err, w.aw.Close())
	return err
}

func NewDecryptingReader(identities []age.Identity, in io.Reader) (io.Reader, error) {
	rr := bufio.NewReader(in)
	if start, _ := rr.Peek(len(armor.Header)); string(start) == armor.Header {
		in = armor.NewReader(rr)
	} else {
		in = rr
	}

	return age.Decrypt(in, identities...)
}
