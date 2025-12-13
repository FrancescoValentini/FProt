package protocol

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"io"
	"strings"
)

// # RECIPIENT MARSHAL
//
// Marshal serializes the recipient to the writer in the format:
//
// -> TYPE arg1 arg2 ...
//
// base64(body)
//
// Returns any I/O error encountered during writing.
func (r *Recipient) Marshal(w io.Writer) error {
	// -> TYPE arg1 arg2 ...
	if _, err := io.WriteString(w, "-> "+r.Type); err != nil {
		return err
	}
	for _, a := range r.Args {
		if _, err := io.WriteString(w, " "+a); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(w, "\n"); err != nil {
		return err
	}

	// Body (base64)
	bodyB64 := base64.StdEncoding.EncodeToString(r.Body)
	if _, err := io.WriteString(w, bodyB64+"\n"); err != nil {
		return err
	}

	return nil
}

// # HEADER MARSHAL
//
// Marshal serializes the FprotHeader to the writer and computes an HMAC.
// The key is used to compute HMAC-SHA384 over the canonical header representation.
// The format includes version, recipients, and a base64-encoded HMAC signature.
// Returns any I/O error encountered during writing.
func (h *FprotHeader) Marshal(w io.Writer, key []byte) error {
	var buf bytes.Buffer

	// Version
	buf.WriteString(h.Version + "\n")

	// Recipients
	for i := range h.Recipients {
		if err := h.Recipients[i].Marshal(&buf); err != nil {
			return err
		}
	}

	// Compute HMAC
	hmacValue := computeHMACSHA384(key, buf.Bytes())
	h.HeaderMac = hmacValue

	// Write header
	if _, err := w.Write(buf.Bytes()); err != nil {
		return err
	}

	// Write MAC
	macB64 := base64.StdEncoding.EncodeToString(hmacValue)
	_, err := io.WriteString(w, "--- "+macB64+"\n")
	return err
}

// Unmarshal parses an FprotHeader from the reader.
// Expected format:
//
//	Version
//	-> RecipientType arg1 arg2 ...
//	base64(recipientBody)
//	--- base64(HMAC-SHA384)
//
// Returns ErrInvalidHeader if the format is invalid, or any I/O error.
func (h *FprotHeader) Unmarshal(r io.Reader) error {
	br := bufio.NewReader(r)

	version, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	h.Version = strings.TrimSpace(version)

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "--- ") {
			macB64 := strings.TrimPrefix(line, "--- ")
			h.HeaderMac, err = base64.StdEncoding.DecodeString(macB64)
			return err
		}

		if strings.HasPrefix(line, "-> ") {
			rec, err := unmarshalRecipientReader(br, line)
			if err != nil {
				return err
			}
			h.Recipients = append(h.Recipients, rec)
			continue
		}

		return ErrInvalidHeader
	}
}

// VerifyHeaderHMAC validates the header's HMAC signature using the provided key.
// Returns true if the HMAC matches, false otherwise.
// Returns ErrMissingHMAC if no HMAC is present in the header.
func (h *FprotHeader) VerifyHeaderHMAC(key []byte) (bool, error) {
	if h.HeaderMac == nil {
		return false, ErrMissingHMAC
	}

	data, err := h.marshalCanonical()
	if err != nil {
		return false, err
	}

	expected := computeHMACSHA384(key, data)
	return hmac.Equal(h.HeaderMac, expected), nil
}

// marshalCanonical returns the canonical byte representation of the header
// (version + recipients) without the HMAC. This is used for HMAC computation.
func (h *FprotHeader) marshalCanonical() ([]byte, error) {
	var buf bytes.Buffer

	buf.WriteString(h.Version + "\n")

	for i := range h.Recipients {
		if err := h.Recipients[i].Marshal(&buf); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// unmarshalRecipientReader parses a single recipient from a buffered reader.
// The headerLine should be the "-> TYPE args..." line already read.
// Reads the next line as base64-encoded body data.
func unmarshalRecipientReader(br *bufio.Reader, headerLine string) (Recipient, error) {
	fields := strings.Fields(headerLine)
	r := Recipient{
		Type: fields[1],
		Args: fields[2:],
	}

	bodyLine, err := br.ReadString('\n')
	if err != nil {
		return r, err
	}
	bodyLine = strings.TrimSpace(bodyLine)

	r.Body, err = base64.StdEncoding.DecodeString(bodyLine)
	return r, err
}

// computeHMACSHA384 computes HMAC-SHA384 of data using the provided key.
func computeHMACSHA384(key, data []byte) []byte {
	mac := hmac.New(sha512.New384, key)
	mac.Write(data)
	return mac.Sum(nil)
}
