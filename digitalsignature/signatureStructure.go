package digitalsignature

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

type SignedInfo struct {
	Timestamp   time.Time
	PublicKey   [PublicKeySize]byte
	PublicKeyID [PublicKeyIDSize]byte
	ContentHash [ContentHashSize]byte // SHA-384 of data
}

type Signature struct {
	Info       SignedInfo
	SignedData []byte // ASN.1 DER encoded ECDSA signature
}

func (si *SignedInfo) ToBytes() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, si.Timestamp.Unix())
	buf.Write(si.PublicKey[:])
	buf.Write(si.PublicKeyID[:])
	buf.Write(si.ContentHash[:])
	return buf.Bytes()
}

func (si *SignedInfo) FromBytes(data []byte) error {
	if len(data) < SignedInfoSize {
		return fmt.Errorf("%w", ErrInvalidDataSize)
	}
	buf := bytes.NewReader(data)

	var nano int64
	if err := binary.Read(buf, binary.BigEndian, &nano); err != nil {
		return err
	}
	si.Timestamp = time.Unix(nano, 0)

	copy(si.PublicKey[:], data[TimestampSize:TimestampSize+PublicKeySize])
	copy(si.PublicKeyID[:], data[TimestampSize+PublicKeySize:TimestampSize+PublicKeySize+PublicKeyIDSize])
	copy(si.ContentHash[:], data[TimestampSize+PublicKeySize+PublicKeyIDSize:SignedInfoSize])
	return nil
}

func (s *Signature) ToBytes() []byte {
	infoBytes := s.Info.ToBytes()
	buf := make([]byte, len(infoBytes)+len(s.SignedData))
	copy(buf[:len(infoBytes)], infoBytes)
	copy(buf[len(infoBytes):], s.SignedData)
	return buf
}

func (s *Signature) FromBytes(data []byte) error {
	if len(data) < SignedInfoSize {
		return fmt.Errorf("%w", ErrInvalidDataSize)
	}
	if err := s.Info.FromBytes(data[:SignedInfoSize]); err != nil {
		return err
	}
	s.SignedData = make([]byte, len(data)-SignedInfoSize)
	copy(s.SignedData, data[SignedInfoSize:])
	return nil
}
