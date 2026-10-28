package ipintel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

func decodeRecords(b []byte) ([]Record, error) {
	r := bytes.NewReader(b)
	var count uint32
	if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
		return nil, err
	}
	if count > 1_000_000 {
		return nil, fmt.Errorf("block record count too large: %d", count)
	}
	out := make([]Record, 0, count)
	for i := uint32(0); i < count; i++ {
		var rec Record
		fam, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		rec.Family = fam
		if _, err := io.ReadFull(r, rec.Start[:]); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(r, rec.End[:]); err != nil {
			return nil, err
		}
		var src [2]byte
		if _, err := io.ReadFull(r, src[:]); err != nil {
			return nil, err
		}
		rec.SourceID = binary.LittleEndian.Uint16(src[:])
		rec.Category, err = readString(r)
		if err != nil {
			return nil, err
		}
		conf, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		rec.Confidence = conf
		var asn [4]byte
		if _, err := io.ReadFull(r, asn[:]); err != nil {
			return nil, err
		}
		rec.ASN = binary.LittleEndian.Uint32(asn[:])
		rec.Org, err = readString(r)
		if err != nil {
			return nil, err
		}
		rec.Country, err = readString(r)
		if err != nil {
			return nil, err
		}
		rec.Detail, err = readString(r)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

func readString(r *bytes.Reader) (string, error) {
	var n uint32
	if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
		return "", err
	}
	if n > 4*1024*1024 {
		return "", fmt.Errorf("string too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}
