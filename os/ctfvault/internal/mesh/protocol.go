package mesh

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const maxHeaderSize = 64 * 1024

type Header struct {
	Version       int                   `json:"version"`
	Op            string                `json:"op"`
	Token         string                `json:"token,omitempty"`
	Name          string                `json:"name,omitempty"`
	OrigName      string                `json:"orig_name,omitempty"`
	FileID        string                `json:"file_id,omitempty"`
	ChunkIndex    int                   `json:"chunk_index,omitempty"`
	ChunkTotal    int                   `json:"chunk_total,omitempty"`
	ChunkSize     int                   `json:"chunk_size,omitempty"`
	Size          int64                 `json:"size,omitempty"`
	Encrypted     bool                  `json:"encrypted"`
	MetadataLevel string                `json:"metadata_level,omitempty"`
	Target        string                `json:"target,omitempty"`
	Route         string                `json:"route,omitempty"`
	TTL           int                   `json:"ttl,omitempty"`
	Padding       int                   `json:"padding,omitempty"`
	Security      *SecurityStreamHeader `json:"security,omitempty"`
}

type SecurityStreamHeader struct {
	Salt      string `json:"salt"`
	NonceBase string `json:"nonce_base"`
	ChunkSize int    `json:"chunk_size"`
	Algo      string `json:"algo"`
	Depth     int    `json:"depth"`
	Offset    int    `json:"offset"`
}

func writeHeader(w io.Writer, hdr Header) error {
	data, err := json.Marshal(hdr)
	if err != nil {
		return err
	}
	if len(data) > maxHeaderSize {
		return errors.New("header too large")
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func readHeader(r io.Reader) (Header, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return Header{}, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > maxHeaderSize {
		return Header{}, errors.New("invalid header size")
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return Header{}, err
	}
	var hdr Header
	if err := json.Unmarshal(data, &hdr); err != nil {
		return Header{}, err
	}
	return hdr, nil
}
