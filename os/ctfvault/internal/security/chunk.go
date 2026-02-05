package security

import (
    "encoding/binary"
    "errors"
    "io"
)

func writeChunk(w io.Writer, data []byte) error {
    if len(data) > int(^uint32(0)) {
        return errors.New("chunk too large")
    }
    var lenBuf [4]byte
    binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
    if _, err := w.Write(lenBuf[:]); err != nil {
        return err
    }
    if len(data) == 0 {
        return nil
    }
    _, err := w.Write(data)
    return err
}

func readChunk(r io.Reader) ([]byte, error) {
    var lenBuf [4]byte
    if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
        return nil, err
    }
    length := binary.BigEndian.Uint32(lenBuf[:])
    if length == 0 {
        return nil, nil
    }
    data := make([]byte, length)
    if _, err := io.ReadFull(r, data); err != nil {
        return nil, err
    }
    return data, nil
}
