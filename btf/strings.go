package btf

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

type stringTable []byte

func readStringTable(r io.Reader) (stringTable, error) {
	contents, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("can't read string table: %v", err)
	}

	if len(contents) < 1 {
		return nil, errors.New("string table is empty")
	}

	if contents[0] != '\x00' {
		return nil, errors.New("first item in string table is non-empty")
	}

	if contents[len(contents)-1] != '\x00' {
		return nil, errors.New("string table isn't null terminated")
	}

	return stringTable(contents), nil
}

func (st stringTable) Lookup(offset uint32) (string, error) {
	if int64(offset) > int64(^uint(0)>>1) {
		return "", fmt.Errorf("offset %d overflows int", offset)
	}

	pos := int(offset)
	if pos >= len(st) {
		return "", fmt.Errorf("offset %d is out of bounds", offset)
	}

	if pos > 0 && st[pos-1] != '\x00' {
		return "", fmt.Errorf("offset %d isn't start of a string", offset)
	}

	str := st[pos:]
	end := bytes.IndexByte(str, '\x00')
	if end == -1 {
		return "", fmt.Errorf("offset %d isn't null terminated", offset)
	}

	return string(str[:end]), nil
}

type stringTableBuilder struct {
	offsets map[string]uint32
	buf     bytes.Buffer
}

func newStringTableBuilder() stringTableBuilder {
	stb := stringTableBuilder{
		offsets: map[string]uint32{
			"":   0,
			"\n": 0,
		},
	}
	stb.buf.WriteByte(0)
	return stb
}

func (stb *stringTableBuilder) insert(str string) uint32 {
	off, found := stb.offsets[str]
	if found {
		return off
	}

	strBytes := make([]byte, len(str)+1)
	copy(strBytes, str)

	off = uint32(stb.buf.Len())
	stb.offsets[str] = off
	stb.buf.Write(strBytes)

	return off
}

func (stb *stringTableBuilder) stringTable() stringTable {
	return stringTable(stb.buf.Bytes())
}
