package btf

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

type stringTable interface {
	Lookup(offset uint32) (string, error)
	ForEach(func(uint32, string) error) error
	Marshal(w io.Writer) error
	Num() int

	lookup(offset uint32) (string, error)
	nextOffset() uint32
}

type eagerStringTable struct {
	base    stringTable
	offsets []uint32
	strings []string
}

// sizedReader is implemented by bytes.Reader, io.SectionReader, strings.Reader, etc.
type sizedReader interface {
	io.Reader
	Size() int64
}

func readStringTable(r sizedReader, base stringTable) (stringTable, error) {
	// When parsing split BTF's string table, the first entry offset is derived
	// from the last entry offset of the base BTF.
	firstStringOffset := uint32(0)
	if base != nil {
		firstStringOffset = base.nextOffset()
	}

	// Derived from vmlinux BTF.
	const averageStringLength = 16

	n := int(r.Size() / averageStringLength)
	offsets := make([]uint32, 0, n)
	strings := make([]string, 0, n)

	offset := firstStringOffset
	scanner := bufio.NewScanner(r)
	scanner.Split(splitNull)
	for scanner.Scan() {
		str := scanner.Text()
		offsets = append(offsets, offset)
		strings = append(strings, str)
		offset += uint32(len(str)) + 1
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(strings) == 0 {
		return nil, errors.New("string table is empty")
	}

	if firstStringOffset == 0 && strings[0] != "" {
		return nil, errors.New("first item in string table is non-empty")
	}

	return &eagerStringTable{base, offsets, strings}, nil
}

func splitNull(data []byte, atEOF bool) (advance int, token []byte, err error) {
	i := bytes.IndexByte(data, 0)
	if i == -1 {
		if atEOF && len(data) > 0 {
			return 0, nil, errors.New("string table isn't null terminated")
		}
		return 0, nil, nil
	}

	return i + 1, data[:i], nil
}

func (st *eagerStringTable) nextOffset() uint32 {
	idx := len(st.offsets) - 1
	return st.offsets[idx] + uint32(len(st.strings[idx])) + 1
}

func (st *eagerStringTable) Lookup(offset uint32) (string, error) {
	if st.base != nil && offset < st.base.nextOffset() {
		return st.base.lookup(offset)
	}
	return st.lookup(offset)
}

func (st *eagerStringTable) ForEach(fn func(uint32, string) error) error {
	for i, offset := range st.offsets {
		if err := fn(offset, st.strings[i]); err != nil {
			return err
		}
	}

	return nil
}

func (st *eagerStringTable) lookup(offset uint32) (string, error) {
	i, found := slices.BinarySearch(st.offsets, offset)
	if !found {
		return "", fmt.Errorf("offset %d isn't start of a string", offset)
	}

	return st.strings[i], nil
}

func (st *eagerStringTable) Marshal(w io.Writer) error {
	for _, str := range st.strings {
		_, err := io.WriteString(w, str)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{0})
		if err != nil {
			return err
		}
	}
	return nil
}

// Num returns the number of strings in the table.
func (st *eagerStringTable) Num() int {
	return len(st.strings)
}

// stringTableBuilder builds BTF string tables.
type stringTableBuilder struct {
	length  uint32
	strings map[string]uint32
}

// newStringTableBuilder creates a builder with the given capacity.
//
// capacity may be zero.
func newStringTableBuilder(capacity int) *stringTableBuilder {
	var stb stringTableBuilder

	if capacity == 0 {
		// Use the runtime's small default size.
		stb.strings = make(map[string]uint32)
	} else {
		stb.strings = make(map[string]uint32, capacity)
	}

	// Ensure that the empty string is at index 0.
	stb.append("")
	return &stb
}

// Add a string to the table.
//
// Adding the same string multiple times will only store it once.
func (stb *stringTableBuilder) Add(str string) (uint32, error) {
	if strings.IndexByte(str, 0) != -1 {
		return 0, fmt.Errorf("string contains null: %q", str)
	}

	offset, ok := stb.strings[str]
	if ok {
		return offset, nil
	}

	return stb.append(str), nil
}

func (stb *stringTableBuilder) append(str string) uint32 {
	offset := stb.length
	stb.length += uint32(len(str)) + 1
	stb.strings[str] = offset
	return offset
}

// Lookup finds the offset of a string in the table.
//
// Returns an error if str hasn't been added yet.
func (stb *stringTableBuilder) Lookup(str string) (uint32, error) {
	offset, ok := stb.strings[str]
	if !ok {
		return 0, fmt.Errorf("string %q is not in table", str)
	}

	return offset, nil
}

// Length returns the length in bytes.
func (stb *stringTableBuilder) Length() int {
	return int(stb.length)
}

// AppendEncoded appends the string table to the end of the provided buffer.
func (stb *stringTableBuilder) AppendEncoded(buf []byte) []byte {
	n := len(buf)
	buf = append(buf, make([]byte, stb.Length())...)
	strings := buf[n:]
	for str, offset := range stb.strings {
		copy(strings[offset:], str)
	}
	return buf
}

// Copy the string table builder.
func (stb *stringTableBuilder) Copy() *stringTableBuilder {
	return &stringTableBuilder{
		stb.length,
		maps.Clone(stb.strings),
	}
}
