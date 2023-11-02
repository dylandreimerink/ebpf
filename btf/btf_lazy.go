package btf

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"reflect"
	"strings"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
	"golang.org/x/exp/slices"
)

// Interface implemented by both eagerSpec and lazySpec.
type Spec interface {
	AnyTypeByName(name string) (Type, error)
	AnyTypesByEssentialName(name string) ([]Type, error)
	AnyTypesByName(name string) ([]Type, error)
	Copy() Spec
	Iterate() TypesIterator
	TypeByID(id TypeID) (Type, error)
	TypeByName(name string, typ interface{}) error
	TypeID(typ Type) (TypeID, error)

	anyTypesByKind(kind btfKind) ([]Type, error)

	getFirstTypeID() TypeID
	nextTypeID() (TypeID, error)
	getByteOrder() binary.ByteOrder
	stringTable() stringTable
}

func lazyLoadRawSpec(btf io.ReaderAt, bo binary.ByteOrder, base Spec) (*lazySpec, error) {
	// TODO: turn reader at into ReaderAtCloser and close it when all references to it are gone

	var (
		baseStrings stringTable
		firstTypeID TypeID
		err         error
	)

	if base != nil {
		if base.getFirstTypeID() != 0 {
			return nil, fmt.Errorf("can't use split BTF as base")
		}

		baseStrings = base.stringTable()

		firstTypeID, err = base.nextTypeID()
		if err != nil {
			return nil, err
		}
	}

	typeOffsets, lazyStrings, err := lazyParseBTF(btf, bo, baseStrings)
	if err != nil {
		return nil, err
	}

	types := make(map[TypeID]Type)
	types[0] = (*Void)(nil)

	return &lazySpec{
		rd:   btf,
		base: base,

		firstTypeID: firstTypeID,
		strings:     lazyStrings,
		typeOffsets: typeOffsets,
		byteOrder:   bo,

		types:   types,
		typeIDs: make(map[Type]TypeID),
	}, nil
}

type lazySpec struct {
	rd   io.ReaderAt
	base Spec

	strings     stringTable
	firstTypeID TypeID
	typeOffsets []int64
	byteOrder   binary.ByteOrder

	types   map[TypeID]Type
	typeIDs map[Type]TypeID

	// eNameToTypeIDs map[string][]TypeID
}

func (ls *lazySpec) stringTable() stringTable {
	return ls.strings
}

func (ls *lazySpec) getFirstTypeID() TypeID {
	return ls.firstTypeID
}

func (ls *lazySpec) AnyTypeByName(name string) (Type, error) {
	types, err := ls.AnyTypesByName(name)
	if err != nil {
		return nil, err
	}

	if len(types) > 1 {
		return nil, fmt.Errorf("found multiple types: %v", types)
	}

	return types[0], nil
}

func (ls *lazySpec) AnyTypesByEssentialName(name string) ([]Type, error) {
	// TODO should we memoize essential name to types?

	essentialName := string(newEssentialName(name))

	// typeIds := ls.eNameToTypeIDs[essentialName]
	nameOffsets := make([]uint32, 0, 1)
	ls.strings.ForEach(func(off uint32, str string) error {
		if str == essentialName || strings.HasPrefix(str, essentialName+"___") {
			nameOffsets = append(nameOffsets, off)
		}

		return nil
	})

	if len(nameOffsets) == 0 {
		return nil, fmt.Errorf("type name %s: %w", name, ErrNotFound)
	}

	// Find all types with that name
	var types []Type
	for id, off := range ls.typeOffsets {
		// Read just the type header to get the name offset
		hdr, err := readTypeHeader(io.NewSectionReader(ls.rd, off, math.MaxInt64), ls.byteOrder)
		if err != nil {
			return nil, fmt.Errorf("can't read type header: %w", err)
		}

		if hdr.NameOff == 0 {
			continue
		}

		if !slices.Contains(nameOffsets, hdr.NameOff) {
			continue
		}

		// If the name offset matches, read the full type
		typ, err := ls.TypeByID(TypeID(id) + ls.firstTypeID + 1)
		if err != nil {
			return nil, fmt.Errorf("can't read type: %w", err)
		}

		types = append(types, typ)
	}

	if len(types) == 0 {
		return nil, fmt.Errorf("type name %s: %w", name, ErrNotFound)
	}

	return types, nil
}

func (ls *lazySpec) AnyTypesByName(name string) ([]Type, error) {
	types, err := ls.AnyTypesByEssentialName(name)
	if err != nil {
		return nil, err
	}

	// Return a copy to prevent changes to namedTypes.
	result := make([]Type, 0, len(types))
	for _, t := range types {
		// Match against the full name, not just the essential one
		// in case the type being looked up is a struct flavor.
		if t.TypeName() == name {
			result = append(result, t)
		}
	}
	return result, nil
}

func (ls *lazySpec) anyTypesByKind(kind btfKind) ([]Type, error) {
	// Find all types with that name
	var types []Type
	for id, off := range ls.typeOffsets {
		// Read just the type header to get the name offset
		hdr, err := readTypeHeader(io.NewSectionReader(ls.rd, off, math.MaxInt64), ls.byteOrder)
		if err != nil {
			return nil, fmt.Errorf("can't read type header: %w", err)
		}

		if hdr.Kind() != kind {
			continue
		}

		// If the name offset matches, read the full type
		typ, err := ls.TypeByID(TypeID(id) + ls.firstTypeID + 1)
		if err != nil {
			return nil, fmt.Errorf("can't read type: %w", err)
		}

		types = append(types, typ)
	}

	return types, nil
}

func (ls *lazySpec) Copy() Spec {
	types := make(map[TypeID]Type)
	types[0] = (*Void)(nil)

	return &lazySpec{
		rd:   ls.rd,
		base: ls.base,

		strings:     ls.strings,
		firstTypeID: ls.firstTypeID,
		typeOffsets: ls.typeOffsets,
		byteOrder:   ls.byteOrder,

		// Don't copy the memoized types, re-inflate whichever types are needed.
		types:   types,
		typeIDs: make(map[Type]TypeID),
	}
}

type lazyTypeIterator struct {
	ls  *lazySpec
	id  TypeID
	max TypeID

	typ Type
	err error
}

func (i *lazyTypeIterator) Next() bool {
	if i.id > i.max {
		return false
	}

	i.typ, i.err = i.ls.TypeByID(i.id)
	i.id++
	return true
}

func (i *lazyTypeIterator) Type() (Type, error) {
	return i.typ, i.err
}

func (ls *lazySpec) Iterate() TypesIterator {
	return &lazyTypeIterator{
		ls:  ls,
		id:  ls.firstTypeID,
		max: ls.firstTypeID + TypeID(len(ls.typeOffsets)),
	}
}

func (ls *lazySpec) TypeByID(id sys.TypeID) (Type, error) {
	if id < ls.firstTypeID {
		return nil, fmt.Errorf("type ID %d is out of range", id)
	}

	if typ, found := ls.types[id]; found {
		return typ, nil
	}

	if int(id-ls.firstTypeID-1) >= len(ls.typeOffsets) {
		return nil, fmt.Errorf("type ID %d: %w", id, ErrNotFound)
	}

	offset := ls.typeOffsets[id-ls.firstTypeID-1]
	return ls.inflateType(io.NewSectionReader(ls.rd, offset, math.MaxInt64), ls.byteOrder, id)
}

func (ls *lazySpec) TypeByName(name string, typ interface{}) error {
	typeInterface := reflect.TypeOf((*Type)(nil)).Elem()

	// typ may be **T or *Type
	typValue := reflect.ValueOf(typ)
	if typValue.Kind() != reflect.Ptr {
		return fmt.Errorf("%T is not a pointer", typ)
	}

	typPtr := typValue.Elem()
	if !typPtr.CanSet() {
		return fmt.Errorf("%T cannot be set", typ)
	}

	wanted := typPtr.Type()
	if wanted == typeInterface {
		// This is *Type. Unwrap the value's type.
		wanted = typPtr.Elem().Type()
	}

	if !wanted.AssignableTo(typeInterface) {
		return fmt.Errorf("%T does not satisfy Type interface", typ)
	}

	types, err := ls.AnyTypesByName(name)
	if err != nil {
		return err
	}

	var candidate Type
	for _, typ := range types {
		if reflect.TypeOf(typ) != wanted {
			continue
		}

		if candidate != nil {
			return fmt.Errorf("type %s(%T): %w", name, typ, ErrMultipleMatches)
		}

		candidate = typ
	}

	if candidate == nil {
		return fmt.Errorf("%s %s: %w", wanted, name, ErrNotFound)
	}

	typPtr.Set(reflect.ValueOf(candidate))

	return nil
}

func (ls *lazySpec) TypeID(typ Type) (sys.TypeID, error) {
	if _, ok := typ.(*Void); ok {
		// Equality is weird for void, since it is a zero sized type.
		return 0, nil
	}

	id, ok := ls.typeIDs[typ]
	if !ok {
		return 0, fmt.Errorf("no ID for type %s: %w", typ, ErrNotFound)
	}

	return id, nil
}

func (ls *lazySpec) nextTypeID() (TypeID, error) {
	id := ls.firstTypeID + TypeID(len(ls.typeOffsets))
	if id < ls.firstTypeID {
		return 0, fmt.Errorf("no more type IDs")
	}
	return id, nil
}

func (ls *lazySpec) getByteOrder() binary.ByteOrder {
	return ls.byteOrder
}

func (ls *lazySpec) inflateType(r io.Reader, bo binary.ByteOrder, id TypeID) (Type, error) {
	rawType, err := readRawType(r, id, bo)
	if err != nil {
		return nil, err
	}

	// Get the type without the fixups applied
	typ, fixups, err := ls.newUnfixedType(rawType, ls.firstTypeID, id)
	if err != nil {
		return nil, err
	}

	// Add the unfinished type to the type map to allow recursive types
	ls.types[id] = typ
	ls.typeIDs[typ] = id

	// Apply the fixups, which will further inflate types we depend on
	for _, fixup := range fixups {
		var fixupType Type
		if fixup.id < ls.firstTypeID {
			fixupType, err = ls.base.TypeByID(fixup.id)
		} else {
			fixupType, err = ls.TypeByID(fixup.id)
		}
		if err != nil {
			return nil, err
		}

		*fixup.typ = fixupType
	}

	return typ, nil
}

type typeFixup struct {
	id  TypeID
	typ *Type
}

func (ls *lazySpec) newUnfixedType(raw rawType, firstTypeID, id TypeID) (Type, []typeFixup, error) {
	var fixups []typeFixup
	fixup := func(id TypeID, typ *Type) {
		if id < firstTypeID {
			if baseType, err := ls.base.TypeByID(id); err == nil {
				*typ = baseType
				return
			}
		}

		var found bool
		*typ, found = ls.types[id]
		if found {
			return
		}

		fixups = append(fixups, typeFixup{id, typ})
	}

	name, err := ls.strings.Lookup(raw.NameOff)
	if err != nil {
		return nil, nil, err
	}

	var typ Type

	convertMembers := func(raw []btfMember, kindFlag bool) ([]Member, error) {
		// NB: The fixup below relies on pre-allocating this array to
		// work, since otherwise append might re-allocate members.
		members := make([]Member, 0, len(raw))
		for i, btfMember := range raw {
			name, err := ls.strings.Lookup(btfMember.NameOff)
			if err != nil {
				return nil, fmt.Errorf("can't get name for member %d: %w", i, err)
			}

			members = append(members, Member{
				Name:   name,
				Offset: Bits(btfMember.Offset),
			})

			m := &members[i]
			fixup(raw[i].Type, &m.Type)

			if kindFlag {
				m.BitfieldSize = Bits(btfMember.Offset >> 24)
				m.Offset &= 0xffffff
				// We ignore legacy bitfield definitions if the current composite
				// is a new-style bitfield. This is kind of safe since offset and
				// size on the type of the member must be zero if kindFlat is set
				// according to spec.
				continue
			}

			// TODO implement bitfield support

			// // This may be a legacy bitfield, try to fix it up.
			// data, ok := legacyBitfields[raw[i].Type]
			// if ok {
			// 	// Bingo!
			// 	m.Offset += data[0]
			// 	m.BitfieldSize = data[1]
			// 	continue
			// }

			// if m.Type != nil {
			// 	// We couldn't find a legacy bitfield, but we know that the member's
			// 	// type has already been inflated. Hence we know that it can't be
			// 	// a legacy bitfield and there is nothing left to do.
			// 	continue
			// }

			// // We don't have fixup data, and the type we're pointing
			// // at hasn't been inflated yet. No choice but to defer
			// // the fixup.
			// bitfieldFixups = append(bitfieldFixups, bitfieldFixupDef{
			// 	raw[i].Type,
			// 	m,
			// })
		}
		return members, nil
	}

	switch raw.Kind() {
	case kindInt:
		// size := raw.Size()
		// TODO implement bitfield support
		// if bi.Offset() > 0 || bi.Bits().Bytes() != size {
		// 	legacyBitfields[id] = [2]Bits{bi.Offset(), bi.Bits()}
		// }

		bi := raw.data.(*btfInt)
		typ = &Int{name, raw.Size(), bi.Encoding()}

	case kindPointer:
		ptr := &Pointer{nil}
		fixup(raw.Type(), &ptr.Target)
		typ = ptr

	case kindArray:
		btfArr := raw.data.(*btfArray)
		arr := &Array{nil, nil, btfArr.Nelems}
		fixup(btfArr.IndexType, &arr.Index)
		fixup(btfArr.Type, &arr.Type)
		typ = arr

	case kindStruct:
		members, err := convertMembers(raw.data.([]btfMember), raw.Bitfield())
		if err != nil {
			return nil, nil, fmt.Errorf("struct %s (id %d): %w", name, id, err)
		}
		typ = &Struct{name, raw.Size(), members}

	case kindUnion:
		members, err := convertMembers(raw.data.([]btfMember), raw.Bitfield())
		if err != nil {
			return nil, nil, fmt.Errorf("union %s (id %d): %w", name, id, err)
		}
		typ = &Union{name, raw.Size(), members}

	case kindEnum:
		rawvals := raw.data.([]btfEnum)
		vals := make([]EnumValue, 0, len(rawvals))
		signed := raw.Signed()
		for i, btfVal := range rawvals {
			name, err := ls.strings.Lookup(btfVal.NameOff)
			if err != nil {
				return nil, nil, fmt.Errorf("get name for enum value %d: %s", i, err)
			}
			value := uint64(btfVal.Val)
			if signed {
				// Sign extend values to 64 bit.
				value = uint64(int32(btfVal.Val))
			}
			vals = append(vals, EnumValue{name, value})
		}
		typ = &Enum{name, raw.Size(), signed, vals}

	case kindForward:
		typ = &Fwd{name, raw.FwdKind()}

	case kindTypedef:
		typedef := &Typedef{name, nil}
		fixup(raw.Type(), &typedef.Type)
		typ = typedef

	case kindVolatile:
		volatile := &Volatile{nil}
		fixup(raw.Type(), &volatile.Type)
		typ = volatile

	case kindConst:
		cnst := &Const{nil}
		fixup(raw.Type(), &cnst.Type)
		typ = cnst

	case kindRestrict:
		restrict := &Restrict{nil}
		fixup(raw.Type(), &restrict.Type)
		typ = restrict

	case kindFunc:
		fn := &Func{name, nil, raw.Linkage()}
		fixup(raw.Type(), &fn.Type)
		typ = fn

	case kindFuncProto:
		rawparams := raw.data.([]btfParam)
		params := make([]FuncParam, 0, len(rawparams))
		for i, param := range rawparams {
			name, err := ls.strings.Lookup(param.NameOff)
			if err != nil {
				return nil, nil, fmt.Errorf("get name for func proto parameter %d: %s", i, err)
			}
			params = append(params, FuncParam{
				Name: name,
			})
		}
		for i := range params {
			fixup(rawparams[i].Type, &params[i].Type)
		}

		fp := &FuncProto{nil, params}
		fixup(raw.Type(), &fp.Return)
		typ = fp

	case kindVar:
		variable := raw.data.(*btfVariable)
		v := &Var{name, nil, VarLinkage(variable.Linkage)}
		fixup(raw.Type(), &v.Type)
		typ = v

	case kindDatasec:
		btfVars := raw.data.([]btfVarSecinfo)
		vars := make([]VarSecinfo, 0, len(btfVars))
		for _, btfVar := range btfVars {
			vars = append(vars, VarSecinfo{
				Offset: btfVar.Offset,
				Size:   btfVar.Size,
			})
		}
		for i := range vars {
			fixup(btfVars[i].Type, &vars[i].Type)
		}
		typ = &Datasec{name, raw.Size(), vars}

	case kindFloat:
		typ = &Float{name, raw.Size()}

	case kindDeclTag:
		btfIndex := raw.data.(*btfDeclTag).ComponentIdx
		if uint64(btfIndex) > math.MaxInt {
			return nil, nil, fmt.Errorf("type id %d: index exceeds int", id)
		}

		dt := &declTag{nil, name, int(int32(btfIndex))}
		fixup(raw.Type(), &dt.Type)
		typ = dt

		// TODO decl tag checks
		// declTags = append(declTags, dt)

	case kindTypeTag:
		tt := &typeTag{nil, name}
		fixup(raw.Type(), &tt.Type)
		typ = tt

	case kindEnum64:
		rawvals := raw.data.([]btfEnum64)
		vals := make([]EnumValue, 0, len(rawvals))
		for i, btfVal := range rawvals {
			name, err := ls.strings.Lookup(btfVal.NameOff)
			if err != nil {
				return nil, nil, fmt.Errorf("get name for enum64 value %d: %s", i, err)
			}
			value := (uint64(btfVal.ValHi32) << 32) | uint64(btfVal.ValLo32)
			vals = append(vals, EnumValue{name, value})
		}
		typ = &Enum{name, raw.Size(), raw.Signed(), vals}

	}

	return typ, fixups, nil
}

type lazyStringTable struct {
	base    stringTable
	rd      sizedReaderAt
	offsets []uint32

	strBuf []byte
}

type sizedReaderAt interface {
	io.Reader
	io.ReaderAt
	Size() int64
}

func readLazyStringTable(r sizedReaderAt, base stringTable) (*lazyStringTable, error) {
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

	maxStrSize := 0
	offset := firstStringOffset
	scanner := bufio.NewScanner(r)
	scanner.Split(splitNull)
	for scanner.Scan() {
		str := scanner.Text()
		if len(str) > maxStrSize {
			maxStrSize = len(str)
		}
		offsets = append(offsets, offset)
		offset += uint32(len(str)) + 1
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Make a new slice the exact size of offsets and copy the values over.
	// This avoids holding onto more memory than necessary due to the likely oversized capacity.
	offsetsExact := make([]uint32, len(offsets))
	copy(offsetsExact, offsets)

	return &lazyStringTable{base, r, offsetsExact, make([]byte, maxStrSize)}, nil
}

func (st *lazyStringTable) nextOffset() uint32 {
	return uint32(st.rd.Size())
}

var ErrOffsetNotFound = fmt.Errorf("offset not found")

func (st *lazyStringTable) ForEach(fn func(uint32, string) error) error {
	for i := 0; i < len(st.offsets); i++ {
		var (
			str string
			err error
			end uint32
		)

		start := st.offsets[i]
		if st.base != nil {
			start -= st.base.nextOffset()
		}

		if i >= len(st.offsets)-1 {
			end = uint32(st.rd.Size()) - 1
		} else {
			end = st.offsets[i+1] - 1
			if st.base != nil {
				end -= st.base.nextOffset()
			}
		}

		str, err = st.get(start, end)
		if err != nil {
			return err
		}

		if err := fn(st.offsets[i], str); err != nil {
			return err
		}
	}

	return nil
}

func (st *lazyStringTable) Lookup(offset uint32) (string, error) {
	if st.base != nil && offset < st.base.nextOffset() {
		return st.base.lookup(offset)
	}
	return st.lookup(offset)
}

func (st *lazyStringTable) lookup(offset uint32) (string, error) {
	// TODO just scan for the next null byte?

	i, found := slices.BinarySearch(st.offsets, offset)
	if !found {
		return "", fmt.Errorf("offset %d isn't start of a string", offset)
	}

	start := st.offsets[i]

	var end uint32
	if i+1 < len(st.offsets) {
		end = st.offsets[i+1] - 1
	} else {
		end = uint32(st.rd.Size()) - 1
	}

	if st.base != nil {
		start -= st.base.nextOffset()
		end -= st.base.nextOffset()
	}

	return st.get(start, end)
}

func (st *lazyStringTable) get(start, end uint32) (string, error) {
	n, err := st.rd.ReadAt(st.strBuf[:(end-start)], int64(start))
	if err != nil {
		return "", err
	}

	return string(st.strBuf[:n]), nil
}

func (st *lazyStringTable) Marshal(w io.Writer) error {
	for _, off := range st.offsets {
		str, err := st.Lookup(off)
		if err != nil {
			return err
		}

		_, err = io.WriteString(w, str)
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
func (st *lazyStringTable) Num() int {
	return len(st.offsets)
}

// lazyParseBTF
func lazyParseBTF(btf io.ReaderAt, bo binary.ByteOrder, baseStrings stringTable) ([]int64, *lazyStringTable, error) {
	buf := internal.NewBufferedSectionReader(btf, 0, math.MaxInt64)
	header, err := parseBTFHeader(buf, bo)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing .BTF header: %v", err)
	}

	lazyStrings, err := readLazyStringTable(io.NewSectionReader(btf, header.stringStart(), int64(header.StringLen)),
		baseStrings)
	if err != nil {
		return nil, nil, fmt.Errorf("can't read type names: %w", err)
	}

	buf.Reset(io.NewSectionReader(btf, header.typeStart(), int64(header.TypeLen)))
	typeOffsets, err := readTypeOffsets(buf, bo, header.typeStart(), header.TypeLen)
	if err != nil {
		return nil, nil, fmt.Errorf("can't read types: %w", err)
	}

	return typeOffsets, lazyStrings, nil
}

func readTypeOffsets(buf *bufio.Reader, bo binary.ByteOrder, typeStart int64, typeLen uint32) ([]int64, error) {
	var header btfType
	// because of the interleaving between types and struct members it is difficult to
	// precompute the numbers of raw types this will parse
	// this "guess" is a good first estimation
	sizeOfbtfType := uintptr(btfTypeLen)
	tyMaxCount := uintptr(typeLen) / sizeOfbtfType / 2
	offsets := make([]int64, 0, tyMaxCount)

	// TODO can we make this nicer?
	const (
		headerSize   = int(4 * 3)
		intSize      = int(4 * 1)
		arraySize    = int(4 * 3)
		memberSize   = int(4 * 3)
		enumSize     = int(4 * 2)
		paramSize    = int(4 * 2)
		varSecSize   = int(4 * 3)
		variableSize = int(4 * 1)
		declTagSize  = int(4 * 1)
		enum64Size   = int(4 * 3)
	)

	offset := typeStart

	for id := TypeID(1); ; id++ {
		if err := binary.Read(buf, bo, &header); err == io.EOF {
			return offsets, nil
		} else if err != nil {
			return nil, fmt.Errorf("can't read type info for id %v: %v", id, err)
		}

		offsets = append(offsets, offset)
		offset += int64(headerSize)

		var (
			n   int
			err error
		)
		switch header.Kind() {
		case kindInt:
			n, err = buf.Discard(intSize)
		case kindPointer:
		case kindArray:
			n, err = buf.Discard(arraySize)
		case kindStruct:
			fallthrough
		case kindUnion:
			n, err = buf.Discard(memberSize * int(header.Vlen()))
		case kindEnum:
			n, err = buf.Discard(enumSize * int(header.Vlen()))
		case kindForward:
		case kindTypedef:
		case kindVolatile:
		case kindConst:
		case kindRestrict:
		case kindFunc:
		case kindFuncProto:
			n, err = buf.Discard(paramSize * int(header.Vlen()))
		case kindVar:
			n, err = buf.Discard(variableSize)
		case kindDatasec:
			n, err = buf.Discard(varSecSize * int(header.Vlen()))
		case kindFloat:
		case kindDeclTag:
			n, err = buf.Discard(declTagSize)
		case kindTypeTag:
		case kindEnum64:
			n, err = buf.Discard(enum64Size * int(header.Vlen()))
		default:
			return nil, fmt.Errorf("type id %v: unknown kind: %v", id, header.Kind())
		}

		if err != nil {
			return nil, fmt.Errorf("type id %d: kind %v: can't discard %d bytes: %v", id, header.Kind(), intSize, err)
		}
		offset += int64(n)
	}
}

var headerBufFreelist = make(chan []byte, 16)

func readTypeHeader(r io.Reader, bo binary.ByteOrder) (btfType, error) {
	// Take a buffer from the freelist if available, otherwise allocate a new one.
	var buf []byte
	select {
	case buf = <-headerBufFreelist:
	default:
		buf = make([]byte, 3*4)
	}

	_, err := r.Read(buf)
	if err != nil {
		return btfType{}, fmt.Errorf("can't read type info: %v", err)
	}

	header := btfType{
		NameOff:  bo.Uint32(buf[:4]),
		Info:     bo.Uint32(buf[4:8]),
		SizeType: bo.Uint32(buf[8:12]),
	}

	// Put the buffer back in the freelist
	select {
	case headerBufFreelist <- buf:
	default:
	}

	return header, nil
}

func readRawType(r io.Reader, id TypeID, bo binary.ByteOrder) (rawType, error) {
	header, err := readTypeHeader(r, bo)
	if err != nil {
		return rawType{}, err
	}

	var data interface{}
	switch header.Kind() {
	case kindInt:
		data = new(btfInt)
	case kindPointer:
	case kindArray:
		data = new(btfArray)
	case kindStruct:
		fallthrough
	case kindUnion:
		data = make([]btfMember, header.Vlen())
	case kindEnum:
		data = make([]btfEnum, header.Vlen())
	case kindForward:
	case kindTypedef:
	case kindVolatile:
	case kindConst:
	case kindRestrict:
	case kindFunc:
	case kindFuncProto:
		data = make([]btfParam, header.Vlen())
	case kindVar:
		data = new(btfVariable)
	case kindDatasec:
		data = make([]btfVarSecinfo, header.Vlen())
	case kindFloat:
	case kindDeclTag:
		data = new(btfDeclTag)
	case kindTypeTag:
	case kindEnum64:
		data = make([]btfEnum64, header.Vlen())
	default:
		return rawType{}, fmt.Errorf("type id %v: unknown kind: %v", id, header.Kind())
	}

	if data == nil {
		return rawType{header, nil}, nil
	}

	if err := binary.Read(r, bo, data); err != nil {
		return rawType{}, fmt.Errorf("type id %d: kind %v: can't read %T: %v", id, header.Kind(), data, err)
	}

	return rawType{header, data}, nil
}
