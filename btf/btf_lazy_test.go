package btf

// import (
// 	"bytes"
// 	"encoding/binary"
// 	"io"
// 	"testing"

// 	"github.com/davecgh/go-spew/spew"
// )

// func vmlinuxTestdataOffsetReader(tb testing.TB) *bytes.Reader {
// 	tb.Helper()

// 	td, err := vmlinuxTestdata()
// 	if err != nil {
// 		tb.Fatal(err)
// 	}

// 	return bytes.NewReader(td.raw)
// }

// func BenchmarkParseLazyVmlinux(b *testing.B) {
// 	rd := vmlinuxTestdataReader(b)
// 	b.ReportAllocs()
// 	b.ResetTimer()

// 	for n := 0; n < b.N; n++ {
// 		if _, err := rd.Seek(0, io.SeekStart); err != nil {
// 			b.Fatal(err)
// 		}

// 		if _, err := lazyLoadRawSpec(rd, binary.LittleEndian, nil); err != nil {
// 			b.Fatal("Can't load BTF:", err)
// 		}
// 	}
// }

// func BenchmarkParseLazyAndIterVmlinux(b *testing.B) {
// 	rd := vmlinuxTestdataReader(b)
// 	b.ReportAllocs()
// 	b.ResetTimer()

// 	for n := 0; n < b.N; n++ {
// 		if _, err := rd.Seek(0, io.SeekStart); err != nil {
// 			b.Fatal(err)
// 		}

// 		spec, err := lazyLoadRawSpec(rd, binary.LittleEndian, nil)
// 		if err != nil {
// 			b.Fatal("Can't load BTF:", err)
// 		}

// 		for i := TypeID(0); i < TypeID(len(spec.typeOffsets)); i++ {
// 			_, err := spec.TypeByID(i + 1)
// 			if err != nil {
// 				b.Fatal(err)
// 			}
// 		}
// 	}
// }

// func TestLazyParse(t *testing.T) {
// 	rd := vmlinuxTestdataReader(t)

// 	spec, err := lazyLoadRawSpec(rd, binary.LittleEndian, nil)
// 	if err != nil {
// 		t.Fatal("Can't load BTF:", err)
// 	}

// 	count := make(map[string]int)

// 	for i := TypeID(0); i < TypeID(len(spec.typeOffsets)); i++ {
// 		typ, err := spec.TypeByID(i + 1)
// 		if err != nil {
// 			t.Fatal(err)
// 		}

// 		count[typ.TypeName()]++
// 	}

// 	for name, count := range count {
// 		if count > 1 {
// 			t.Logf("%s: %d", name, count)
// 		}
// 	}
// }

// func TestLazyAnyTypesByName(t *testing.T) {
// 	rd := vmlinuxTestdataReader(t)

// 	spec, err := lazyLoadRawSpec(rd, binary.LittleEndian, nil)
// 	if err != nil {
// 		t.Fatal("Can't load BTF:", err)
// 	}

// 	types, err := spec.AnyTypesByName("iommu_page_response")
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	spew.Dump(len(types))
// }
