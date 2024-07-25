package l4lbdrv

// Given an ELF binary, we read the DWARF debug info to extract the structs
// defined in the binary. This is used to assert that the binary layout of the
// structs defined in the C code match the structs defined in the Go code.

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"log/slog"
)

type dwarfReaderState int

const (
	dwarfReaderStateSkippingNonStructs dwarfReaderState = iota
	dwarfReaderStateInsideStruct
)

func (st dwarfReaderState) String() string {
	switch st {
	case dwarfReaderStateSkippingNonStructs:
		return "SkippingNonStructs"
	case dwarfReaderStateInsideStruct:
		return "InsideStruct"
	default:
		return fmt.Sprintf("dwarfReaderState(%d)", st)
	}
}

type DWARFStructField struct {
	Name   string
	Offset int64
}

type DWARFStruct struct {
	Name   string
	Size   int64
	Fields map[string]DWARFStructField
}

func ReadDWARFStructs(binPath string) (map[string]*DWARFStruct, error) {
	f, err := elf.Open(binPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to open bin %q: %w", binPath, err)
	}
	defer f.Close()

	dwarf5Sections := []string{
		".debug_str_offsets",
		".debug_rnglists",
		".debug_addr",
	}
	requiredSections := append([]string{
		".debug_abbrev",
		".debug_info",
		".debug_str",
	}, dwarf5Sections...)

	sbytes := make(map[string][]byte)
	for _, name := range requiredSections {
		s := f.Section(name)
		if s == nil {
			return nil, fmt.Errorf("Failed to find section %q", name)
		}
		bs, err := s.Data()
		if err != nil {
			return nil, fmt.Errorf("Failed to read section %q: %w", name, err)
		}
		sbytes[name] = bs
	}

	dw, err := dwarf.New(
		/*abbrev=*/ sbytes[".debug_abbrev"],
		/*aranges=*/ nil,
		/*frame=*/ nil,
		/*info=*/ sbytes[".debug_info"],
		/*line=*/ nil,
		/*pubnames=*/ nil,
		/*ranges=*/ nil,
		/*str=*/ sbytes[".debug_str"])
	if err != nil {
		return nil, fmt.Errorf("Failed to dwarf.New: %w", err)
	}
	for _, name := range dwarf5Sections {
		if err := dw.AddSection(name, sbytes[name]); err != nil {
			return nil, fmt.Errorf("Failed to dw.AddSection(%q): %w", name, err)
		}
	}

	structs := make(map[string]*DWARFStruct)
	state := dwarfReaderStateSkippingNonStructs
	curr := &DWARFStruct{}

	r := dw.Reader()
	for {
		e, err := r.Next()
		if err != nil {
			return nil, fmt.Errorf("Failed to r.Next: %w", err)
		}
		if e == nil {
			break
		}
		// l.Debugf("state: %s tag: %d e: %v", state, e.Tag, e)

		switch state {
		case dwarfReaderStateSkippingNonStructs:
			if e.Tag != dwarf.TagStructType {
				continue
			}

			name, ok := e.Val(dwarf.AttrName).(string)
			if !ok {
				// l.Warnf("entry unexpectedly missing name, skipping") // This actually seems to be the case for anonymous structs
				continue
			}
			size, ok := e.Val(dwarf.AttrByteSize).(int64)
			if !ok {
				if name == "bpf_map" {
					// Suppress error on `struct bpf_map`, since that's a forward declaration.
					continue
				}
				slog.Warn("Failed to decode AttrByteSize, skipping", slog.String("name", name))
				continue
			}

			state = dwarfReaderStateInsideStruct
			curr = &DWARFStruct{
				Name:   name,
				Size:   size,
				Fields: make(map[string]DWARFStructField),
			}
		case dwarfReaderStateInsideStruct:
			switch e.Tag {
			case 0:
				structs[curr.Name] = curr
				state = dwarfReaderStateSkippingNonStructs
			case dwarf.TagMember:
				name, ok := e.Val(dwarf.AttrName).(string)
				if !ok {
					// l.Warnf("entry unexpectedly missing name, skipping") // This actually seems to be the case for nested structs/unions
					continue
				}
				offset, ok := e.Val(dwarf.AttrDataMemberLoc).(int64)
				if !ok {
					slog.Warn("Failed to decode AttrDataMemberLoc, skipping", slog.String("name", name))
					continue
				}

				curr.Fields[name] = DWARFStructField{
					Name:   name,
					Offset: offset,
				}

			case dwarf.TagUnionType, dwarf.TagStructType:
				// l.Debugf("Nested structs are not supported, skipping")

			default:
				slog.Warn("Unexpected tag, skipping", slog.Uint64("tag", uint64(e.Tag)))
			}

		}
	}

	return structs, nil
}
