package artifactscan

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"strings"
)

// moduleData holds the lazily-parsed facts that YARA-module condition
// expressions read from one artifact. It is built once per Scan and shared
// across every rule, so the executable is parsed at most once. Access is
// single-goroutine (Scan evaluates rules sequentially), so no locking.
type moduleData struct {
	data []byte

	peTried bool
	pe      *peFacts
	elfDone bool
	elf     *elfFacts
}

func newModuleData(data []byte) *moduleData { return &moduleData{data: data} }

// peFacts is the subset of the YARA `pe` module backed by debug/pe.
type peFacts struct {
	numSections int
	entryOff    int64 // file offset of the entry point, or -1 if not resolvable
	isDLL       bool
	importLibs  map[string]bool            // lowercased DLL names
	importSyms  map[string]map[string]bool // dll -> set of lowercased symbol names
}

// elfFacts is the subset of the YARA `elf` module backed by debug/elf.
type elfFacts struct {
	typ         int
	numSections int
}

func (m *moduleData) peData() *peFacts {
	if m.peTried {
		return m.pe
	}
	m.peTried = true
	f, err := pe.NewFile(bytes.NewReader(m.data))
	if err != nil {
		return nil
	}
	defer f.Close()
	pf := &peFacts{
		numSections: len(f.Sections),
		entryOff:    -1,
		isDLL:       f.Characteristics&0x2000 != 0, // IMAGE_FILE_DLL
		importLibs:  map[string]bool{},
		importSyms:  map[string]map[string]bool{},
	}
	var entryRVA uint32
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		entryRVA = oh.AddressOfEntryPoint
	case *pe.OptionalHeader64:
		entryRVA = oh.AddressOfEntryPoint
	}
	pf.entryOff = rvaToOffset(f, entryRVA)
	if libs, err := f.ImportedLibraries(); err == nil {
		for _, l := range libs {
			pf.importLibs[strings.ToLower(l)] = true
		}
	}
	// ImportedSymbols returns "Symbol:Library" entries; index by DLL.
	if syms, err := f.ImportedSymbols(); err == nil {
		for _, s := range syms {
			i := strings.LastIndexByte(s, ':')
			if i < 0 {
				continue
			}
			sym := strings.ToLower(s[:i])
			dll := strings.ToLower(s[i+1:])
			pf.importLibs[dll] = true
			if pf.importSyms[dll] == nil {
				pf.importSyms[dll] = map[string]bool{}
			}
			pf.importSyms[dll][sym] = true
		}
	}
	m.pe = pf
	return pf
}

// rvaToOffset maps a relative virtual address to a raw file offset using the
// section table (classic YARA pe.entry_point semantics: a file offset).
func rvaToOffset(f *pe.File, rva uint32) int64 {
	if rva == 0 {
		return -1
	}
	for _, s := range f.Sections {
		span := s.VirtualSize
		if s.Size > span {
			span = s.Size
		}
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+span {
			return int64(rva-s.VirtualAddress) + int64(s.Offset)
		}
	}
	return -1
}

func (m *moduleData) elfData() *elfFacts {
	if m.elfDone {
		return m.elf
	}
	m.elfDone = true
	f, err := elf.NewFile(bytes.NewReader(m.data))
	if err != nil {
		return nil
	}
	defer f.Close()
	m.elf = &elfFacts{typ: int(f.Type), numSections: len(f.Sections)}
	return m.elf
}

// --- module condition AST nodes -------------------------------------------

// exprNum / exprStr are literal value nodes.
type exprNum struct{ v int64 }

func (e exprNum) eval(*evalCtx) value { return intVal(e.v) }

type exprStr struct{ v string }

func (e exprStr) eval(*evalCtx) value { return strVal(e.v) }

// exprCompare is a relational comparison (== != < <= > >=) yielding a bool.
type exprCompare struct {
	op   string
	a, b condExpr
}

func (e exprCompare) eval(ctx *evalCtx) value {
	return compareValues(e.op, e.a.eval(ctx), e.b.eval(ctx))
}

// exprArith is a binary arithmetic / bitwise operation.
type exprArith struct {
	op   string
	a, b condExpr
}

func (e exprArith) eval(ctx *evalCtx) value {
	return arith(e.op, e.a.eval(ctx), e.b.eval(ctx))
}

// exprUnary is a prefix - (negate) or ~ (bitwise not).
type exprUnary struct {
	op string
	x  condExpr
}

func (e exprUnary) eval(ctx *evalCtx) value {
	v := e.x.eval(ctx)
	switch e.op {
	case "-":
		if v.kind == vInt {
			return intVal(-v.i)
		}
		if f, ok := v.asFloat(); ok {
			return floatVal(-f)
		}
	case "~":
		if v.kind == vInt {
			return intVal(^v.i)
		}
	}
	return undefVal
}

// exprModule is a module field (pe.number_of_sections), module function
// (pe.imports("k","f"), math.entropy(0, filesize), hash.sha256(...)), the
// filesize keyword, or an integer reader (uint16(0)).
type exprModule struct {
	path []string
	args []condExpr
	call bool
}

func (e exprModule) eval(ctx *evalCtx) value {
	return evalModule(ctx, e.path, e.args, e.call)
}

// knownModuleHead reports whether the leading identifier is a module/keyword
// this engine evaluates. Unknown heads (cuckoo, dotnet, time, …) cause the rule
// to be skipped at parse time, rather than silently never matching.
func knownModuleHead(head string) bool {
	switch head {
	case "filesize", "pe", "elf", "math", "hash",
		"uint8", "uint16", "uint32", "uint16be", "uint32be",
		"int8", "int16", "int32":
		return true
	}
	return false
}

func evalModule(ctx *evalCtx, path []string, args []condExpr, call bool) value {
	switch path[0] {
	case "filesize":
		if call || len(path) != 1 {
			return undefVal
		}
		return intVal(int64(len(ctx.data)))
	case "uint8", "uint16", "uint32", "uint16be", "uint32be", "int8", "int16", "int32":
		if !call || len(path) != 1 || len(args) != 1 {
			return undefVal
		}
		off, ok := args[0].eval(ctx).asInt()
		if !ok {
			return undefVal
		}
		return readInt(ctx.data, path[0], off)
	case "pe":
		return evalPE(ctx, path, args)
	case "elf":
		return evalELF(ctx, path)
	case "math":
		return evalMath(ctx, path, args)
	case "hash":
		return evalHash(ctx, path, args)
	}
	return undefVal
}

func readInt(data []byte, fn string, off int64) value {
	if off < 0 || off >= int64(len(data)) {
		return undefVal
	}
	o := int(off)
	switch fn {
	case "uint8":
		return intVal(int64(data[o]))
	case "int8":
		return intVal(int64(int8(data[o])))
	case "uint16":
		if o+2 > len(data) {
			return undefVal
		}
		return intVal(int64(binary.LittleEndian.Uint16(data[o:])))
	case "int16":
		if o+2 > len(data) {
			return undefVal
		}
		return intVal(int64(int16(binary.LittleEndian.Uint16(data[o:]))))
	case "uint16be":
		if o+2 > len(data) {
			return undefVal
		}
		return intVal(int64(binary.BigEndian.Uint16(data[o:])))
	case "uint32":
		if o+4 > len(data) {
			return undefVal
		}
		return intVal(int64(binary.LittleEndian.Uint32(data[o:])))
	case "int32":
		if o+4 > len(data) {
			return undefVal
		}
		return intVal(int64(int32(binary.LittleEndian.Uint32(data[o:]))))
	case "uint32be":
		if o+4 > len(data) {
			return undefVal
		}
		return intVal(int64(binary.BigEndian.Uint32(data[o:])))
	}
	return undefVal
}

func evalPE(ctx *evalCtx, path []string, args []condExpr) value {
	if len(path) != 2 {
		return undefVal
	}
	pf := ctx.mod.peData()
	if pf == nil {
		return undefVal
	}
	switch path[1] {
	case "number_of_sections":
		return intVal(int64(pf.numSections))
	case "entry_point":
		if pf.entryOff < 0 {
			return undefVal
		}
		return intVal(pf.entryOff)
	case "is_dll":
		return boolVal(pf.isDLL)
	case "imports":
		switch len(args) {
		case 1:
			dll := strings.ToLower(argStr(ctx, args[0]))
			return boolVal(pf.importLibs[dll])
		case 2:
			dll := strings.ToLower(argStr(ctx, args[0]))
			fn := strings.ToLower(argStr(ctx, args[1]))
			if syms, ok := pf.importSyms[dll]; ok {
				return boolVal(syms[fn])
			}
			return boolVal(false)
		}
	}
	return undefVal
}

// elfTypes maps the YARA elf.ET_* constant names to their numeric values.
var elfTypes = map[string]int64{
	"ET_NONE": 0, "ET_REL": 1, "ET_EXEC": 2, "ET_DYN": 3, "ET_CORE": 4,
}

func evalELF(ctx *evalCtx, path []string) value {
	if len(path) != 2 {
		return undefVal
	}
	if v, ok := elfTypes[path[1]]; ok {
		return intVal(v)
	}
	ef := ctx.mod.elfData()
	if ef == nil {
		return undefVal
	}
	switch path[1] {
	case "type":
		return intVal(int64(ef.typ))
	case "number_of_sections":
		return intVal(int64(ef.numSections))
	}
	return undefVal
}

func evalMath(ctx *evalCtx, path []string, args []condExpr) value {
	if len(path) != 2 {
		return undefVal
	}
	switch path[1] {
	case "entropy":
		if len(args) != 2 {
			return undefVal
		}
		seg := segment(ctx, args[0], args[1])
		if seg == nil {
			return undefVal
		}
		return floatVal(shannonEntropy(seg))
	case "in_range":
		if len(args) != 3 {
			return undefVal
		}
		x, okx := args[0].eval(ctx).asFloat()
		lo, oklo := args[1].eval(ctx).asFloat()
		hi, okhi := args[2].eval(ctx).asFloat()
		if !okx || !oklo || !okhi {
			return undefVal
		}
		return boolVal(x >= lo && x <= hi)
	}
	return undefVal
}

func evalHash(ctx *evalCtx, path []string, args []condExpr) value {
	if len(path) != 2 || len(args) != 2 {
		return undefVal
	}
	seg := segment(ctx, args[0], args[1])
	if seg == nil {
		return undefVal
	}
	switch path[1] {
	case "md5":
		sum := md5.Sum(seg)
		return strVal(hex.EncodeToString(sum[:]))
	case "sha1":
		sum := sha1.Sum(seg)
		return strVal(hex.EncodeToString(sum[:]))
	case "sha256":
		sum := sha256.Sum256(seg)
		return strVal(hex.EncodeToString(sum[:]))
	}
	return undefVal
}

// segment resolves (offset, length) argument expressions to a bounded slice of
// the artifact, or nil if the range is out of bounds.
func segment(ctx *evalCtx, offExpr, lenExpr condExpr) []byte {
	off, ok1 := offExpr.eval(ctx).asInt()
	ln, ok2 := lenExpr.eval(ctx).asInt()
	if !ok1 || !ok2 || off < 0 || ln < 0 {
		return nil
	}
	if off > int64(len(ctx.data)) || off+ln > int64(len(ctx.data)) {
		return nil
	}
	return ctx.data[off : off+ln]
}

func argStr(ctx *evalCtx, e condExpr) string {
	v := e.eval(ctx)
	if v.kind == vStr {
		return v.s
	}
	return ""
}
