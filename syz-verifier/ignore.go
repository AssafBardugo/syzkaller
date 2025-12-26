package main

import (
	_ "embed"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/google/syzkaller/pkg/log"
	"gopkg.in/yaml.v3"
)

//go:embed ignore_list.yaml
var ignoreListYAML []byte

var (
	ignoreRules     []IgnoreRule
	ignoreRulesOnce sync.Once
	ignoreRulesErr  error
)

const atFDCWD int64 = -100

type IgnoreRulesFile struct {
	Rules []IgnoreRule `yaml:"rules"`
}

type IgnoreRule struct {
	Call          string      `yaml:"call"`
	ChangeVersion string      `yaml:"change_version"`
	OldErrno      string      `yaml:"old_errno"`
	NewErrno      string      `yaml:"new_errno"`
	Match         IgnoreMatch `yaml:"match"`

	parsedVersion kernelVersion
	versionOK     bool
}

type IgnoreMatch struct {
	Args ArgMatches `yaml:"args"`
}

type ArgMatches []ArgMatch

func (a *ArgMatches) UnmarshalYAML(value *yaml.Node) error {
	if value == nil {
		return nil
	}
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("args: expected mapping, got %v", value.Kind)
	}
	var matches []ArgMatch
	for i := 0; i < len(value.Content); i += 2 {
		keyNode := value.Content[i]
		valNode := value.Content[i+1]
		var cond ArgCond
		if err := valNode.Decode(&cond); err != nil {
			return err
		}
		matches = append(matches, ArgMatch{
			Name: keyNode.Value,
			Cond: cond,
		})
	}
	*a = matches
	return nil
}

type ArgMatch struct {
	Name string
	Cond ArgCond
}

type FSSuperblockCond struct {
	RoCompat bool `yaml:"ro_compat"`
}

type ArgCond struct {
	Equals       *string           `yaml:"equals"`
	NotEquals    *string           `yaml:"not_equals"`
	Endswith     *string           `yaml:"endswith"`
	Any          bool              `yaml:"any"`
	PositiveFD   bool              `yaml:"positive_fd"`
	FSSuperblock *FSSuperblockCond `yaml:"fs_superblock"`
}

type kernelVersion struct {
	major int
	minor int
	patch int
}

func shouldIgnoreMismatch(callLine string, call0Err, call1Err int32,
	baseVer, otherVer kernelVersion, versionsOK bool) bool {

	if !versionsOK {
		return false
	}

	rules, err := loadIgnoreRules()
	if err != nil {
		log.Logf(0, "failed to load ignore rules: %v", err)
		return false
	}

	callName := extractCallName(callLine)
	for _, rule := range rules {
		if !rule.versionOK || rule.Call != callName {
			continue
		}

		if !rule.matchArgs(callLine) {
			continue
		}

		baseOld := errnoString(call0Err) == rule.OldErrno
		baseNew := errnoString(call0Err) == rule.NewErrno
		otherOld := errnoString(call1Err) == rule.OldErrno
		otherNew := errnoString(call1Err) == rule.NewErrno

		// base is old, other is new
		if baseOld && otherNew && versionLessThan(baseVer, rule.parsedVersion) && !versionLessThan(otherVer, rule.parsedVersion) {
			return true
		}
		// base is new, other is old
		if baseNew && otherOld && !versionLessThan(baseVer, rule.parsedVersion) && versionLessThan(otherVer, rule.parsedVersion) {
			return true
		}
	}
	return false
}

func loadIgnoreRules() ([]IgnoreRule, error) {

	ignoreRulesOnce.Do(func() {
		var file IgnoreRulesFile
		if err := yaml.Unmarshal(ignoreListYAML, &file); err != nil {
			ignoreRulesErr = err
			return
		}
		for i := range file.Rules {
			file.Rules[i].parsedVersion, file.Rules[i].versionOK = parseKernelVersionString(file.Rules[i].ChangeVersion)
		}
		ignoreRules = file.Rules
	})
	return ignoreRules, ignoreRulesErr
}

func parseKernelVersionString(ver string) (kernelVersion, bool) {
	parts := strings.Split(ver, ".")
	if len(parts) < 2 {
		return kernelVersion{}, false
	}

	parsePart := func(s string) (int, bool) {
		s = strings.TrimSpace(s)
		i := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == 0 {
			return 0, false
		}
		v, err := strconv.Atoi(s[:i])
		return v, err == nil
	}

	major, okMajor := parsePart(parts[0])
	minor, okMinor := parsePart(parts[1])
	patch := 0
	okPatch := true
	if len(parts) > 2 {
		if v, ok := parsePart(parts[2]); ok {
			patch = v
		} else {
			okPatch = false
		}
	}
	if !okMajor || !okMinor || !okPatch {
		return kernelVersion{}, false
	}
	return kernelVersion{major: major, minor: minor, patch: patch}, true
}

func versionLessThan(a, b kernelVersion) bool {
	if a.major != b.major {
		return a.major < b.major
	}
	if a.minor != b.minor {
		return a.minor < b.minor
	}
	return a.patch < b.patch
}

func errnoString(errno int32) string {
	return strconv.FormatInt(int64(errno), 10)
}

func extractCallName(callLine string) string {

	line := strings.TrimSpace(callLine)
	if line == "" {
		return ""
	}

	callName := line
	if idx := strings.Index(line, "("); idx > 0 {
		callName = line[:idx]
	}

	if eqIdx := strings.LastIndex(callName, "="); eqIdx >= 0 {
		callName = callName[eqIdx+1:]
	}

	return strings.TrimSpace(callName)
}

func (rule IgnoreRule) matchArgs(callLine string) bool {
	if len(rule.Match.Args) == 0 {
		return true
	}
	args := extractCallArgs(callLine)
	for idx, argRule := range rule.Match.Args {
		if idx >= len(args) {
			return false
		}
		if !argRule.Cond.match(args[idx]) {
			return false
		}
	}
	return true
}

func extractCallArgs(callLine string) []string {
	start := strings.Index(callLine, "(")
	if start == -1 {
		return nil
	}
	end := strings.LastIndex(callLine, ")")
	if end == -1 || end <= start {
		end = len(callLine)
	}
	argPart := callLine[start+1 : end]

	var args []string
	depth := 0
	last := 0
	inString := false
	var quote rune
	escapeNext := false

	for i, r := range argPart {
		if escapeNext {
			escapeNext = false
			continue
		}
		switch r {
		case '\\':
			if inString {
				escapeNext = true
			}
		case '\'', '"':
			if inString && r == quote {
				inString = false
			} else if !inString {
				inString = true
				quote = r
			}
		case '(', '{', '[':
			if !inString {
				depth++
			}
		case ')', '}', ']':
			if !inString && depth > 0 {
				depth--
			}
		case ',':
			if !inString && depth == 0 {
				arg := strings.TrimSpace(argPart[last:i])
				args = append(args, arg)
				last = i + 1
			}
		}
	}
	if last <= len(argPart) {
		tail := strings.TrimSpace(argPart[last:])
		if tail != "" {
			args = append(args, tail)
		}
	}
	return args
}

func (c ArgCond) match(arg string) bool {
	if c.Any {
		return true
	}

	variants := argVariants(arg)
	matched := false

	if c.Equals != nil {
		matched = true
		if !anyVariant(variants, func(v string) bool { return v == *c.Equals }) {
			return false
		}
	}
	if c.NotEquals != nil {
		matched = true
		if anyVariant(variants, func(v string) bool { return v == *c.NotEquals }) {
			return false
		}
	}
	if c.Endswith != nil {
		matched = true
		if !anyVariant(variants, func(v string) bool { return strings.HasSuffix(v, *c.Endswith) }) {
			return false
		}
	}
	if c.PositiveFD {
		matched = true
		if !anyVariant(variants, isPositiveFD) {
			return false
		}
	}
	if c.FSSuperblock != nil {
		matched = true
		hasRO := anyVariant(variants, checkImageRoCompat)
		if c.FSSuperblock.RoCompat && !hasRO {
			return false
		}
		if !c.FSSuperblock.RoCompat && hasRO {
			return false
		}
	}
	return matched
}

func anyVariant(vars []string, fn func(string) bool) bool {
	for _, v := range vars {
		if fn(v) {
			return true
		}
	}
	return false
}

func argVariants(arg string) []string {
	trimmed := strings.TrimSpace(arg)
	variants := []string{trimmed}

	if idx := strings.Index(trimmed, "="); idx >= 0 {
		val := strings.TrimSpace(trimmed[idx+1:])
		variants = append(variants, val)
	}

	var dedup []string
	seen := make(map[string]struct{})
	for _, v := range variants {
		unquoted := trimMatchingQuotes(v)
		for _, cand := range []string{v, unquoted} {
			if cand == "" {
				continue
			}
			if _, ok := seen[cand]; ok {
				continue
			}
			seen[cand] = struct{}{}
			dedup = append(dedup, cand)
		}
	}
	return dedup
}

func trimMatchingQuotes(s string) string {
	if len(s) < 2 {
		return s
	}
	first, last := s[0], s[len(s)-1]
	if first == last && (first == '"' || first == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

func isPositiveFD(arg string) bool {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return false
	}
	// syzkaller-style resource reference: r0, r1, ...
	if arg[0] == 'r' {
		return true
	}
	val, ok := parseFD(arg)
	if !ok {
		return false
	}
	// Treat AT_FDCWD as a valid dirfd for matching purposes.
	return val == atFDCWD || val > 0
}

// parseFD accepts signed literals and, if the signed parse overflows, allows
// two's-complement hex re-interpretation (e.g. 0xffffffffffffff9c -> -100).
func parseFD(arg string) (int64, bool) {
	val, err := strconv.ParseInt(arg, 0, 64)
	if err == nil {
		return val, true
	}
	numErr, ok := err.(*strconv.NumError)
	if !ok || numErr.Err != strconv.ErrRange {
		return 0, false
	}

	u, err := strconv.ParseUint(arg, 0, 64)
	if err != nil {
		return 0, false
	}
	// Only allow values that actually encode a negative int64.
	if u < 1<<63 {
		return 0, false
	}
	return int64(u), true
}

// checkImageRoCompat inspects an ext4 image for any ro_compat features.
func checkImageRoCompat(arg string) bool {
	data := decodeImageData(arg)
	if len(data) == 0 {
		return false
	}

	const (
		superblockOffset = 1024
		roCompatOffset   = 0x64
	)
	offset := superblockOffset + roCompatOffset
	if len(data) < offset+4 {
		return false
	}
	roCompat := binary.LittleEndian.Uint32(data[offset:])
	return roCompat != 0
}

func decodeImageData(arg string) []byte {
	raw := strings.TrimSpace(arg)
	if raw == "" {
		return nil
	}
	if idx := strings.LastIndex(raw, "="); idx >= 0 {
		raw = strings.TrimSpace(raw[idx+1:])
	}

	unquote := func(s string) ([]byte, bool) {
		data, err := strconv.Unquote(s)
		if err != nil {
			return nil, false
		}
		return []byte(data), true
	}

	if data, ok := unquote(raw); ok {
		return data
	}
	if start := strings.Index(raw, "\""); start >= 0 {
		if end := strings.LastIndex(raw, "\""); end > start {
			if data, ok := unquote(raw[start : end+1]); ok {
				return data
			}
		}
	}

	var decoded []byte
	for i := 0; i+3 < len(raw); i++ {
		if raw[i] == '\\' && raw[i+1] == 'x' {
			if b, err := strconv.ParseUint(raw[i+2:i+4], 16, 8); err == nil {
				decoded = append(decoded, byte(b))
				i += 3
			}
		}
	}
	return decoded
}
