package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"golang.org/x/sys/unix"
)

func (vrf *Verifier) handleErrnoMismatches(req *queue.Request, responses map[int]*queue.Result) {

	baseline := responses[0]
	progCopy, progLines := safeProgSnapshot(req.Prog)
	if progCopy == nil || len(progLines) == 0 {
		// Nothing to compare; avoid crashing the verifier on serialization issues.
		return
	}

	baseVer := vrf.kernels[0].verParsed
	baseVerOK := vrf.kernels[0].verOK

	var kernelIDs []int
	for id := range responses {
		if id == 0 {
			continue
		}
		kernelIDs = append(kernelIDs, id)
	}
	sort.Ints(kernelIDs)

	for _, i := range kernelIDs {

		res := responses[i]

		if !shouldCompareResults(baseline, res) {
			continue
		}
		vrf.progCtr.Add(1)

		otherVer := vrf.kernels[i].verParsed
		otherVerOK := vrf.kernels[i].verOK
		versionsOK := baseVerOK && otherVerOK
		mismatchSet := findErrnoMismatchCalls(progLines, baseline.Info, res.Info, baseVer, otherVer, versionsOK)
		if len(mismatchSet) == 0 {
			vrf.callCtr.Add(uint64(len(progCopy.Calls)))
			continue
		}

		progCtr := vrf.progCtr.Load()
		callData := vrf.buildMismatchCallData(progCopy, progLines, baseline, res, mismatchSet)
		for _, data := range callData {
			if data.IsMismatch && data.HasResults {
				writeMismatchJSON(progCtr, data.CallCtr, data.CallName, data.CallLine, data.Args,
					baseVer, data.Call0Err, otherVer, data.Call1Err)
			}
		}
		vrf.reportErrnoMismatch(baseline, res, i, progCtr, callData)
	}
}

// safeProgSnapshot clones the program and serializes it to lines, recovering from panics.
func safeProgSnapshot(p *prog.Prog) (*prog.Prog, []string) {
	clone := func() (ret *prog.Prog) {
		defer func() {
			if r := recover(); r != nil {
				log.Logf(0, "failed to clone program for mismatch logging: %v", r)
			}
		}()
		return p.Clone()
	}()
	if clone == nil {
		return nil, nil
	}
	lines := func() (ret []string) {
		defer func() {
			if r := recover(); r != nil {
				log.Logf(0, "failed to serialize program for mismatch logging: %v", r)
				ret = nil
			}
		}()
		data := clone.Serialize()
		if len(data) == 0 {
			return nil
		}
		return strings.Split(strings.TrimSpace(string(data)), "\n")
	}()
	return clone, lines
}

func shouldCompareResults(baseline, res *queue.Result) bool {

	if baseline == nil || res == nil || baseline.Info == nil || res.Info == nil {
		return false
	}
	return baseline.Status == queue.Success && res.Status == queue.Success
}

func findErrnoMismatchCalls(progLines []string, baseline, res *flatrpc.ProgInfo,
	baseVer, otherVer kernelVersion, versionsOK bool) map[int]struct{} {

	if baseline == nil || res == nil {
		return nil
	}

	callCount := len(baseline.Calls)
	if len(res.Calls) < callCount {
		callCount = len(res.Calls)
	}

	var mismatchSet map[int]struct{}
	for callIdx := 0; callIdx < callCount; callIdx++ {
		call0 := baseline.Calls[callIdx]
		call1 := res.Calls[callIdx]

		if call0 == nil || call1 == nil {
			continue
		}
		required := flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished
		if call0.Flags&required != required || call1.Flags&required != required {
			continue
		}
		if call0.Flags&flatrpc.CallFlagBlocked != 0 || call1.Flags&flatrpc.CallFlagBlocked != 0 {
			continue
		}
		if call0.Error == call1.Error {
			continue
		}

		callLine := ""
		if callIdx < len(progLines) {
			callLine = progLines[callIdx]
		}
		if shouldIgnoreMismatch(callLine, call0.Error, call1.Error, baseVer, otherVer, versionsOK) {
			continue
		}

		if mismatchSet == nil {
			mismatchSet = make(map[int]struct{})
		}
		mismatchSet[callIdx] = struct{}{}
	}
	return mismatchSet
}

type mismatchCallData struct {
	CallIdx    int
	CallCtr    uint64
	CallLine   string
	CallName   string
	Args       []string
	HasResults bool
	Call0Err   int32
	Call1Err   int32
	Call0Flags flatrpc.CallFlag
	Call1Flags flatrpc.CallFlag
	IsMismatch bool
}

func (vrf *Verifier) buildMismatchCallData(p *prog.Prog, progLines []string, baseline, res *queue.Result,
	mismatchSet map[int]struct{}) []mismatchCallData {

	hasResults := baseline != nil && res != nil && baseline.Info != nil && res.Info != nil
	data := make([]mismatchCallData, 0, len(p.Calls))

	for callIdx, call := range p.Calls {
		vrf.callCtr.Add(1)
		callCtr := vrf.callCtr.Load()

		compareLine := ""
		hasCallLine := callIdx < len(progLines)
		if hasCallLine {
			compareLine = progLines[callIdx]
		}
		callLine := compareLine
		if callLine == "" {
			callLine = call.Meta.CallName + "(...)"
		}

		callName := extractCallName(callLine)
		args := []string{}
		if hasCallLine {
			// TODO: agent should not rely on argument position semantics beyond what verifier guarantees.
			args = extractCallArgs(callLine)
			if args == nil {
				args = []string{}
			}
		}

		entry := mismatchCallData{
			CallIdx:  callIdx,
			CallCtr:  callCtr,
			CallLine: callLine,
			CallName: callName,
			Args:     args,
		}
		if hasResults && callIdx < len(baseline.Info.Calls) && callIdx < len(res.Info.Calls) {
			call0 := baseline.Info.Calls[callIdx]
			call1 := res.Info.Calls[callIdx]
			entry.HasResults = true
			entry.Call0Err = call0.Error
			entry.Call1Err = call1.Error
			entry.Call0Flags = call0.Flags
			entry.Call1Flags = call1.Flags
			if _, ok := mismatchSet[callIdx]; ok {
				entry.IsMismatch = true
			}
		}
		data = append(data, entry)
	}
	return data
}

func (vrf *Verifier) reportErrnoMismatch(baseline, res *queue.Result,
	kernelIdx int, progCtr uint64, callData []mismatchCallData) {

	log.Logf(0, "")
	log.Logf(0, "========== ERRNO MISMATCH DETECTED ==========")
	log.Logf(0, "Between: Kernel 0 (%s) and Kernel %d (%s)",
		vrf.kernels[0].version, kernelIdx, vrf.kernels[kernelIdx].version)
	log.Logf(0, "Program Counter = %d", progCtr)
	log.Logf(0, "")
	log.Logf(0, "Complete Program Sequence:")

	for _, entry := range callData {
		prefix := "   "
		if entry.IsMismatch {
			prefix = ">>>"
		}

		log.Logf(0, "%s [%d] %s", prefix, entry.CallCtr, entry.CallLine)

		if entry.HasResults {
			log.Logf(0, "%s Kernel %s: errno = %s, flags = %s",
				prefix, vrf.kernels[0].version, formatErrno(entry.Call0Err), formatCallFlags(entry.Call0Flags))
			log.Logf(0, "%s Kernel %s: errno = %s, flags = %s",
				prefix, vrf.kernels[kernelIdx].version, formatErrno(entry.Call1Err), formatCallFlags(entry.Call1Flags))
		}
		log.Logf(0, "")
	}

	if len(baseline.Output) > 0 || len(res.Output) > 0 {
		log.Logf(0, "Kernel Outputs:")
		log.Logf(0, "  %s: %q", vrf.kernels[0].version, baseline.Output)
		log.Logf(0, "  %s: %q", vrf.kernels[kernelIdx].version, res.Output)
	}
	if baseline.Err != nil || res.Err != nil {
		log.Logf(0, "Execution Errors:")
		log.Logf(0, "  %s: %v", vrf.kernels[0].version, baseline.Err)
		log.Logf(0, "  %s: %v", vrf.kernels[kernelIdx].version, res.Err)
	}
	log.Logf(0, "=============================================")
	log.Logf(0, "")
}

func formatErrno(errno int32) string {
	if name := unix.ErrnoName(syscall.Errno(errno)); name != "" {
		return fmt.Sprintf("%d (%s)", errno, name)
	}
	return fmt.Sprintf("%d", errno)
}

func formatCallFlags(flags flatrpc.CallFlag) string {
	if name := flatrpc.EnumNamesCallFlag[flags]; name != "" {
		return name
	}

	var parts []string
	for flag, name := range flatrpc.EnumNamesCallFlag {
		if flag == 0 || flag&(flag-1) != 0 {
			// Skip combined/multi-bit entries to avoid duplicating them alongside individual flags.
			continue
		}
		if flags&flag != 0 {
			parts = append(parts, name)
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%d", flags)
	}
	sort.Strings(parts)
	return strings.Join(parts, " | ")
}

type mismatchKernel struct {
	Version string `json:"version"`
	Errno   string `json:"errno"`
}

type mismatchJSON struct {
	CreatedAt string         `json:"created_at"`
	ProgIndex uint64         `json:"prog_index"`
	CallIndex uint64         `json:"call_index"`
	CallName  string         `json:"call_name"`
	CallLine  string         `json:"call_line"`
	Args      []string       `json:"args"`
	Kernel0   mismatchKernel `json:"kernel0"`
	Kernel1   mismatchKernel `json:"kernel1"`
}

func formatKernelVersion(ver kernelVersion) string {
	return fmt.Sprintf("%d.%d.%d", ver.major, ver.minor, ver.patch)
}

func writeMismatchJSON(progCtr, callCtr uint64, callName, callLine string, args []string,
	baseVer kernelVersion, call0Err int32, otherVer kernelVersion, call1Err int32) {

	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	payload := mismatchJSON{
		CreatedAt: timestamp,
		ProgIndex: progCtr,
		CallIndex: callCtr,
		CallName:  callName,
		CallLine:  callLine,
		Args:      args,
		Kernel0: mismatchKernel{
			Version: formatKernelVersion(baseVer),
			Errno:   fmt.Sprintf("%d", call0Err),
		},
		Kernel1: mismatchKernel{
			Version: formatKernelVersion(otherVer),
			Errno:   fmt.Sprintf("%d", call1Err),
		},
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		log.Logf(0, "failed to marshal mismatch json: %v", err)
		return
	}
	data = append(data, '\n')

	dir := filepath.Join("agent", "queue", "new")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Logf(0, "failed to create mismatch json dir: %v", err)
		return
	}
	path := filepath.Join(dir, timestamp+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Logf(0, "failed to write mismatch json: %v", err)
	}
}
