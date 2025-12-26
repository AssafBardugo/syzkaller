package main

import (
	"fmt"
	"sort"
	"strings"
	"syscall"

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

		mismatchCalls := vrf.collectErrnoMismatchCalls(
			progLines, baseline.Info, res.Info, baseVer, otherVer, baseVerOK && otherVerOK)

		if len(mismatchCalls) == 0 {
			vrf.callCtr.Add(uint64(len(progCopy.Calls)))
			continue
		}

		vrf.reportErrnoMismatch(progCopy, progLines, baseline, res, i, mismatchCalls)
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

func (vrf *Verifier) collectErrnoMismatchCalls(
	progLines []string, baseline, res *flatrpc.ProgInfo,
	baseVer, otherVer kernelVersion, versionsOK bool) []int {

	callCount := len(baseline.Calls)
	if len(res.Calls) < callCount {
		callCount = len(res.Calls)
	}

	var mismatchCalls []int

	for callIdx := 0; callIdx < callCount; callIdx++ {

		call0 := baseline.Calls[callIdx]
		call1 := res.Calls[callIdx]

		if !comparableCallPair(call0, call1) {
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
		mismatchCalls = append(mismatchCalls, callIdx)
	}
	return mismatchCalls
}

func comparableCallPair(call0, call1 *flatrpc.CallInfo) bool {
	if call0 == nil || call1 == nil {
		return false
	}
	required := flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished
	if call0.Flags&required != required || call1.Flags&required != required {
		return false
	}
	return call0.Flags&flatrpc.CallFlagBlocked == 0 &&
		call1.Flags&flatrpc.CallFlagBlocked == 0
}

func (vrf *Verifier) reportErrnoMismatch(p *prog.Prog, progLines []string, baseline, res *queue.Result,
	kernelIdx int, mismatchCalls []int) {

	log.Logf(0, "")
	log.Logf(0, "========== ERRNO MISMATCH DETECTED ==========")
	log.Logf(0, "Between: Kernel 0 (%s) and Kernel %d (%s)",
		vrf.kernels[0].version, kernelIdx, vrf.kernels[kernelIdx].version)
	log.Logf(0, "Program Counter = %d", vrf.progCtr.Load())
	log.Logf(0, "")
	log.Logf(0, "Complete Program Sequence:")

	mismatchSet := make(map[int]struct{}, len(mismatchCalls))
	for _, idx := range mismatchCalls {
		mismatchSet[idx] = struct{}{}
	}

	for callIdx, call := range p.Calls {
		vrf.callCtr.Add(1)

		prefix := "   "
		if _, ok := mismatchSet[callIdx]; ok {
			prefix = ">>>"
		}

		callStr := call.Meta.CallName + "(...)"
		if callIdx < len(progLines) {
			callStr = progLines[callIdx]
		}
		log.Logf(0, "%s [%d] %s", prefix, vrf.callCtr.Load(), callStr)

		if callIdx < len(baseline.Info.Calls) && callIdx < len(res.Info.Calls) {
			call0 := baseline.Info.Calls[callIdx]
			call1 := res.Info.Calls[callIdx]

			log.Logf(0, "%s Kernel %s: errno = %s, flags = %s",
				prefix, vrf.kernels[0].version, formatErrno(call0.Error), formatCallFlags(call0.Flags))
			log.Logf(0, "%s Kernel %s: errno = %s, flags = %s",
				prefix, vrf.kernels[kernelIdx].version, formatErrno(call1.Error), formatCallFlags(call1.Flags))
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
