package xhttp

import (
	"strconv"
	"sync/atomic"
)

// InHive instrumentation (build 129, TEMPORARY — remove once the write-scratch cap
// is finalized). Histogram of xhttp write-chunk sizes = the payload of each
// splitConn.Write, i.e. the TRUE per-chunk size fed into the h2 upload stream BEFORE
// x/net's frameScratchBufferLen cap (forked 512KB→64KB for the iOS NE jetsam fix).
// Purpose: pick the buffer size from real device data instead of a static guess —
// if chunks cluster ≤16-32KB we can drop the cap further; if they push >64KB we hold
// or raise. Read out by the mem sampler into the device diag mem.log. Lock-free
// atomics; cost per proxied Write = one switch + one atomic Add (+ a rare CAS for max).
var (
	wrChunkLE8K  atomic.Int64 // ≤ 8 KiB
	wrChunkLE16K atomic.Int64 // ≤ 16 KiB
	wrChunkLE32K atomic.Int64 // ≤ 32 KiB
	wrChunkLE64K atomic.Int64 // ≤ 64 KiB
	wrChunkGT64K atomic.Int64 // > 64 KiB — would split across multiple 64KB frames
	wrChunkMax   atomic.Int64 // largest single Write seen (bytes)
)

func recordWriteChunk(n int) {
	switch {
	case n <= 8<<10:
		wrChunkLE8K.Add(1)
	case n <= 16<<10:
		wrChunkLE16K.Add(1)
	case n <= 32<<10:
		wrChunkLE32K.Add(1)
	case n <= 64<<10:
		wrChunkLE64K.Add(1)
	default:
		wrChunkGT64K.Add(1)
	}
	for {
		cur := wrChunkMax.Load()
		if int64(n) <= cur || wrChunkMax.CompareAndSwap(cur, int64(n)) {
			break
		}
	}
}

// ChunkSizeHistogram returns a compact one-line summary for the diag log.
func ChunkSizeHistogram() string {
	return "xhttp_wr[<=8K=" + strconv.FormatInt(wrChunkLE8K.Load(), 10) +
		" <=16K=" + strconv.FormatInt(wrChunkLE16K.Load(), 10) +
		" <=32K=" + strconv.FormatInt(wrChunkLE32K.Load(), 10) +
		" <=64K=" + strconv.FormatInt(wrChunkLE64K.Load(), 10) +
		" >64K=" + strconv.FormatInt(wrChunkGT64K.Load(), 10) +
		" maxK=" + strconv.FormatInt(wrChunkMax.Load()/1024, 10) + "]"
}
