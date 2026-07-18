// SPDX-License-Identifier: MIT

//go:build windows

package main

import (
	"fmt"
	"io"

	"github.com/sungurerdim/dizgin/internal/diagnostic/wct"
)

// diagnoseHangImpl probes pid via WCT and writes a one-thread-per-line
// summary to w. Threads with empty wait chains are omitted from the
// detailed listing but counted in the header.
func diagnoseHangImpl(pid uint32, w io.Writer) error {
	chains, err := wct.DiagnoseHang(pid)
	if err != nil {
		return fmt.Errorf("diagnose-hang: %w", err)
	}
	if len(chains) == 0 {
		fmt.Fprintf(w, "pid=%d: no threads found (already exited?)\n", pid)
		return nil
	}
	withNodes := 0
	for _, c := range chains {
		if len(c.Nodes) > 0 {
			withNodes++
		}
	}
	fmt.Fprintf(w, "pid=%d: %d thread(s) sampled, %d with non-empty wait chains\n",
		pid, len(chains), withNodes)
	for _, c := range chains {
		if len(c.Nodes) == 0 {
			continue
		}
		fmt.Fprintln(w, wct.FormatThreadChain(c))
	}
	return nil
}
