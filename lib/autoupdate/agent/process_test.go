/*
 * Teleport
 * Copyright (C) 2024  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWaitForStablePID(t *testing.T) {
	t.Parallel()

	svc := &SystemdService{
		Log: slog.Default(),
	}

	for _, tt := range []struct {
		name       string
		ticks      []int
		baseline   int
		minStable  int
		maxCrashes int
		findErrs   map[int]error

		finalPID int
		errored  bool
		canceled bool
	}{
		{
			name:       "immediate restart",
			ticks:      []int{2, 2},
			baseline:   1,
			minStable:  1,
			maxCrashes: 1,
			finalPID:   2,
		},
		{
			name: "zero stable",
		},
		{
			name:       "immediate crash",
			ticks:      []int{2, 3},
			baseline:   1,
			minStable:  1,
			maxCrashes: 0,
			errored:    true,
			finalPID:   3,
		},
		{
			name:       "no changes times out",
			ticks:      []int{1, 1, 1, 1},
			baseline:   1,
			minStable:  3,
			maxCrashes: 2,
			canceled:   true,
			finalPID:   1,
		},
		{
			name:       "baseline restart",
			ticks:      []int{2, 2, 2, 2},
			baseline:   1,
			minStable:  3,
			maxCrashes: 2,
			finalPID:   2,
		},
		{
			name:       "one restart then stable",
			ticks:      []int{1, 2, 2, 2, 2},
			baseline:   1,
			minStable:  3,
			maxCrashes: 2,
			finalPID:   2,
		},
		{
			name:       "two restarts then stable",
			ticks:      []int{1, 2, 3, 3, 3, 3},
			baseline:   1,
			minStable:  3,
			maxCrashes: 2,
			finalPID:   3,
		},
		{
			name:       "three restarts then stable",
			ticks:      []int{1, 2, 3, 4, 4, 4, 4},
			baseline:   1,
			minStable:  3,
			maxCrashes: 2,
			finalPID:   4,
		},
		{
			name:       "too many restarts excluding baseline",
			ticks:      []int{1, 2, 3, 4, 5},
			baseline:   1,
			minStable:  3,
			maxCrashes: 2,
			errored:    true,
			finalPID:   5,
		},
		{
			name:       "too many restarts including baseline",
			ticks:      []int{1, 2, 3, 4},
			baseline:   0,
			minStable:  3,
			maxCrashes: 2,
			errored:    true,
			finalPID:   4,
		},
		{
			name:       "too many restarts slow",
			ticks:      []int{1, 1, 1, 2, 2, 2, 3, 3, 3, 4},
			baseline:   0,
			minStable:  3,
			maxCrashes: 2,
			errored:    true,
			finalPID:   4,
		},
		{
			name:       "too many restarts after stable",
			ticks:      []int{1, 1, 1, 2, 2, 2, 3, 3, 3, 3, 4},
			baseline:   0,
			minStable:  3,
			maxCrashes: 2,
			finalPID:   3,
		},
		{
			name:       "stable after too many restarts",
			ticks:      []int{1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 4},
			baseline:   0,
			minStable:  3,
			maxCrashes: 2,
			errored:    true,
			finalPID:   4,
		},
		{
			name:       "cancel",
			ticks:      []int{1, 1, 1},
			baseline:   0,
			minStable:  3,
			maxCrashes: 2,
			canceled:   true,
			finalPID:   1,
		},
		{
			name:       "stale PID crash",
			ticks:      []int{2, 2, 2, 2, 2},
			baseline:   1,
			minStable:  3,
			maxCrashes: 2,
			findErrs: map[int]error{
				2: os.ErrProcessDone,
			},
			errored:  true,
			finalPID: 2,
		},
		{
			name:       "stale PID but fixed",
			ticks:      []int{2, 2, 3, 3, 3, 3},
			baseline:   1,
			minStable:  3,
			maxCrashes: 2,
			findErrs: map[int]error{
				2: os.ErrProcessDone,
			},
			finalPID: 3,
		},
		{
			name:       "error PID",
			ticks:      []int{2, 2, 3, 3, 3, 3},
			baseline:   1,
			minStable:  3,
			maxCrashes: 2,
			findErrs: map[int]error{
				2: errors.New("bad"),
			},
			errored:  true,
			finalPID: 2,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			ch := make(chan int)
			go func() {
				defer cancel() // always quit after last tick
				for _, tick := range tt.ticks {
					ch <- tick
				}
			}()
			pid, err := svc.waitForStablePID(ctx, tt.minStable, tt.maxCrashes,
				tt.baseline, ch, func(pid int) error {
					return tt.findErrs[pid]
				})
			require.Equal(t, tt.finalPID, pid)
			require.Equal(t, tt.canceled, errors.Is(err, context.Canceled))
			if !tt.canceled {
				require.Equal(t, tt.errored, err != nil)
			}
		})
	}
}

func TestTickFile(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		ticks   []int
		errored bool
	}{
		{
			name:    "consistent",
			ticks:   []int{1, 1, 1},
			errored: false,
		},
		{
			name:    "divergent",
			ticks:   []int{1, 2, 3},
			errored: false,
		},
		{
			name:    "start error",
			ticks:   []int{-1, 1, 1},
			errored: false,
		},
		{
			name:    "ephemeral error",
			ticks:   []int{1, -1, 1},
			errored: false,
		},
		{
			name:    "end error",
			ticks:   []int{1, 1, -1},
			errored: true,
		},
		{
			name:    "start missing",
			ticks:   []int{0, 1, 1},
			errored: false,
		},
		{
			name:    "ephemeral missing",
			ticks:   []int{1, 0, 1},
			errored: false,
		},
		{
			name:    "end missing",
			ticks:   []int{1, 1, 0},
			errored: false,
		},
		{
			name:    "cancel-only",
			errored: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			filePath := filepath.Join(t.TempDir(), "file")

			ctx := context.Background()
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			tickC := make(chan time.Time)
			ch := make(chan int)

			go func() {
				defer cancel() // always quit after last tick or fail
				for _, tick := range tt.ticks {
					_ = os.RemoveAll(filePath)
					switch {
					case tick > 0:
						err := os.WriteFile(filePath, fmt.Appendln(nil, tick), os.ModePerm)
						require.NoError(t, err)
					case tick < 0:
						err := os.Mkdir(filePath, os.ModePerm)
						require.NoError(t, err)
					}
					tickC <- time.Now()
					res := <-ch
					if tick < 0 {
						tick = 0
					}
					require.Equal(t, tick, res)
				}
			}()
			err := tickFile(ctx, filePath, ch, tickC)
			require.Equal(t, tt.errored, err != nil)
		})
	}
}

func TestParseSystemdVersion(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		output  string
		version int
	}{
		{
			name:    "valid",
			output:  "systemd 249 (249.4-1ubuntu1.1)\n+PAM +AUDIT\n",
			version: 249,
		},
		{
			name:    "short",
			output:  "systemd 249\n",
			version: 249,
		},
		{
			name:    "stripped",
			output:  "systemd 249",
			version: 249,
		},
		{
			name:   "missing",
			output: "systemd",
		},
		{
			name:   "bad",
			output: "not found",
		},
		{
			name: "empty",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v, ok := parseSystemDVersion([]byte(tt.output))
			if tt.version == 0 {
				require.False(t, ok)
			}
			require.Equal(t, tt.version, v)
		})
	}
}
