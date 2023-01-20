/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package ringlogger

import (
	"bytes"
	"io"
	"os"
	"runtime"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	maxLogLineLength = 512
	maxTagLength     = 5
	maxLines         = 2048
	magic            = 0xbadbabe
)

type logLine struct {
	timeNs int64
	line   [maxLogLineLength]byte
}

type logMem struct {
	magic     uint32
	nextIndex uint32
	lines     [maxLines]logLine
}

type Ringlogger struct {
	tag      string
	file     *os.File
	mapping  windows.Handle
	log      *logMem
	readOnly bool
}

func NewRinglogger(filename, tag string) (*Ringlogger, error) {
	if len(tag) > maxTagLength {
		return nil, windows.ERROR_LABEL_TOO_LONG
	}
	rl, err := newRingloggerFromMappingHandle(windows.Handle(uintptr(0)), tag, windows.FILE_MAP_WRITE)
	if err != nil {
		return nil, err
	}
	return rl, nil
}

func NewRingloggerFromInheritedMappingHandle(handleStr, tag string) (*Ringlogger, error) {
	handle, err := strconv.ParseUint(handleStr, 10, 64)
	if err != nil {
		return nil, err
	}
	return newRingloggerFromMappingHandle(windows.Handle(handle), tag, windows.FILE_MAP_READ)
}

func newRingloggerFromMappingHandle(mappingHandle windows.Handle, tag string, access uint32) (*Ringlogger, error) {
	rl := &Ringlogger{
		tag:      tag,
		readOnly: access&windows.FILE_MAP_WRITE == 0,
	}
	runtime.SetFinalizer(rl, (*Ringlogger).Close)
	return rl, nil
}

func (rl *Ringlogger) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (rl *Ringlogger) WriteWithTimestamp(p []byte, ts int64) (n int, err error) {
	return len(p), nil
}

func (rl *Ringlogger) WriteTo(out io.Writer) (n int64, err error) {
	return 0, nil
}

const CursorAll = ^uint32(0)

type FollowLine struct {
	Line  string
	Stamp time.Time
}

func (rl *Ringlogger) FollowFromCursor(cursor uint32) (followLines []FollowLine, nextCursor uint32) {
	followLines = make([]FollowLine, 0, maxLines)
	nextCursor = cursor

	if rl.log == nil {
		return
	}
	log := *rl.log

	i := cursor
	if cursor == CursorAll {
		i = log.nextIndex
	}

	for l := 0; l < maxLines; l++ {
		line := &log.lines[i%maxLines]
		if cursor != CursorAll && i%maxLines == log.nextIndex%maxLines {
			break
		}
		if line.timeNs == 0 {
			if cursor == CursorAll {
				i++
				continue
			} else {
				break
			}
		}
		index := bytes.IndexByte(line.line[:], 0)
		if index > 0 {
			followLines = append(followLines, FollowLine{string(line.line[:index]), time.Unix(0, line.timeNs)})
		}
		i++
		nextCursor = i % maxLines
	}
	return
}

func (rl *Ringlogger) Close() error {
	if rl.file != nil {
		rl.file.Close()
		rl.file = nil
	}
	if rl.log != nil {
		windows.UnmapViewOfFile((uintptr)(unsafe.Pointer(rl.log)))
		rl.log = nil
	}
	if rl.mapping != 0 {
		windows.CloseHandle(rl.mapping)
		rl.mapping = 0
	}
	return nil
}

func (rl *Ringlogger) ExportInheritableMappingHandle() (handleToClose windows.Handle, err error) {
	return windows.Handle(uintptr(0)), nil
}
