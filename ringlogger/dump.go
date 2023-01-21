/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package ringlogger

import (
	"errors"
	"fmt"
	"io"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func DumpTo(inPath string, out io.Writer, continuous bool) error {
	fileSize := uint64(unsafe.Sizeof(logMem{}))
	sharedName, err := windows.UTF16PtrFromString(inPath)
	if err != nil {
		return err
	}
	mapping, err := windows.CreateFileMapping(windows.Handle(windows.InvalidHandle), nil, windows.PAGE_READONLY, uint32(fileSize >> 32), uint32(fileSize & 0xffffffff), sharedName)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return err
	}
	rl, err := newRingloggerFromMappingHandle(mapping, "DMP", windows.FILE_MAP_READ)
	if err != nil {
		windows.CloseHandle(mapping)
		return err
	}
	defer rl.Close()
	if !continuous {
		_, err = rl.WriteTo(out)
		if err != nil {
			return err
		}
	} else {
		cursor := CursorAll
		for {
			var items []FollowLine
			items, cursor = rl.FollowFromCursor(cursor)
			for _, item := range items {
				_, err = fmt.Fprintf(out, "%s: %s\n", item.Stamp.Format("2006-01-02 15:04:05.000000"), item.Line)
				if errors.Is(err, io.EOF) {
					return nil
				} else if err != nil {
					return err
				}
			}
			time.Sleep(time.Millisecond * 100)
		}
	}
	return nil
}
