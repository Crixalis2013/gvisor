// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package merkletree

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/usermem"
)

func TestLayout(t *testing.T) {
	testCases := []struct {
		dataSize              int64
		hashAlgorithms        int
		dataAndTreeInSameFile bool
		expectedDigestSize    int64
		expectedLevelOffset   []int64
	}{
		{
			dataSize:              100,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{0},
		},
		{
			dataSize:              100,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{0},
		},
		{
			dataSize:              100,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{usermem.PageSize},
		},
		{
			dataSize:              100,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{usermem.PageSize},
		},
		{
			dataSize:              1000000,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{0, 2 * usermem.PageSize, 3 * usermem.PageSize},
		},
		{
			dataSize:              1000000,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{0, 4 * usermem.PageSize, 5 * usermem.PageSize},
		},
		{
			dataSize:              1000000,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{245 * usermem.PageSize, 247 * usermem.PageSize, 248 * usermem.PageSize},
		},
		{
			dataSize:              1000000,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{245 * usermem.PageSize, 249 * usermem.PageSize, 250 * usermem.PageSize},
		},
		{
			dataSize:              4096 * int64(usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{0, 32 * usermem.PageSize, 33 * usermem.PageSize},
		},
		{
			dataSize:              4096 * int64(usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{0, 64 * usermem.PageSize, 65 * usermem.PageSize},
		},
		{
			dataSize:              4096 * int64(usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{4096 * usermem.PageSize, 4128 * usermem.PageSize, 4129 * usermem.PageSize},
		},
		{
			dataSize:              4096 * int64(usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{4096 * usermem.PageSize, 4160 * usermem.PageSize, 4161 * usermem.PageSize},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d", tc.dataSize), func(t *testing.T) {
			l, err := InitLayout(tc.dataSize, tc.hashAlgorithms, tc.dataAndTreeInSameFile)
			if err != nil {
				t.Fatalf("Failed to InitLayout: %v", err)
			}
			if l.blockSize != int64(usermem.PageSize) {
				t.Errorf("Got blockSize %d, want %d", l.blockSize, usermem.PageSize)
			}
			if l.digestSize != tc.expectedDigestSize {
				t.Errorf("Got digestSize %d, want %d", l.digestSize, sha256DigestSize)
			}
			if l.numLevels() != len(tc.expectedLevelOffset) {
				t.Errorf("Got levels %d, want %d", l.numLevels(), len(tc.expectedLevelOffset))
			}
			for i := 0; i < l.numLevels() && i < len(tc.expectedLevelOffset); i++ {
				if l.levelOffset[i] != tc.expectedLevelOffset[i] {
					t.Errorf("Got levelStart[%d] %d, want %d", i, l.levelOffset[i], tc.expectedLevelOffset[i])
				}
			}
		})
	}
}

const (
	defaultName = "merkle_test"
	defaultMode = 0644
	defaultUID  = 0
	defaultGID  = 0
)

// bytesReadWriter is used to read from/write to/seek in a byte array. Unlike
// bytes.Buffer, it keeps the whole buffer during read so that it can be reused.
type bytesReadWriter struct {
	// bytes contains the underlying byte array.
	bytes []byte
	// readPos is the currently location for Read. Write always appends to
	// the end of the array.
	readPos int
}

func (brw *bytesReadWriter) Write(p []byte) (int, error) {
	brw.bytes = append(brw.bytes, p...)
	return len(p), nil
}

func (brw *bytesReadWriter) Read(p []byte) (int, error) {
	if brw.readPos >= len(brw.bytes) {
		return 0, io.EOF
	}
	bytesRead := copy(p, brw.bytes[brw.readPos:])
	brw.readPos += bytesRead
	if bytesRead < len(p) {
		return bytesRead, io.EOF
	}
	return bytesRead, nil
}

func (brw *bytesReadWriter) Seek(offset int64, whence int) (int64, error) {
	off := offset
	if whence == io.SeekCurrent {
		off += int64(brw.readPos)
	}
	if whence == io.SeekEnd {
		off += int64(len(brw.bytes))
	}
	if off < 0 {
		panic("seek with negative offset")
	}
	if off >= int64(len(brw.bytes)) {
		return 0, io.EOF
	}
	brw.readPos = int(off)
	return off, nil
}

func TestGenerate(t *testing.T) {
	// The input data has size dataSize. It starts with the data in startWith,
	// and all other bytes are zeroes.
	testCases := []struct {
		data           []byte
		hashAlgorithms int
		expectedRoot   []byte
	}{
		{
			data:           bytes.Repeat([]byte{0}, usermem.PageSize),
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA256,
			expectedRoot:   []byte{64, 253, 58, 72, 192, 131, 82, 184, 193, 33, 108, 142, 43, 46, 179, 134, 244, 21, 29, 190, 14, 39, 66, 129, 6, 46, 200, 211, 30, 247, 191, 252},
		},
		{
			data:           bytes.Repeat([]byte{0}, usermem.PageSize),
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA512,
			expectedRoot:   []byte{14, 27, 126, 158, 9, 94, 163, 51, 243, 162, 82, 167, 183, 127, 93, 121, 221, 23, 184, 59, 104, 166, 111, 49, 161, 195, 229, 111, 121, 201, 233, 68, 10, 154, 78, 142, 154, 236, 170, 156, 110, 167, 15, 144, 155, 97, 241, 235, 202, 233, 246, 217, 138, 88, 152, 179, 238, 46, 247, 185, 125, 20, 101, 201},
		},
		{
			data:           bytes.Repeat([]byte{0}, 128*usermem.PageSize+1),
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA256,
			expectedRoot:   []byte{182, 223, 218, 62, 65, 185, 160, 219, 93, 119, 186, 88, 205, 32, 122, 231, 173, 72, 78, 76, 65, 57, 177, 146, 159, 39, 44, 123, 230, 156, 97, 26},
		},
		{
			data:           bytes.Repeat([]byte{0}, 128*usermem.PageSize+1),
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA512,
			expectedRoot:   []byte{55, 204, 240, 1, 224, 252, 58, 131, 251, 174, 45, 140, 107, 57, 118, 11, 18, 236, 203, 204, 19, 59, 27, 196, 3, 78, 21, 7, 22, 98, 197, 128, 17, 128, 90, 122, 54, 83, 253, 108, 156, 67, 59, 229, 236, 241, 69, 88, 99, 44, 127, 109, 204, 183, 150, 232, 187, 57, 228, 137, 209, 235, 241, 172},
		},
		{
			data:           []byte{'a'},
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA256,
			expectedRoot:   []byte{28, 201, 8, 36, 150, 178, 111, 5, 193, 212, 129, 205, 206, 124, 211, 90, 224, 142, 81, 183, 72, 165, 243, 240, 242, 241, 76, 127, 101, 61, 63, 11},
		},
		{
			data:           []byte{'a'},
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA512,
			expectedRoot:   []byte{207, 233, 114, 94, 113, 212, 243, 160, 59, 232, 226, 77, 28, 81, 176, 61, 211, 213, 222, 190, 148, 196, 90, 166, 237, 56, 113, 148, 230, 154, 23, 105, 14, 97, 144, 211, 12, 122, 226, 207, 167, 203, 136, 193, 38, 249, 227, 187, 92, 238, 101, 97, 170, 255, 246, 209, 246, 98, 241, 150, 175, 253, 173, 206},
		},
		{
			data:           bytes.Repeat([]byte{'a'}, usermem.PageSize),
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA256,
			expectedRoot:   []byte{106, 58, 160, 152, 41, 68, 38, 108, 245, 74, 177, 84, 64, 193, 19, 176, 249, 86, 27, 193, 85, 164, 99, 240, 79, 104, 148, 222, 76, 46, 191, 79},
		},
		{
			data:           bytes.Repeat([]byte{'a'}, usermem.PageSize),
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA512,
			expectedRoot:   []byte{110, 103, 29, 250, 27, 211, 235, 119, 112, 65, 49, 156, 6, 92, 66, 105, 133, 1, 187, 172, 169, 13, 186, 34, 105, 72, 252, 131, 12, 159, 91, 188, 79, 184, 240, 227, 40, 164, 72, 193, 65, 31, 227, 153, 191, 6, 117, 42, 82, 122, 33, 255, 92, 215, 215, 249, 2, 131, 170, 134, 39, 192, 222, 33},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d:%v", len(tc.data), tc.data[0]), func(t *testing.T) {
			for _, dataAndTreeInSameFile := range []bool{false, true} {
				var tree bytesReadWriter
				params := GenerateParams{
					Size:                  int64(len(tc.data)),
					Name:                  defaultName,
					Mode:                  defaultMode,
					UID:                   defaultUID,
					GID:                   defaultGID,
					HashAlgorithms:        tc.hashAlgorithms,
					TreeReader:            &tree,
					TreeWriter:            &tree,
					DataAndTreeInSameFile: dataAndTreeInSameFile,
				}
				if dataAndTreeInSameFile {
					tree.Write(tc.data)
					params.File = &tree
				} else {
					params.File = &bytesReadWriter{
						bytes: tc.data,
					}
				}
				root, err := Generate(&params)
				if err != nil {
					t.Fatalf("Got err: %v, want nil", err)
				}

				if !bytes.Equal(root, tc.expectedRoot) {
					t.Errorf("Got root: %v, want %v", root, tc.expectedRoot)
				}
			}
		})
	}
}

func TestVerify(t *testing.T) {
	// The input data has size dataSize. The portion to be verified ranges from
	// verifyStart with verifySize. A bit is flipped in outOfRangeByteIndex to
	// confirm that modifications outside the verification range does not cause
	// issue. And a bit is flipped in modifyByte to confirm that
	// modifications in the verification range is caught during verification.
	testCases := []struct {
		dataSize    int64
		verifyStart int64
		verifySize  int64
		// A byte in input data is modified during the test. If the
		// modified byte falls in verification range, Verify should
		// fail, otherwise Verify should still succeed.
		modifyByte    int64
		modifyName    bool
		modifyMode    bool
		modifyUID     bool
		modifyGID     bool
		shouldSucceed bool
	}{
		// Verify range start outside the data range should fail.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   usermem.PageSize,
			verifySize:    1,
			modifyByte:    0,
			shouldSucceed: false,
		},
		// Verifying range is valid if it starts inside data and ends
		// outside data range, in that case start to the end of data is
		// verified.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   0,
			verifySize:    2 * usermem.PageSize,
			modifyByte:    0,
			shouldSucceed: false,
		},
		// Invalid verify range (negative size) should fail.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   1,
			verifySize:    -1,
			modifyByte:    0,
			shouldSucceed: false,
		},
		// 0 verify size should only verify metadata.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   0,
			verifySize:    0,
			modifyByte:    0,
			shouldSucceed: true,
		},
		// Modified name should fail verification.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   0,
			verifySize:    0,
			modifyByte:    0,
			modifyName:    true,
			shouldSucceed: false,
		},
		// Modified mode should fail verification.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   0,
			verifySize:    0,
			modifyByte:    0,
			modifyMode:    true,
			shouldSucceed: false,
		},
		// Modified UID should fail verification.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   0,
			verifySize:    0,
			modifyByte:    0,
			modifyUID:     true,
			shouldSucceed: false,
		},
		// Modified GID should fail verification.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   0,
			verifySize:    0,
			modifyByte:    0,
			modifyGID:     true,
			shouldSucceed: false,
		},
		// The test cases below use a block-aligned verify range.
		// Modifying a byte in the verified range should cause verify
		// to fail.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4 * usermem.PageSize,
			verifySize:    usermem.PageSize,
			modifyByte:    4 * usermem.PageSize,
			shouldSucceed: false,
		},
		// Modifying a byte before the verified range should not cause
		// verify to fail.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4 * usermem.PageSize,
			verifySize:    usermem.PageSize,
			modifyByte:    4*usermem.PageSize - 1,
			shouldSucceed: true,
		},
		// Modifying a byte after the verified range should not cause
		// verify to fail.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4 * usermem.PageSize,
			verifySize:    usermem.PageSize,
			modifyByte:    5 * usermem.PageSize,
			shouldSucceed: true,
		},
		// The tests below use a non-block-aligned verify range.
		// Modifying a byte at strat of verify range should cause
		// verify to fail.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4*usermem.PageSize + 123,
			verifySize:    2 * usermem.PageSize,
			modifyByte:    4*usermem.PageSize + 123,
			shouldSucceed: false,
		},
		// Modifying a byte at the end of verify range should cause
		// verify to fail.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4*usermem.PageSize + 123,
			verifySize:    2 * usermem.PageSize,
			modifyByte:    6*usermem.PageSize + 123,
			shouldSucceed: false,
		},
		// Modifying a byte in the middle verified block should cause
		// verify to fail.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4*usermem.PageSize + 123,
			verifySize:    2 * usermem.PageSize,
			modifyByte:    5*usermem.PageSize + 123,
			shouldSucceed: false,
		},
		// Modifying a byte in the first block in the verified range
		// should cause verify to fail, even the modified bit itself is
		// out of verify range.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4*usermem.PageSize + 123,
			verifySize:    2 * usermem.PageSize,
			modifyByte:    4*usermem.PageSize + 122,
			shouldSucceed: false,
		},
		// Modifying a byte in the last block in the verified range
		// should cause verify to fail, even the modified bit itself is
		// out of verify range.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4*usermem.PageSize + 123,
			verifySize:    2 * usermem.PageSize,
			modifyByte:    6*usermem.PageSize + 124,
			shouldSucceed: false,
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d", tc.modifyByte), func(t *testing.T) {
			data := make([]byte, tc.dataSize)
			// Generate random bytes in data.
			rand.Read(data)

			for _, hashAlgorithms := range []int{linux.FS_VERITY_HASH_ALG_SHA256, linux.FS_VERITY_HASH_ALG_SHA512} {
				for _, dataAndTreeInSameFile := range []bool{false, true} {
					var tree bytesReadWriter
					genParams := GenerateParams{
						Size:                  int64(len(data)),
						Name:                  defaultName,
						Mode:                  defaultMode,
						UID:                   defaultUID,
						GID:                   defaultGID,
						HashAlgorithms:        hashAlgorithms,
						TreeReader:            &tree,
						TreeWriter:            &tree,
						DataAndTreeInSameFile: dataAndTreeInSameFile,
					}
					if dataAndTreeInSameFile {
						tree.Write(data)
						genParams.File = &tree
					} else {
						genParams.File = &bytesReadWriter{
							bytes: data,
						}
					}
					root, err := Generate(&genParams)
					if err != nil {
						t.Fatalf("Generate failed: %v", err)
					}

					// Flip a bit in data and checks Verify results.
					var buf bytes.Buffer
					data[tc.modifyByte] ^= 1
					verifyParams := VerifyParams{
						Out:                   &buf,
						File:                  bytes.NewReader(data),
						Tree:                  &tree,
						Size:                  tc.dataSize,
						Name:                  defaultName,
						Mode:                  defaultMode,
						UID:                   defaultUID,
						GID:                   defaultGID,
						HashAlgorithms:        hashAlgorithms,
						ReadOffset:            tc.verifyStart,
						ReadSize:              tc.verifySize,
						ExpectedRoot:          root,
						DataAndTreeInSameFile: dataAndTreeInSameFile,
					}
					if tc.modifyName {
						verifyParams.Name = defaultName + "abc"
					}
					if tc.modifyMode {
						verifyParams.Mode = defaultMode + 1
					}
					if tc.modifyUID {
						verifyParams.UID = defaultUID + 1
					}
					if tc.modifyGID {
						verifyParams.GID = defaultGID + 1
					}
					if tc.shouldSucceed {
						n, err := Verify(&verifyParams)
						if err != nil && err != io.EOF {
							t.Errorf("Verification failed when expected to succeed: %v", err)
						}
						if n != tc.verifySize {
							t.Errorf("Got Verify output size %d, want %d", n, tc.verifySize)
						}
						if int64(buf.Len()) != tc.verifySize {
							t.Errorf("Got Verify output buf size %d, want %d,", buf.Len(), tc.verifySize)
						}
						if !bytes.Equal(data[tc.verifyStart:tc.verifyStart+tc.verifySize], buf.Bytes()) {
							t.Errorf("Incorrect output buf from Verify")
						}
					} else {
						if _, err := Verify(&verifyParams); err == nil {
							t.Errorf("Verification succeeded when expected to fail")
						}
					}
				}
			}
		})
	}
}

func TestVerifyRandom(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	// Use a random dataSize.  Minimum size 2 so that we can pick a random
	// portion from it.
	dataSize := rand.Int63n(200*usermem.PageSize) + 2
	data := make([]byte, dataSize)
	// Generate random bytes in data.
	rand.Read(data)

	for _, hashAlgorithms := range []int{linux.FS_VERITY_HASH_ALG_SHA256, linux.FS_VERITY_HASH_ALG_SHA512} {
		for _, dataAndTreeInSameFile := range []bool{false, true} {
			var tree bytesReadWriter
			genParams := GenerateParams{
				Size:                  int64(len(data)),
				Name:                  defaultName,
				Mode:                  defaultMode,
				UID:                   defaultUID,
				GID:                   defaultGID,
				HashAlgorithms:        hashAlgorithms,
				TreeReader:            &tree,
				TreeWriter:            &tree,
				DataAndTreeInSameFile: dataAndTreeInSameFile,
			}

			if dataAndTreeInSameFile {
				tree.Write(data)
				genParams.File = &tree
			} else {
				genParams.File = &bytesReadWriter{
					bytes: data,
				}
			}
			root, err := Generate(&genParams)
			if err != nil {
				t.Fatalf("Generate failed: %v", err)
			}

			// Pick a random portion of data.
			start := rand.Int63n(dataSize - 1)
			size := rand.Int63n(dataSize) + 1

			var buf bytes.Buffer
			verifyParams := VerifyParams{
				Out:                   &buf,
				File:                  bytes.NewReader(data),
				Tree:                  &tree,
				Size:                  dataSize,
				Name:                  defaultName,
				Mode:                  defaultMode,
				UID:                   defaultUID,
				GID:                   defaultGID,
				HashAlgorithms:        hashAlgorithms,
				ReadOffset:            start,
				ReadSize:              size,
				ExpectedRoot:          root,
				DataAndTreeInSameFile: dataAndTreeInSameFile,
			}

			// Checks that the random portion of data from the original data is
			// verified successfully.
			n, err := Verify(&verifyParams)
			if err != nil && err != io.EOF {
				t.Errorf("Verification failed for correct data: %v", err)
			}
			if size > dataSize-start {
				size = dataSize - start
			}
			if n != size {
				t.Errorf("Got Verify output size %d, want %d", n, size)
			}
			if int64(buf.Len()) != size {
				t.Errorf("Got Verify output buf size %d, want %d", buf.Len(), size)
			}
			if !bytes.Equal(data[start:start+size], buf.Bytes()) {
				t.Errorf("Incorrect output buf from Verify")
			}

			// Verify that modified metadata should fail verification.
			buf.Reset()
			verifyParams.Name = defaultName + "abc"
			if _, err := Verify(&verifyParams); err == nil {
				t.Error("Verify succeeded for modified metadata, expect failure")
			}

			// Flip a random bit in randPortion, and check that verification fails.
			buf.Reset()
			randBytePos := rand.Int63n(size)
			data[start+randBytePos] ^= 1
			verifyParams.File = bytes.NewReader(data)
			verifyParams.Name = defaultName

			if _, err := Verify(&verifyParams); err == nil {
				t.Error("Verification succeeded for modified data, expect failure")
			}
		}
	}
}
