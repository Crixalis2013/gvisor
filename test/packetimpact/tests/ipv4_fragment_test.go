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

package ipv4_fragment_test

import (
	"bytes"
	"encoding/hex"
	"flag"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.RegisterFlags(flag.CommandLine)
}

func TestIPv4Fragment(t *testing.T) {
	const (
		data       = "IPV4_PROTOCOL_TESTER_FOR_FRAGMENT"
		fragmentID = 1
	)

	type reply uint8

	const (
		icmpEchoReply reply = iota
		icmpError
		noReply
	)

	type errorDetail struct {
		typ             header.ICMPv4Type
		code            header.ICMPv4Code
		payloadFragment int
	}

	tests := []struct {
		name                 string
		firstPayloadLength   uint16
		payload              []byte
		secondFragmentOffset uint16
		sendFrameOrder       []int
		expectFrameTimeout   time.Duration
		expectReply          reply
		expectErrorDetail    errorDetail
	}{
		{
			name:                 "reassemble two fragments",
			firstPayloadLength:   8,
			payload:              []byte(data)[:20],
			secondFragmentOffset: header.ICMPv4PayloadOffset + 8,
			sendFrameOrder:       []int{1, 2},
			expectFrameTimeout:   time.Second,
			expectReply:          icmpEchoReply,
		},
		{
			name:               "reassembly timeout (first fragment only)",
			firstPayloadLength: 8,
			payload:            []byte(data)[:20],
			sendFrameOrder:     []int{1},
			expectFrameTimeout: 40 * time.Second,
			expectReply:        icmpError,
			expectErrorDetail: errorDetail{
				typ:             header.ICMPv4TimeExceeded,
				code:            header.ICMPv4ReassemblyTimeout,
				payloadFragment: 1,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dut := testbench.NewDUT(t)
			defer dut.TearDown()
			ipv4Conn := testbench.NewIPv4Conn(t, testbench.IPv4{}, testbench.IPv4{})
			conn := (*testbench.Connection)(&ipv4Conn)
			defer ipv4Conn.Close(t)

			icmpv4Header := header.ICMPv4(make([]byte, header.ICMPv4MinimumSize))
			icmpv4Header.SetType(header.ICMPv4Echo)
			icmpv4Header.SetCode(header.ICMPv4UnusedCode)
			icmpv4Header.SetIdent(0)
			icmpv4Header.SetSequence(0)
			cksum := header.ICMPv4Checksum(
				icmpv4Header,
				buffer.NewVectorisedView(len(test.payload), []buffer.View{test.payload}),
			)
			icmpv4Header.SetChecksum(cksum)
			icmpv4Bytes := append([]byte(icmpv4Header), test.payload...)

			firstFragment := conn.CreateFrame(t,
				testbench.Layers{
					&testbench.IPv4{
						ID:             testbench.Uint16(fragmentID),
						Flags:          testbench.Uint8(header.IPv4FlagMoreFragments),
						FragmentOffset: testbench.Uint16(0),
						Protocol:       testbench.Uint8(uint8(header.ICMPv4ProtocolNumber)),
					},
				},
				&testbench.Payload{
					Bytes: icmpv4Bytes[:header.ICMPv4PayloadOffset+test.firstPayloadLength],
				},
			)
			firstIPv4 := firstFragment[1:]
			firstIPv4Bytes, err := firstIPv4.ToBytes()
			if err != nil {
				t.Fatalf("can't convert first %s to bytes: %s", firstIPv4, err)
			}

			secondFragment := conn.CreateFrame(t,
				testbench.Layers{
					&testbench.IPv4{
						ID:             testbench.Uint16(fragmentID),
						Flags:          testbench.Uint8(0),
						FragmentOffset: testbench.Uint16(test.secondFragmentOffset),
						Protocol:       testbench.Uint8(uint8(header.ICMPv4ProtocolNumber)),
					},
				},
				&testbench.Payload{
					Bytes: icmpv4Bytes[header.ICMPv4PayloadOffset+test.firstPayloadLength:],
				},
			)
			secondIPv4 := secondFragment[1:]
			secondIPv4Bytes, err := secondIPv4.ToBytes()
			if err != nil {
				t.Fatalf("can't convert %s to bytes: %s", secondIPv4, err)
			}

			fragments := []testbench.Layers{firstFragment, secondFragment}
			ipv4Bytes := [][]byte{firstIPv4Bytes, secondIPv4Bytes}

			for _, i := range test.sendFrameOrder {
				conn.SendFrame(t, fragments[i-1])
			}

			switch test.expectReply {
			case icmpEchoReply:
				gotEchoReply, err := ipv4Conn.ExpectFrame(t, testbench.Layers{
					&testbench.Ether{},
					&testbench.IPv4{},
					&testbench.ICMPv4{
						Type: testbench.ICMPv4Type(header.ICMPv4EchoReply),
						Code: testbench.ICMPv4Code(header.ICMPv4UnusedCode),
					},
				}, test.expectFrameTimeout)
				if err != nil {
					t.Fatalf("expected an ICMPv4 Echo Reply, but got none: %s", err)
				}
				gotPayload, err := gotEchoReply[len(gotEchoReply)-1].ToBytes()
				if err != nil {
					t.Fatalf("failed to convert ICMPv4 to bytes: %s", err)
				}
				icmpPayload := gotPayload
				wantPayload := test.payload
				if !bytes.Equal(icmpPayload, wantPayload) {
					t.Fatalf("received unexpected payload, got: %s, want: %s",
						hex.Dump(icmpPayload),
						hex.Dump(wantPayload))
				}
			case icmpError:
				gotErrorMessage, err := ipv4Conn.ExpectFrame(t, testbench.Layers{
					&testbench.Ether{},
					&testbench.IPv4{},
					&testbench.ICMPv4{
						Type: testbench.ICMPv4Type(test.expectErrorDetail.typ),
						Code: testbench.ICMPv4Code(test.expectErrorDetail.code),
					},
				}, test.expectFrameTimeout)
				if err != nil {
					t.Fatalf("expected an ICMPv4 Error Message, but got none: %s", err)
				}
				gotPayload, err := gotErrorMessage[len(gotErrorMessage)-1].ToBytes()
				if err != nil {
					t.Fatalf("failed to convert ICMPv4 to bytes: %s", err)
				}
				wantPayload := ipv4Bytes[test.expectErrorDetail.payloadFragment-1]
				if !bytes.Equal(gotPayload, wantPayload) {
					t.Fatalf("received unexpected payload, got: %s, want: %s",
						hex.Dump(gotPayload),
						hex.Dump(wantPayload))
				}
			case noReply:
				gotErrorMessage, err := ipv4Conn.ExpectFrame(t, testbench.Layers{
					&testbench.Ether{},
					&testbench.IPv4{},
					&testbench.ICMPv4{
						Type: testbench.ICMPv4Type(test.expectErrorDetail.typ),
						Code: testbench.ICMPv4Code(test.expectErrorDetail.code),
					},
				}, test.expectFrameTimeout)
				if err == nil {
					t.Fatalf("didn't expect an ICMPv4 Error Message, but got one: %+v", gotErrorMessage)
				}
			}
		})
	}
}
