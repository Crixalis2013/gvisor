// Copyright 2018 The gVisor Authors.
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

package header

import (
	"encoding/binary"
	"errors"
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// RFC 971 defines the fields of the IPv4 header on page 11 using the following
// diagram: ("Figure 4")
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |Version|  IHL  |Type of Service|          Total Length         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         Identification        |Flags|      Fragment Offset    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  Time to Live |    Protocol   |         Header Checksum       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                       Source Address                          |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Destination Address                        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Options                    |    Padding    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
const (
	versIHL = 0
	tos     = 1
	// IPv4TotalLenOffset is the offset of the total length field in the
	// IPv4 header.
	IPv4TotalLenOffset = 2
	id                 = 4
	flagsFO            = 6
	ttl                = 8
	protocol           = 9
	checksum           = 10
	srcAddr            = 12
	dstAddr            = 16
	options            = 20
)

// IPv4Fields contains the fields of an IPv4 packet. It is used to describe the
// fields of a packet that needs to be encoded.
type IPv4Fields struct {
	// IHL is the "internet header length" field of an IPv4 packet. The value
	// is in bytes.
	IHL uint8

	// TOS is the "type of service" field of an IPv4 packet.
	TOS uint8

	// TotalLength is the "total length" field of an IPv4 packet.
	TotalLength uint16

	// ID is the "identification" field of an IPv4 packet.
	ID uint16

	// Flags is the "flags" field of an IPv4 packet.
	Flags uint8

	// FragmentOffset is the "fragment offset" field of an IPv4 packet.
	FragmentOffset uint16

	// TTL is the "time to live" field of an IPv4 packet.
	TTL uint8

	// Protocol is the "protocol" field of an IPv4 packet.
	Protocol uint8

	// Checksum is the "checksum" field of an IPv4 packet.
	Checksum uint16

	// SrcAddr is the "source ip address" of an IPv4 packet.
	SrcAddr tcpip.Address

	// DstAddr is the "destination ip address" of an IPv4 packet.
	DstAddr tcpip.Address
}

// IPv4 represents an IPv4 header stored in a byte array.
// Most of the methods of IPv4 access to the underlying slice without
// checking the boundaries and could panic because of 'index out of range'.
// Always call IsValid() to validate an instance of IPv4 before using other
// methods.
type IPv4 []byte

const (
	// IPv4MinimumSize is the minimum size of a valid IPv4 packet;
	// i.e. a packet header with no options.
	IPv4MinimumSize = 20

	// IPv4MaximumHeaderSize is the maximum size of an IPv4 header. Given
	// that there are only 4 bits to represents the header length in 32-bit
	// units, the header cannot exceed 15*4 = 60 bytes.
	IPv4MaximumHeaderSize = 60

	// IPv4MaximumOptionSize is the largest size the IPv4 options can be.
	IPv4MaximumOptionSize = IPv4MaximumHeaderSize - IPv4MinimumSize

	// IPv4MaximumPayloadSize is the maximum size of a valid IPv4 payload.
	//
	// Linux limits this to 65,515 octets (the max IP datagram size - the IPv4
	// header size). But RFC 791 section 3.2 discusses the design of the IPv4
	// fragment "allows 2**13 = 8192 fragments of 8 octets each for a total of
	// 65,536 octets. Note that this is consistent with the the datagram total
	// length field (of course, the header is counted in the total length and not
	// in the fragments)."
	IPv4MaximumPayloadSize = 65536

	// MinIPFragmentPayloadSize is the minimum number of payload bytes that
	// the first fragment must carry when an IPv4 packet is fragmented.
	MinIPFragmentPayloadSize = 8

	// IPv4AddressSize is the size, in bytes, of an IPv4 address.
	IPv4AddressSize = 4

	// IPv4ProtocolNumber is IPv4's network protocol number.
	IPv4ProtocolNumber tcpip.NetworkProtocolNumber = 0x0800

	// IPv4Version is the version of the IPv4 protocol.
	IPv4Version = 4

	// IPv4AllSystems is the all systems IPv4 multicast address as per
	// IANA's IPv4 Multicast Address Space Registry. See
	// https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml.
	IPv4AllSystems tcpip.Address = "\xe0\x00\x00\x01"

	// IPv4Broadcast is the broadcast address of the IPv4 procotol.
	IPv4Broadcast tcpip.Address = "\xff\xff\xff\xff"

	// IPv4Any is the non-routable IPv4 "any" meta address.
	IPv4Any tcpip.Address = "\x00\x00\x00\x00"

	// IPv4MinimumProcessableDatagramSize is the minimum size of an IP
	// packet that every IPv4 capable host must be able to
	// process/reassemble.
	IPv4MinimumProcessableDatagramSize = 576
)

// Flags that may be set in an IPv4 packet.
const (
	IPv4FlagMoreFragments = 1 << iota
	IPv4FlagDontFragment
)

// IPv4EmptySubnet is the empty IPv4 subnet.
var IPv4EmptySubnet = func() tcpip.Subnet {
	subnet, err := tcpip.NewSubnet(IPv4Any, tcpip.AddressMask(IPv4Any))
	if err != nil {
		panic(err)
	}
	return subnet
}()

// IPVersion returns the version of IP used in the given packet. It returns -1
// if the packet is not large enough to contain the version field.
func IPVersion(b []byte) int {
	// Length must be at least offset+length of version field.
	if len(b) < versIHL+1 {
		return -1
	}
	return int(b[versIHL] >> ipVersionShift)
}

// RFC 791 page 11 shows the header length (IHL) is in the lower 4 bits
// of the first byte, and is counted in multiples of 4 bytes.
//
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |Version|  IHL  |Type of Service|          Total Length         |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      (...)
//     Version:  4 bits
//       The Version field indicates the format of the internet header.  This
//       document describes version 4.
//
//     IHL:  4 bits
//       Internet Header Length is the length of the internet header in 32
//       bit words, and thus points to the beginning of the data.  Note that
//       the minimum value for a correct header is 5.
const (
	ipVersionShift = 4
	ipIHLMask      = 0x0f
	IPv4IHLStride  = 4
)

// HeaderLength returns the value of the "header length" field of the IPv4
// header. The length returned is in bytes.
func (b IPv4) HeaderLength() uint8 {
	return (b[versIHL] & ipIHLMask) * IPv4IHLStride
}

// SetHeaderLength sets the value of the "Internet Header Length" field.
func (b IPv4) SetHeaderLength(hdrLen uint8) {
	if hdrLen > IPv4MaximumHeaderSize {
		panic(fmt.Sprintf("got IPv4 Header size = %d, want <= %d", hdrLen, IPv4MaximumHeaderSize))
	}
	b[versIHL] = (IPv4Version << ipVersionShift) | ((hdrLen / IPv4IHLStride) & ipIHLMask)
}

// ID returns the value of the identifier field of the IPv4 header.
func (b IPv4) ID() uint16 {
	return binary.BigEndian.Uint16(b[id:])
}

// Protocol returns the value of the protocol field of the IPv4 header.
func (b IPv4) Protocol() uint8 {
	return b[protocol]
}

// Flags returns the "flags" field of the IPv4 header.
func (b IPv4) Flags() uint8 {
	return uint8(binary.BigEndian.Uint16(b[flagsFO:]) >> 13)
}

// More returns whether the more fragments flag is set.
func (b IPv4) More() bool {
	return b.Flags()&IPv4FlagMoreFragments != 0
}

// TTL returns the "TTL" field of the IPv4 header.
func (b IPv4) TTL() uint8 {
	return b[ttl]
}

// FragmentOffset returns the "fragment offset" field of the IPv4 header.
func (b IPv4) FragmentOffset() uint16 {
	return binary.BigEndian.Uint16(b[flagsFO:]) << 3
}

// TotalLength returns the "total length" field of the IPv4 header.
func (b IPv4) TotalLength() uint16 {
	return binary.BigEndian.Uint16(b[IPv4TotalLenOffset:])
}

// Checksum returns the checksum field of the IPv4 header.
func (b IPv4) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[checksum:])
}

// SourceAddress returns the "source address" field of the IPv4 header.
func (b IPv4) SourceAddress() tcpip.Address {
	return tcpip.Address(b[srcAddr : srcAddr+IPv4AddressSize])
}

// DestinationAddress returns the "destination address" field of the IPv4
// header.
func (b IPv4) DestinationAddress() tcpip.Address {
	return tcpip.Address(b[dstAddr : dstAddr+IPv4AddressSize])
}

// IPv4OptionsBuffer is a buffer that holds all the raw IP options.
type IPv4OptionsBuffer []byte

// Options returns a buffer holding the options.
func (b IPv4) Options() IPv4OptionsBuffer {
	hdrLen := b.HeaderLength()
	return IPv4OptionsBuffer(b[options:hdrLen:hdrLen])
}

// TransportProtocol implements Network.TransportProtocol.
func (b IPv4) TransportProtocol() tcpip.TransportProtocolNumber {
	return tcpip.TransportProtocolNumber(b.Protocol())
}

// Payload implements Network.Payload.
func (b IPv4) Payload() []byte {
	return b[b.HeaderLength():][:b.PayloadLength()]
}

// PayloadLength returns the length of the payload portion of the IPv4 packet.
func (b IPv4) PayloadLength() uint16 {
	return b.TotalLength() - uint16(b.HeaderLength())
}

// TOS returns the "type of service" field of the IPv4 header.
func (b IPv4) TOS() (uint8, uint32) {
	return b[tos], 0
}

// SetTOS sets the "type of service" field of the IPv4 header.
func (b IPv4) SetTOS(v uint8, _ uint32) {
	b[tos] = v
}

// SetTTL sets the "Time to Live" field of the IPv4 header.
func (b IPv4) SetTTL(v byte) {
	b[ttl] = v
}

// SetTotalLength sets the "total length" field of the IPv4 header.
func (b IPv4) SetTotalLength(totalLength uint16) {
	binary.BigEndian.PutUint16(b[IPv4TotalLenOffset:], totalLength)
}

// SetChecksum sets the checksum field of the IPv4 header.
func (b IPv4) SetChecksum(v uint16) {
	binary.BigEndian.PutUint16(b[checksum:], v)
}

// SetFlagsFragmentOffset sets the "flags" and "fragment offset" fields of the
// IPv4 header.
func (b IPv4) SetFlagsFragmentOffset(flags uint8, offset uint16) {
	v := (uint16(flags) << 13) | (offset >> 3)
	binary.BigEndian.PutUint16(b[flagsFO:], v)
}

// SetID sets the identification field.
func (b IPv4) SetID(v uint16) {
	binary.BigEndian.PutUint16(b[id:], v)
}

// SetSourceAddress sets the "source address" field of the IPv4 header.
func (b IPv4) SetSourceAddress(addr tcpip.Address) {
	copy(b[srcAddr:srcAddr+IPv4AddressSize], addr)
}

// SetDestinationAddress sets the "destination address" field of the IPv4
// header.
func (b IPv4) SetDestinationAddress(addr tcpip.Address) {
	copy(b[dstAddr:dstAddr+IPv4AddressSize], addr)
}

// CalculateChecksum calculates the checksum of the IPv4 header.
func (b IPv4) CalculateChecksum() uint16 {
	return Checksum(b[:b.HeaderLength()], 0)
}

// Encode encodes all the fields of the IPv4 header.
func (b IPv4) Encode(i *IPv4Fields) {
	b.SetHeaderLength(i.IHL)
	b[tos] = i.TOS
	b.SetTotalLength(i.TotalLength)
	binary.BigEndian.PutUint16(b[id:], i.ID)
	b.SetFlagsFragmentOffset(i.Flags, i.FragmentOffset)
	b[ttl] = i.TTL
	b[protocol] = i.Protocol
	b.SetChecksum(i.Checksum)
	copy(b[srcAddr:srcAddr+IPv4AddressSize], i.SrcAddr)
	copy(b[dstAddr:dstAddr+IPv4AddressSize], i.DstAddr)
}

// EncodePartial updates the total length and checksum fields of IPv4 header,
// taking in the partial checksum, which is the checksum of the header without
// the total length and checksum fields. It is useful in cases when similar
// packets are produced.
func (b IPv4) EncodePartial(partialChecksum, totalLength uint16) {
	b.SetTotalLength(totalLength)
	checksum := Checksum(b[IPv4TotalLenOffset:IPv4TotalLenOffset+2], partialChecksum)
	b.SetChecksum(^checksum)
}

// IsValid performs basic validation on the packet.
func (b IPv4) IsValid(pktSize int) bool {
	if len(b) < IPv4MinimumSize {
		return false
	}

	hlen := int(b.HeaderLength())
	tlen := int(b.TotalLength())
	if hlen < IPv4MinimumSize || hlen > tlen || tlen > pktSize {
		return false
	}

	if IPVersion(b) != IPv4Version {
		return false
	}

	return true
}

// IsV4MulticastAddress determines if the provided address is an IPv4 multicast
// address (range 224.0.0.0 to 239.255.255.255). The four most significant bits
// will be 1110 = 0xe0.
func IsV4MulticastAddress(addr tcpip.Address) bool {
	if len(addr) != IPv4AddressSize {
		return false
	}
	return (addr[0] & 0xf0) == 0xe0
}

// IsV4LoopbackAddress determines if the provided address is an IPv4 loopback
// address (belongs to 127.0.0.0/8 subnet). See RFC 1122 section 3.2.1.3.
func IsV4LoopbackAddress(addr tcpip.Address) bool {
	if len(addr) != IPv4AddressSize {
		return false
	}
	return addr[0] == 0x7f
}

// ========================= Options ==========================
//
//      Example options layout. Adapted from RFC 791
//
//   |                      destination address                      |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   | Opt. Code = w | Opt.  Len.= 3 | option value  | Opt. Code = x |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   | Opt. Len. = 4 |           option value        | Opt. Code = 1 |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   | Opt. Code = y | Opt. Len. = 3 |  option value | Opt. Code = z |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   | Opt. Len = 2  | Opt. Code = 0 |  Ignored      |  Ignored      |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                              data                             |
//
//   Options types:
//      End of Option List
//        +--------+
//        |00000000| Type=0
//        +--------+
//
//      No Operation
//        +--------+
//        |00000001| Type=1
//        +--------+
//
//      Record Route
//        +--------+--------+--------+---------//--------+
//        |00000111| length | pointer|     route data    | Type=7
//        +--------+--------+--------+---------//--------+
//
//      Internet Timestamp
//        +--------+--------+--------+--------+
//        |01000100| length | pointer|oflw|flg| Type=68
//        +--------+--------+--------+--------+
//        |         internet address          |
//        +--------+--------+--------+--------+
//        |             timestamp             |
//        +--------+--------+--------+--------+
//        |                 .                 |
//        |                 .
//
//	Notes:
//  Option code 0: End of options. Anything following is ignored.
//  Option code 1: NOP/spacer. Can go anywhere and appear multiple times.
//  Only codes 0 and 1 have no length field.
//  Options may be on any byte boundary, however the complete options area ends
//  on a multiple of 4 bytes as specified by the IP header length field.
//  Several other options have been deprecated and are not shown here.
//
//  While RFC 791  (page 31) says "Every internet module must be able to act on
//  every option." This has not generally been adhered to and some options have
//  very low rates of support. We do not support options other than those shown
//  above.
const (
	// IPv4OptionListEndType is the option type for the End Of Option List
	// option.
	IPv4OptionListEndType = 0

	// IPv4OptionNOPType is the No-Operation option. May appear between other
	// options and may appear multiple times.
	IPv4OptionNOPType = 1

	// IPv4OptionTimestampType is the option type for the Timestamp option.
	IPv4OptionTimestampType = 68

	// IPv4OptionRecordRouteType is used by each router on the path of the packet
	// to record it's path. It is carried over to an Echo Reply.
	IPv4OptionRecordRouteType = 7

	// IPv4OptionTypeOffset is the offset in an option of it's type field.
	IPv4OptionTypeOffset = 0

	// IPv4OptionLengthOffset is the offset in an option of it's length field.
	IPv4OptionLengthOffset = 1
)

// Potential errors when parsing generic IP options.
var (
	ErrIPv4OptZeroLength   = errors.New("zero length IP option")
	ErrIPv4OptDuplicate    = errors.New("duplicate IP option")
	ErrIPv4OptInvalid      = errors.New("invalid IP option")
	ErrIPv4OptMalformed    = errors.New("malformed IP option")
	ErrIPv4OptionTruncated = errors.New("truncated IP option")
)

// IPv4Option is an interface representing various option types.
type IPv4Option interface {
	Type() uint8
	Size() uint8
	Contents() []byte
}

// IPv4OptionGeneric represents an IPv4 Option of unknown type stored
// in a byte array. It is an implementation of the IPv4Option interface.
type IPv4OptionGeneric []byte

// Type returns the type for the given IPv4 Option.
func (o IPv4OptionGeneric) Type() uint8 { return o[IPv4OptionTypeOffset] }

// Size implements IPv4Option.Size()
func (o IPv4OptionGeneric) Size() uint8 { return uint8(len(o)) }

// Contents implements IPv4Option.Contents()
func (o IPv4OptionGeneric) Contents() []byte { return []byte(o) }

// IPv4OptionIterator represents an iterator pointing to a specific IP option
// at any point of time. It also holds information as to a new options buffer
// that we are building up to hand back to the caller.
type IPv4OptionIterator struct {
	options IPv4OptionsBuffer
	// While parsing options we need to keep track of where we are as the
	// resulting ICMP packet is supposed to have a pointer to the byte within
	// the IP packet where the error was detected.
	ErrCursor     byte
	nextErrCursor byte
	newOptions    []byte
	writePoint    int
}

// NewIterator sets up and returns an iterator of options. It also sets up the
// building of a new option set.
func (o IPv4OptionsBuffer) NewIterator() IPv4OptionIterator {
	return IPv4OptionIterator{
		options:       o,
		nextErrCursor: IPv4MinimumSize,
		newOptions:    make([]byte, IPv4MaximumOptionSize, IPv4MaximumOptionSize),
	}
}

// RemainingBuffer returns the remaining (unused) part of the new option buffer,
// into which a new option may be written.
func (i *IPv4OptionIterator) RemainingBuffer() IPv4OptionsBuffer {
	return IPv4OptionsBuffer(i.newOptions[i.writePoint:])
}

// ConsumeBuffer marks a portion of the new buffer as used.
func (i *IPv4OptionIterator) ConsumeBuffer(size int) {
	i.writePoint += size
}

// PushByte puts one of the single byte options onto the new options.
func (i *IPv4OptionIterator) PushByte(val byte) {
	if i.writePoint < IPv4MaximumOptionSize {
		i.newOptions[i.writePoint] = val
		i.writePoint++
	}
}

// CloseBuffer ensures that the new options buffer is padded to a legal
// size, ready to add to an IP header.  RFC 791 page 31 says:
//
//     The options might not end on a 32-bit boundary.  The internet header
//     must be filled out with octets of zeros.  The first of these would
//     be interpreted as the end-of-options option, and the remainder as
//     internet header padding.
func (i *IPv4OptionIterator) CloseBuffer() {
	target := (i.writePoint + 3) & ^0x3
	var p = i.writePoint
	for p < target {
		i.newOptions[p] = IPv4OptionListEndType
		p++
	}
	i.writePoint = p
}

// NewOptions returns the completed replacement options buffer.
func (i *IPv4OptionIterator) NewOptions() IPv4OptionsBuffer {
	return IPv4OptionsBuffer(i.newOptions[:i.writePoint])
}

// Next returns the next IP option in the buffer/list of IP options.
// It returns
// - A slice of bytes holding the next option or nil if there is error.
// - A boolean which is true if parsing of all the options is complete.
// - An error which is non-nil if an error condition was encountered.
func (i *IPv4OptionIterator) Next() (IPv4Option, bool, error) {
	// The opts slice gets shorter as we process the options. When we have no
	// bytes left we are done.
	if len(i.options) == 0 {
		return nil, true, nil
	}

	i.ErrCursor = i.nextErrCursor

	optType := i.options[IPv4OptionTypeOffset]

	if optType == IPv4OptionNOPType || optType == IPv4OptionListEndType {
		returnOption := i.options[:1]
		i.options = i.options[1:]
		i.nextErrCursor = i.ErrCursor + 1
		return IPv4OptionGeneric(returnOption), false, nil
	}

	// There are no more single byte options defined.  All the rest have a length
	// field so we need to sanity check it.
	if len(i.options) == 1 {
		return nil, true, ErrIPv4OptMalformed
	}

	optLen := i.options[IPv4OptionLengthOffset]

	if optLen == 0 {
		i.ErrCursor++
		return nil, true, ErrIPv4OptZeroLength
	}

	if optLen < 2 { // i.e. 1.
		i.ErrCursor++
		return nil, true, ErrIPv4OptMalformed
	}

	if optLen > byte(len(i.options)) {
		i.ErrCursor++
		return nil, true, ErrIPv4OptionTruncated
	}

	optionBody := i.options[:optLen]
	i.nextErrCursor = i.ErrCursor + optLen
	i.options = i.options[optLen:]

	// We will check the length of some option types that we know.
	switch optType {
	case IPv4OptionTimestampType:
		if optLen < IPv4OptionTimestampHdrLength {
			i.ErrCursor++
			return nil, true, ErrIPv4OptMalformed
		}
		return IPv4OptionTimestamp(optionBody), false, nil

	case IPv4OptionRecordRouteType:
		if optLen < IPv4OptionRecordRouteHdrLength {
			i.ErrCursor++
			return nil, true, ErrIPv4OptMalformed
		}
		return IPv4OptionRecordRoute(optionBody), false, nil
	}
	return IPv4OptionGeneric(optionBody), false, nil
}

//
// IP Timestamp option - RFC 791 page 22.
// +--------+--------+--------+--------+
// |01000100| length | pointer|oflw|flg|
// +--------+--------+--------+--------+
// |         internet address          |
// +--------+--------+--------+--------+
// |             timestamp             |
// +--------+--------+--------+--------+
// |                ...                |
//
// Type = 68
//
// The Option Length is the number of octets in the option counting
// the type, length, pointer, and overflow/flag octets (maximum
// length 40).
//
// The Pointer is the number of octets from the beginning of this
// option to the end of timestamps plus one (i.e., it points to the
// octet beginning the space for next timestamp).  The smallest
// legal value is 5.  The timestamp area is full when the pointer
// is greater than the length.
//
// The Overflow (oflw) [4 bits] is the number of IP modules that
// cannot register timestamps due to lack of space.
//
// The Flag (flg) [4 bits] values are
//
//   0 -- time stamps only, stored in consecutive 32-bit words,
//
//   1 -- each timestamp is preceded with internet address of the
//        registering entity,
//
//   3 -- the internet address fields are prespecified.  An IP
//        module only registers its timestamp if it matches its own
//        address with the next specified internet address.
//
// Timestamps are defined in RFC 791 page 22 as milliseconds since midnight UTC.
//
//        The Timestamp is a right-justified, 32-bit timestamp in
//        milliseconds since midnight UT.  If the time is not available in
//        milliseconds or cannot be provided with respect to midnight UT
//        then any time may be inserted as a timestamp provided the high
//        order bit of the timestamp field is set to one to indicate the
//        use of a non-standard value.
//
// In Go we can get nSecs since then using UnixNano() (an int64)
// and get rid of parts > 1 day while converting to milliseconds.
const millisecondsPerDay = 24 * 3600 * 1000

// ipv4TimestampTime provides the current time as specified in RFC 791.
func ipv4TimestampTime(clock tcpip.Clock) uint32 {
	return uint32((clock.NowNanoseconds() / 1000000) % (millisecondsPerDay))
}

// Timestamp option specific related constants.
const (
	// IPv4OptionTimestampHdrLength is the length of the timestamp option header.
	IPv4OptionTimestampHdrLength = 4

	// IPv4OptionTimestampSize is the size of an IP timestamp.
	IPv4OptionTimestampSize = 4

	// IPv4OptionTimestampWithAddrSize is the size of an IP timestamp + Address.
	IPv4OptionTimestampWithAddrSize = IPv4AddressSize + IPv4OptionTimestampSize

	// IPv4OptionTimestampMaxSize is limited by space for options
	IPv4OptionTimestampMaxSize = IPv4MaximumOptionSize

	// IPv4OptionTimestampOnlyFlag is a flag indicating that only timestamp
	// is present.
	IPv4OptionTimestampOnlyFlag = 0

	// IPv4OptionTimestampWithIPFlag is a flag indicating that both timestamps and
	// IP are present.
	IPv4OptionTimestampWithIPFlag = 1

	// IPv4OptionTimestampWithPredefinedIPFlag is a flag indicating that
	// predefined IP is present.
	IPv4OptionTimestampWithPredefinedIPFlag = 3
)

// IP Timestamp option fields.
const (
	ipv4OptionTimestampPointer      = 2
	ipv4OptionTimestampOFLWAndFLG   = 3
	ipv4OptionTimestampOverflowMask = 0xf0
	ipv4OptionTimestampFlagsMask    = 0x0f
)

// These errors are specific to Timestamp option processing.
var (
	// ErrIPv4TimestampOptInvalidLength indicates a timestamp option had an
	// inconsitency to do with its length.
	ErrIPv4TimestampOptInvalidLength = errors.New("invalid timestamp length")

	// ErrIPv4TimestampOptInvalidPointer is used when the pointer in a timestamp
	// does not point within the option.
	ErrIPv4TimestampOptInvalidPointer = errors.New("invalid timestamp pointer")

	// ErrIPv4TimestampOptOverflow is used when the number of overflowed
	// timestamps exceeds 15 (a four bit value).
	ErrIPv4TimestampOptOverflow = errors.New("timestamp overflow")

	// ErrIPv4TimestampOptInvalidFlags indicates that the flags of a
	// timestamp option do not contain a valid combination.
	ErrIPv4TimestampOptInvalidFlags = errors.New("invalid timestamp flags")
)

// IPv4OptionTimestamp represents an IPv4 Timestamp Option stored
// in a byte slice. It is an instance of the IPv4Option interface.
type IPv4OptionTimestamp []byte

// Type implements IPv4Option.Type(). Returns 68
func (ts IPv4OptionTimestamp) Type() uint8 { return IPv4OptionTimestampType }

// Size implements IPv4Option.Size().
func (ts IPv4OptionTimestamp) Size() uint8 { return uint8(len(ts)) }

// Contents implements IPv4Option.Contents().
func (ts IPv4OptionTimestamp) Contents() []byte { return []byte(ts) }

// Pointer returns the pointer field in the IP Timestamp option.
func (ts IPv4OptionTimestamp) Pointer() uint8 {
	return ts[ipv4OptionTimestampPointer]
}

// Flags returns the flags field in the IP Timestamp option.
func (ts IPv4OptionTimestamp) Flags() uint8 {
	return ts[ipv4OptionTimestampOFLWAndFLG] & ipv4OptionTimestampFlagsMask
}

// Overflow returns the Overflow field in the IP Timestamp option
func (ts IPv4OptionTimestamp) Overflow() uint8 {
	return (ts[ipv4OptionTimestampOFLWAndFLG] & ipv4OptionTimestampOverflowMask) >> 4
}

// IncOverflow increments the Overflow field in the IP Timestamp option. If
// the return value is 0 then the field overflowed.
func (ts IPv4OptionTimestamp) IncOverflow() uint8 {
	ts[ipv4OptionTimestampOFLWAndFLG] += byte(1 << 4)
	return (ts[ipv4OptionTimestampOFLWAndFLG] & ipv4OptionTimestampOverflowMask) >> 4
}

// UpdateTimestamp updates the fields of the next free timestamp slot.
func (ts IPv4OptionTimestamp) UpdateTimestamp(addr tcpip.Address, clock tcpip.Clock) {
	slot := ts[ts.Pointer()-1:]

	switch ts.Flags() {
	case IPv4OptionTimestampOnlyFlag:
		binary.BigEndian.PutUint32(slot, ipv4TimestampTime(clock))
		ts[ipv4OptionTimestampPointer] += IPv4OptionTimestampSize
	case IPv4OptionTimestampWithIPFlag:
		_ = copy(slot, addr)
		binary.BigEndian.PutUint32(slot[IPv4AddressSize:], ipv4TimestampTime(clock))
		ts[ipv4OptionTimestampPointer] += IPv4OptionTimestampWithAddrSize
	case IPv4OptionTimestampWithPredefinedIPFlag:
		if tcpip.Address(slot[:IPv4AddressSize]) == addr {
			binary.BigEndian.PutUint32(slot[IPv4AddressSize:], ipv4TimestampTime(clock))
			ts[ipv4OptionTimestampPointer] += IPv4OptionTimestampWithAddrSize
		}
	}
	return
}

// from RFC 791 page 20:
//   Record Route
//
//         +--------+--------+--------+---------//--------+
//         |00000111| length | pointer|     route data    |
//         +--------+--------+--------+---------//--------+
//           Type=7
//
//         The record route option provides a means to record the route of
//         an internet datagram.
//
//         The option begins with the option type code.  The second octet
//         is the option length which includes the option type code and the
//         length octet, the pointer octet, and length-3 octets of route
//         data.  The third octet is the pointer into the route data
//         indicating the octet which begins the next area to store a route
//         address.  The pointer is relative to this option, and the
//         smallest legal value for the pointer is 4.

// RecordRoute option specific related constants.
const (
	// IPv4OptionRecordRouteHdrLength is the length of the Record Route option
	// header.
	IPv4OptionRecordRouteHdrLength = 3

	// ipv4OptionRecordRoutePointer is the next free slot in the list of
	// addresses.
	ipv4OptionRecordRoutePointer = 2
)

// These errors are specific to RecordRoute option processing.
var (
	// ErrIPv4RecordRouteOptInvalidLength indicates a Record Route option had an
	// inconsitency to do with its length.
	ErrIPv4RecordRouteOptInvalidLength = errors.New("record Route invalid length")

	// ErrIPv4RecordRouteOptInvalidPointer is used when the pointer in a Record
	// Route has a problem with the pointer to its next free slot.
	ErrIPv4RecordRouteOptInvalidPointer = errors.New("record Route invalid pointer")
)

// IPv4OptionRecordRoute represents an IPv4 RecordRoute Option stored
// in a byte slice. It is an instance of the IPv4Option interface.
type IPv4OptionRecordRoute []byte

// Pointer returns the pointer field in the IP RecordRoute option.
func (rr IPv4OptionRecordRoute) Pointer() uint8 {
	return rr[ipv4OptionRecordRoutePointer]
}

// StoreAddress stores the given IPv4 address into the next free slot.
func (rr IPv4OptionRecordRoute) StoreAddress(addr tcpip.Address) {
	start := rr.Pointer() - 1 // A one based number.
	copy(rr[start:], addr)
	rr[ipv4OptionRecordRoutePointer] += IPv4AddressSize
}

// Type implements IPv4Option.Type().
func (rr IPv4OptionRecordRoute) Type() uint8 { return IPv4OptionRecordRouteType }

// Size implements IPv4Option.Size().
func (rr IPv4OptionRecordRoute) Size() uint8 { return uint8(len(rr)) }

// Contents implements IPv4Option.Contents().
func (rr IPv4OptionRecordRoute) Contents() []byte { return []byte(rr) }
