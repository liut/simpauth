package auth

// NOTE: THIS FILE WAS PRODUCED BY THE
// MSGP CODE GENERATION TOOL (github.com/tinylib/msgp)
// DO NOT EDIT

import (
	"github.com/tinylib/msgp/msgp"
)

// MarshalMsg implements msgp.Marshaler
func (z Names) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	o = msgp.AppendArrayHeader(o, uint32(len(z)))
	for zxvk := range z {
		o = msgp.AppendString(o, z[zxvk])
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *Names) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var zbai uint32
	zbai, bts, err = msgp.ReadArrayHeaderBytes(bts)
	if err != nil {
		return
	}
	if cap((*z)) >= int(zbai) {
		(*z) = (*z)[:zbai]
	} else {
		(*z) = make(Names, zbai)
	}
	for zbzg := range *z {
		(*z)[zbzg], bts, err = msgp.ReadStringBytes(bts)
		if err != nil {
			return
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z Names) Msgsize() (s int) {
	s = msgp.ArrayHeaderSize
	for zcmr := range z {
		s += msgp.StringPrefixSize + len(z[zcmr])
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *User) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 7
	// string "u"
	o = append(o, 0x87, 0xa1, 0x75)
	o = msgp.AppendString(o, z.UID)
	// string "n"
	o = append(o, 0xa1, 0x6e)
	o = msgp.AppendString(o, z.Name)
	// string "a"
	o = append(o, 0xa1, 0x61)
	o = msgp.AppendString(o, z.Avatar)
	// string "h"
	o = append(o, 0xa1, 0x68)
	o = msgp.AppendInt64(o, z.LastHit)
	// string "t"
	o = append(o, 0xa1, 0x74)
	o = msgp.AppendInt(o, z.TeamID)
	// string "r"
	o = append(o, 0xa1, 0x72)
	o = msgp.AppendArrayHeader(o, uint32(len(z.Roles)))
	for zajw := range z.Roles {
		o = msgp.AppendString(o, z.Roles[zajw])
	}
	// string "w"
	o = append(o, 0xa1, 0x77)
	o = msgp.AppendArrayHeader(o, uint32(len(z.Watchings)))
	for zwht := range z.Watchings {
		o = msgp.AppendString(o, z.Watchings[zwht])
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *User) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zhct uint32
	zhct, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zhct > 0 {
		zhct--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "u":
			z.UID, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				return
			}
		case "n":
			z.Name, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				return
			}
		case "a":
			z.Avatar, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				return
			}
		case "h":
			z.LastHit, bts, err = msgp.ReadInt64Bytes(bts)
			if err != nil {
				return
			}
		case "t":
			z.TeamID, bts, err = msgp.ReadIntBytes(bts)
			if err != nil {
				return
			}
		case "r":
			var zcua uint32
			zcua, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.Roles) >= int(zcua) {
				z.Roles = (z.Roles)[:zcua]
			} else {
				z.Roles = make(Names, zcua)
			}
			for zajw := range z.Roles {
				z.Roles[zajw], bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
			}
		case "w":
			var zxhx uint32
			zxhx, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.Watchings) >= int(zxhx) {
				z.Watchings = (z.Watchings)[:zxhx]
			} else {
				z.Watchings = make(Names, zxhx)
			}
			for zwht := range z.Watchings {
				z.Watchings[zwht], bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					return
				}
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *User) Msgsize() (s int) {
	s = 1 + 2 + msgp.StringPrefixSize + len(z.UID) + 2 + msgp.StringPrefixSize + len(z.Name) + 2 + msgp.StringPrefixSize + len(z.Avatar) + 2 + msgp.Int64Size + 2 + msgp.IntSize + 2 + msgp.ArrayHeaderSize
	for zajw := range z.Roles {
		s += msgp.StringPrefixSize + len(z.Roles[zajw])
	}
	s += 2 + msgp.ArrayHeaderSize
	for zwht := range z.Watchings {
		s += msgp.StringPrefixSize + len(z.Watchings[zwht])
	}
	return
}
