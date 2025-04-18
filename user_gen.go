package auth

// Code generated by github.com/tinylib/msgp DO NOT EDIT.

import (
	"github.com/tinylib/msgp/msgp"
)

// MarshalMsg implements msgp.Marshaler
func (z Names) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	o = msgp.AppendArrayHeader(o, uint32(len(z)))
	for za0001 := range z {
		o = msgp.AppendString(o, z[za0001])
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *Names) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var zb0002 uint32
	zb0002, bts, err = msgp.ReadArrayHeaderBytes(bts)
	if err != nil {
		err = msgp.WrapError(err)
		return
	}
	if cap((*z)) >= int(zb0002) {
		(*z) = (*z)[:zb0002]
	} else {
		(*z) = make(Names, zb0002)
	}
	for zb0001 := range *z {
		(*z)[zb0001], bts, err = msgp.ReadStringBytes(bts)
		if err != nil {
			err = msgp.WrapError(err, zb0001)
			return
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z Names) Msgsize() (s int) {
	s = msgp.ArrayHeaderSize
	for zb0003 := range z {
		s += msgp.StringPrefixSize + len(z[zb0003])
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *User) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 8
	// string "i"
	o = append(o, 0x88, 0xa1, 0x69)
	o = msgp.AppendString(o, z.OID)
	// string "u"
	o = append(o, 0xa1, 0x75)
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
	o = msgp.AppendInt64(o, z.TeamID)
	// string "r"
	o = append(o, 0xa1, 0x72)
	o = msgp.AppendArrayHeader(o, uint32(len(z.Roles)))
	for za0001 := range z.Roles {
		o = msgp.AppendString(o, z.Roles[za0001])
	}
	// string "w"
	o = append(o, 0xa1, 0x77)
	o = msgp.AppendArrayHeader(o, uint32(len(z.Watchings)))
	for za0002 := range z.Watchings {
		o = msgp.AppendString(o, z.Watchings[za0002])
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *User) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zb0001 uint32
	zb0001, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		err = msgp.WrapError(err)
		return
	}
	for zb0001 > 0 {
		zb0001--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		switch msgp.UnsafeString(field) {
		case "i":
			z.OID, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "OID")
				return
			}
		case "u":
			z.UID, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "UID")
				return
			}
		case "n":
			z.Name, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Name")
				return
			}
		case "a":
			z.Avatar, bts, err = msgp.ReadStringBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Avatar")
				return
			}
		case "h":
			z.LastHit, bts, err = msgp.ReadInt64Bytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "LastHit")
				return
			}
		case "t":
			z.TeamID, bts, err = msgp.ReadInt64Bytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "TeamID")
				return
			}
		case "r":
			var zb0002 uint32
			zb0002, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Roles")
				return
			}
			if cap(z.Roles) >= int(zb0002) {
				z.Roles = (z.Roles)[:zb0002]
			} else {
				z.Roles = make(Names, zb0002)
			}
			for za0001 := range z.Roles {
				z.Roles[za0001], bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					err = msgp.WrapError(err, "Roles", za0001)
					return
				}
			}
		case "w":
			var zb0003 uint32
			zb0003, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				err = msgp.WrapError(err, "Watchings")
				return
			}
			if cap(z.Watchings) >= int(zb0003) {
				z.Watchings = (z.Watchings)[:zb0003]
			} else {
				z.Watchings = make(Names, zb0003)
			}
			for za0002 := range z.Watchings {
				z.Watchings[za0002], bts, err = msgp.ReadStringBytes(bts)
				if err != nil {
					err = msgp.WrapError(err, "Watchings", za0002)
					return
				}
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				err = msgp.WrapError(err)
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *User) Msgsize() (s int) {
	s = 1 + 2 + msgp.StringPrefixSize + len(z.OID) + 2 + msgp.StringPrefixSize + len(z.UID) + 2 + msgp.StringPrefixSize + len(z.Name) + 2 + msgp.StringPrefixSize + len(z.Avatar) + 2 + msgp.Int64Size + 2 + msgp.Int64Size + 2 + msgp.ArrayHeaderSize
	for za0001 := range z.Roles {
		s += msgp.StringPrefixSize + len(z.Roles[za0001])
	}
	s += 2 + msgp.ArrayHeaderSize
	for za0002 := range z.Watchings {
		s += msgp.StringPrefixSize + len(z.Watchings[za0002])
	}
	return
}
