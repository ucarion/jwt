package parts

import (
	"bytes"
	"errors"
)

type Parts struct {
	Header    string
	Claims    string
	Signature string
}

var ErrNotEnoughParts = errors.New("jwt: not enough parts")

func Parse(s []byte) (Parts, error) {
	p := bytes.SplitN(s, []byte("."), 3)
	if len(p) != 3 {
		return Parts{}, ErrNotEnoughParts
	}

	return Parts{
		Header:    string(p[0]),
		Claims:    string(p[1]),
		Signature: string(p[2]),
	}, nil
}
