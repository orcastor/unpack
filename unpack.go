package unpack

import (
	"io"
	"sync"
)

type Unpacker interface {
	Name() string
	Detect(path string) int
	Unpack(path string) (io.ReaderAt, error)
}

var ups = sync.Map{}

func RegisterFormat(name string, unpack Unpacker) {
	ups.Store(name, unpack)
}

func DetectFormat(path string) (up Unpacker, version int) {
	ups.Range(func(k, v interface{}) bool {
		if ver := v.(Unpacker).Detect(path); ver > 0 {
			up = v.(Unpacker)
			version = ver
			return false
		}
		return true
	})
	return
}

func Unpack(path string) (io.ReaderAt, error) {
	if up, _ := DetectFormat(path); up != nil {
		var err error
		if _, err := up.Unpack(path); err == nil {
			return Unpack(path)
		}
		return nil, err
	}
	return nil, nil
}
