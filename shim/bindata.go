// Code generated by go-bindata.
// sources:
// bindata.go
// byline.js
// index.js
// shim.go
// DO NOT EDIT!

package shim

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _bindataGo = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x01\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00")

func bindataGoBytes() ([]byte, error) {
	return bindataRead(
		_bindataGo,
		"bindata.go",
	)
}

func bindataGo() (*asset, error) {
	bytes, err := bindataGoBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "bindata.go", size: 0, mode: os.FileMode(420), modTime: time.Unix(1554191796, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _bylineJs = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x94\x58\x61\x4f\xe3\x48\x12\xfd\x9e\x5f\x51\xcb\x49\x93\xa0\x33\x06\x46\x3a\x69\x34\x88\x93\x3c\xc1\x80\xef\x82\x83\x1c\xb3\xdc\x68\x66\xb4\xea\xd8\x65\xdc\x8b\xd3\xed\xeb\x6e\x93\x41\x0b\xff\xfd\x54\xdd\x76\xec\x40\xe0\x76\xbf\x0c\x8e\xbb\xeb\x55\xd5\xab\x57\xd5\xed\x39\x3c\x84\xa9\xac\x1f\x15\xbf\x2b\x0d\x4c\xa6\xfb\xf0\xf1\xe8\xf8\xf8\xe0\xe3\xd1\xf1\x3f\xe0\x5f\xb2\x14\x70\x89\x6b\x2d\xc5\xe8\xf0\x70\x74\x78\x08\xd7\xa8\x56\x5c\x6b\x2e\x05\x70\x0d\x25\x2a\x5c\x3e\xc2\x9d\x62\xc2\x60\xee\x41\xa1\x10\x41\x16\x90\x95\x4c\xdd\xa1\x07\x46\x02\x13\x8f\x50\xa3\xd2\x52\x80\x5c\x1a\xc6\x05\x17\x77\xc0\x20\x93\xf5\x23\xe1\xc9\x02\x4c\xc9\x35\x68\x59\x98\x35\x53\x08\x4c\xe4\xc0\xb4\x96\x19\x67\x06\x73\xc8\x65\xd6\xac\x50\x18\x66\xc8\x65\xc1\x2b\xd4\x30\x31\x25\xc2\xde\xa2\xb5\xd8\xdb\x27\x3f\x84\x95\x23\xab\x80\x0b\xa0\xe5\x6e\x15\xd6\xdc\x94\xb2\x31\xa0\x50\x1b\xc5\x33\x82\xf1\x80\x8b\xac\x6a\x72\x8a\xa4\x5b\xae\xf8\x8a\xb7\x4e\x4c\x89\x84\x66\xf9\xd0\x94\x42\xa3\xd1\xb3\x01\x7b\xb0\x92\x39\x2f\xe8\x2f\xda\xfc\xea\x66\x59\x71\x5d\x7a\x90\x73\x42\x5f\x36\x06\x3d\xd0\xf4\x32\x43\x41\x56\x4c\xe4\x87\x52\x11\x9c\xc6\xaa\x22\x10\x8e\xda\x25\xdd\xc7\x68\xb7\x91\xa3\x9a\xc8\x35\x2d\x5d\xd6\xf5\xba\x94\xab\xed\x7c\xb8\x26\xb4\xa2\x51\x82\xeb\x12\xad\x59\x2e\x41\x4b\xeb\xf7\x77\xcc\x0c\xbd\x21\x8b\x42\x56\x95\x5c\x53\x8e\x99\x14\x39\xa7\xd4\xf4\xe7\xb6\x8a\x69\x89\xc0\x96\xf2\x01\x6d\x5a\xae\xf2\x42\x1a\x9e\x39\xfe\x6d\x45\xea\xbe\xd2\xed\x92\x2e\x59\x55\xc1\x12\x5b\xfa\x30\x07\x4e\xb2\x00\x36\xc8\x4c\x51\x18\xda\x30\x61\x38\xab\xa0\x96\xca\xfa\x7d\x99\xb1\xdf\xc5\x71\x19\xc2\x62\x7e\x9e\xde\x06\x49\x08\xd1\x02\xae\x93\xf9\xaf\xd1\x59\x78\x06\x7b\xc1\x02\xa2\xc5\x9e\x07\xb7\x51\x7a\x39\xbf\x49\xe1\x36\x48\x92\x20\x4e\xbf\xc2\xfc\x1c\x82\xf8\x2b\xfc\x3b\x8a\xcf\x3c\x08\xff\x73\x9d\x84\x8b\x05\xcc\x13\x42\x8b\xae\xae\x67\x51\x78\xe6\x41\x14\x4f\x67\x37\x67\x51\x7c\x01\x5f\x6e\x52\x88\xe7\x29\xcc\xa2\xab\x28\x0d\xcf\x20\x9d\x5b\x9f\x2d\x5a\x14\x2e\x08\xef\x2a\x4c\xa6\x97\x41\x9c\x06\x5f\xa2\x59\x94\x7e\xf5\x08\xeb\x3c\x4a\x63\x42\x3e\x9f\x27\x10\xc0\x75\x90\xa4\xd1\xf4\x66\x16\x24\x70\x7d\x93\x5c\xcf\x17\x21\x04\xf1\x19\xc4\xf3\x38\x8a\xcf\x93\x28\xbe\x08\xaf\xc2\x38\xf5\x21\x8a\x21\x9e\x43\xf8\x6b\x18\xa7\xb0\xb8\x0c\x66\x33\xf2\x46\x70\xc1\x4d\x7a\x39\x4f\x28\x50\x98\xce\xaf\xbf\x26\xd1\xc5\x65\x0a\x97\xf3\xd9\x59\x98\x2c\xe0\x4b\x08\xb3\x28\xf8\x32\x0b\x9d\xb7\xf8\x2b\x4c\x67\x41\x74\xe5\xc1\x59\x70\x15\x5c\x84\xd6\x6a\x9e\x5e\x86\x36\x49\xda\xe9\xc2\x84\xdb\xcb\x90\xde\x92\xd7\x20\x86\x60\x9a\x46\xf3\x98\xf2\x99\xce\xe3\x34\x09\xa6\xa9\x07\xe9\x3c\x49\x37\xd6\xb7\xd1\x22\xf4\x20\x48\xa2\x45\x14\x5f\xd8\x1c\x93\xf9\x95\x07\xc4\xee\xfc\x9c\x76\x45\x31\x99\xc6\xa1\x03\x22\xe6\xb7\x0b\x34\x4f\xec\xef\x9b\x45\xb8\xc1\x84\xb3\x30\x98\x45\xf1\xc5\xc2\xf2\x1f\x6f\xed\xf7\x47\xa3\x07\xa6\x40\x1b\x85\x6c\x05\xa7\xa0\xf0\xbf\x0d\x57\x38\x19\xbb\x37\xe3\x7d\x6f\x04\x00\xd0\x18\x5e\x0d\x57\xe9\xf7\x78\xff\x64\x44\x88\x99\x14\x0f\x5c\x70\x14\x19\x42\x70\x1d\x8d\x56\x32\x6f\x2a\xf4\xf1\x27\x09\x4b\xc3\x29\x14\x8d\xb0\x2d\x3d\x51\xc8\xf2\x85\xc5\xf5\x40\xd6\x56\x74\xfb\xf0\xc7\x08\x40\xa1\x69\x94\x80\x6d\x4b\x3f\x53\xc8\x0c\x3a\x83\x9d\xb6\x27\xa3\x67\x17\xc2\x92\x69\x9e\xed\x70\xbe\x05\xf1\xa7\x22\xe1\x05\x0c\x16\xdd\xbb\x4d\x7c\x0e\x6d\xc6\xc5\xfb\x41\x01\x3c\x03\x56\x1a\xb7\x8d\x05\xae\x61\x60\xba\xb5\xbd\xcb\x23\xc7\x5a\x61\x66\x67\xea\x9b\xc9\xf4\x18\xbb\x13\x72\x31\x67\x52\x68\x59\xa1\x5f\xc9\xbb\xc9\xf8\x36\x48\xe2\x28\xbe\xf8\x0c\xcb\xc7\x8a\x0b\xfc\xdb\x2b\x20\xae\x87\xae\x69\xba\xac\xb9\x9b\x22\x0a\x57\xf2\x01\x73\xd0\x52\x8a\xb1\x0d\xf6\xff\x73\xd1\xd6\xa5\x8b\xed\xcf\xd1\xb6\x61\xff\x97\xd7\xf4\x9b\x52\xc9\xb5\x25\x30\x54\x4a\xaa\xc9\x18\x7f\xd6\x98\x51\xa8\xfd\xde\x71\xcb\xe4\x2b\x10\x9f\x1e\xd9\xb2\xc2\x37\xd1\xfa\xbd\xb0\x6a\xb4\x71\x69\x3b\x9b\x1e\x95\xba\xa4\x22\x35\xbf\x53\xc7\x81\xd3\x9a\xd7\x38\xa9\xf4\x90\xb1\x4a\x9f\x8c\x9e\x47\xed\x50\x6d\x34\x0d\x7d\x1a\xb7\x84\x27\x64\x8e\xf0\x70\xe4\x1f\x1f\xc1\x9e\x6b\x3c\xfd\x71\xcf\x4a\xe0\xf0\x70\xf4\x52\x06\x5b\x02\xe8\x7f\x0c\x19\xdf\x11\x9f\x4d\xde\x61\xfb\xa9\x62\x42\x17\x52\xad\xfc\x8c\x55\xd5\x84\x4e\x92\x6d\xfd\xb6\xcf\x70\xba\x79\x7a\x7a\x82\x3f\xa8\xa8\x00\x36\x78\x04\x69\xcf\xb1\x2b\x0a\xdc\x48\xd0\x46\xd6\x36\x1b\xd9\x98\xba\x31\x50\x28\xb9\x82\x25\x52\x8e\xcb\xa6\x28\x50\x61\xee\x4c\xd7\x25\xcf\x4a\x50\x78\x90\x49\x91\x31\xc3\x04\x33\xa8\xad\x25\x29\x53\x7b\xf0\x3b\x55\xa0\x3b\xf0\x05\xae\xed\x6b\x7f\x04\xf6\xbc\xf3\x7f\xeb\x0a\xb3\x30\xcc\xa0\x3f\x08\xe2\x14\x8c\x6a\xf0\x64\xb3\x91\xec\xbe\x58\xd7\x70\x0a\xdf\x7e\xf4\x0b\xf7\x88\x75\xb8\xaa\xcd\x23\x91\x34\x48\xd1\x7f\xb1\xf0\xf4\x04\x05\xab\xf4\x10\x92\x69\x33\x2d\x1b\x71\x1f\x8a\x1c\xf3\x5b\x6e\xca\x69\x42\x3d\xe8\x76\xb9\xfc\x0c\xbb\x47\x9b\x8e\x96\x8d\xca\x70\xac\x01\x45\x26\xed\x2d\x86\x17\xb0\x46\xc8\xa5\x18\x1b\x28\xd9\x03\x82\x14\xd8\x61\x4b\x31\x19\x93\x64\xc6\x5e\xdf\xd2\x5a\x65\x9d\x64\xad\xa4\xed\xc6\x0e\xad\x5b\xb1\x4e\x97\x8d\x21\xe8\x8c\x11\x74\x2e\xdd\xd5\xa0\x90\x0a\x64\x95\x1f\x68\xf3\x58\x61\x5b\x79\xdd\xda\x10\x9e\x56\x19\x70\x41\xb7\x80\x0c\x65\xd1\x49\x23\x79\xd1\x2c\xae\x61\x06\x8e\xe1\x14\xb4\xca\x5e\x16\xa2\x5b\x3d\x69\x8d\x9e\x47\xdd\xbf\xcf\x34\x0d\x46\x74\x5e\xf8\x5c\x94\xa8\xb8\xd1\x93\x5e\x9e\xde\x2b\x49\xd2\xa1\xd2\xaf\xfb\xb5\x92\x46\x9a\xc7\x1a\xfd\xdf\x4c\xb7\x65\x38\xf7\x32\xaa\x87\xb7\x21\xd9\x23\x7e\xdb\xe0\xed\x3c\xcd\x48\x1b\x4b\x2e\x98\x7a\x04\xbb\x57\x03\xd3\x70\x93\x9e\x1f\x7c\x1a\x01\x0c\x92\xda\x3c\x3e\x3d\xc1\xb8\x31\xc5\xa7\xb1\x2d\x29\x31\xe5\x64\xe4\x73\xed\x1e\x9c\xcf\xfd\x61\x6d\x7a\x9c\x53\x18\x3b\xc1\x8f\x7b\x06\xed\x7e\x38\x75\x7f\x7d\x23\x17\x46\x71\x71\x37\xd9\x3f\xb1\xbd\x64\x8a\x4f\xed\xbe\x41\x34\x5d\x04\x3d\x97\x83\x03\xe5\x2d\xc0\x8d\x36\x7a\xbb\xe7\x8d\x78\x33\x27\xdc\x57\xf9\xda\x2c\xed\x70\x6b\xdb\xc1\x81\xea\xba\xe2\x66\x72\xf8\x5d\x7d\x17\x4f\xdf\xd5\xd3\x77\x71\x48\xb0\x2d\xab\x56\xc2\x76\x07\x4c\x93\xd9\x79\xdb\xd4\xba\x66\x42\xb7\x24\xb7\xcc\xbd\xd3\x37\x1f\x3e\xb8\xad\xdf\x8e\x7e\x58\xd6\xbe\x8b\x0d\x63\xae\xe5\x75\xc9\x0b\x33\x69\xe7\xef\x36\xde\xa6\xb5\xfd\x0a\xc5\x9d\x29\xe1\x9f\x70\xd4\x4f\xf7\xed\x2d\xdf\xde\xb2\x39\x80\xe3\x1f\xf0\xf7\x53\xe7\xed\xdb\xd1\x8f\x93\x77\x7c\xbf\xdb\xff\x2e\x0d\x47\xdb\x10\xdb\x66\xa5\xc6\x6f\x8c\xa4\x57\x61\xb9\x81\x38\xb1\x01\xec\xf7\x46\x75\xa3\xcb\x56\x77\xbd\xc8\x8f\x5b\x9d\xbb\x83\x76\x77\xbb\xf4\x86\xc3\x7e\xe9\x31\x68\xdc\xbd\x68\x17\x56\xad\xd9\xa3\x6e\x27\xb6\x1b\xca\x4c\x1b\x98\xd4\x52\x6b\xbe\xac\x1e\xa1\x66\x8a\x3e\x19\xf6\x2d\x4d\x23\xa0\xc2\x57\xf8\x5e\x59\xc8\x49\x57\x99\x4e\x64\xbb\x92\x1f\x10\x6e\x23\xd1\xf7\xbc\x06\xa4\x61\xec\x2a\xb2\xe9\xb4\x9d\x33\xfc\xe9\xc9\xee\x1a\xa8\x01\xfa\xee\xeb\x67\x27\x31\x32\xe9\x8e\x11\x4b\x04\x5a\xba\xfb\xf1\xb1\xbf\x3f\x9c\x7b\xf6\xb8\x42\xf7\xa9\x5a\xf2\xbb\xf2\x60\xcd\x0c\x2a\x58\x31\x75\x4f\x37\x26\x85\x2c\x2b\xe9\x83\x3a\x47\xa2\x8b\xd0\x51\x43\x23\xe8\xaa\xec\x0e\xf6\x9f\x06\x0c\xcf\xee\x37\x80\xf6\xa6\x8d\x55\xd1\x32\x70\xb2\x59\xd0\x68\xa2\xd5\x0a\x73\xfa\x9c\x9e\x6c\x6a\x35\x8c\x05\xac\xe1\x1b\x72\x18\x94\xb2\xc7\x7c\x1e\x3c\xbb\x1b\xc8\x8e\xe1\x3c\x02\x6b\x36\x79\x57\x49\x45\xd5\xe8\x72\x28\xa2\x5e\x34\xaf\x34\xba\x63\xd8\x78\x70\xb4\x25\x57\xfb\x9d\x8d\xd0\x9d\x34\x9f\x3f\x93\xf9\x1b\xae\xbb\x3a\x0d\xbd\xbb\x92\x6d\xb9\xe8\x6f\x8f\xdb\x67\xd5\x87\x0f\x2f\x0e\xaf\x5f\x4e\x77\x19\x6e\xdd\xd1\xdb\x44\x76\x79\xe9\x47\xed\xf6\x59\xdc\xdd\x11\xed\x8c\x7e\x15\x45\xe7\x83\x6e\x07\xf6\x7f\x51\x4a\xd9\x54\x39\xdd\x32\x49\x25\x2b\xa9\x0d\x64\x72\xb5\xa2\x8b\x32\xd3\xe8\x01\xf7\xd1\x87\x35\x8e\x15\xb6\xb7\x44\x26\x9c\x40\xed\x35\x9c\x6e\x15\xed\xa1\x39\x8c\x9c\xc2\xdd\x0a\xe3\xaf\xe4\xb5\xf9\x06\xf9\x5f\x00\x00\x00\xff\xff\xbb\x06\x82\x6d\x66\x12\x00\x00")

func bylineJsBytes() ([]byte, error) {
	return bindataRead(
		_bylineJs,
		"byline.js",
	)
}

func bylineJs() (*asset, error) {
	bytes, err := bylineJsBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "byline.js", size: 4710, mode: os.FileMode(420), modTime: time.Unix(1554191268, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _indexJs = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x8c\x54\x5d\x6f\xe4\x34\x14\x7d\xcf\xaf\x38\xbb\x52\x95\xa4\x9b\x66\xda\xa2\xbe\x4c\x95\x07\xa0\x85\x2d\x82\x5d\xa4\x82\x78\x28\x65\xd7\xb1\xef\x64\x0c\x19\x3b\xd8\xce\xcc\x44\xa5\xff\x1d\x5d\x27\xf3\xb1\xa8\x2c\x3c\xcd\xc4\x3e\xbe\xf7\x9c\xe3\xe3\x9b\xac\x85\x83\x5c\xea\x56\xa1\x82\xa3\x3f\x7b\xed\x28\x4b\xe3\xc2\x87\xce\x59\x49\xde\xa7\xf9\x75\x44\xd5\x43\xab\x0d\x1d\xc3\xca\xd9\xb8\xc6\x88\x64\x76\x7a\x9a\xe0\x14\x37\x54\xf7\x0d\xc8\xac\xb1\x16\xae\x4c\x70\x3a\x4b\x12\x69\x8d\x0f\x50\x71\xa7\xc2\x54\xb6\x24\xb3\x2e\x6f\x6e\xbf\xfa\xf9\xdb\x0f\xf7\x6f\xef\x7e\x38\x54\xf8\x12\x2b\xd1\xc1\x2e\xe0\x83\xd3\xa6\xc9\xb4\xca\x11\x2c\xa4\x68\xdb\x5a\xc8\x3f\xb0\xe8\x8d\x0c\xda\x9a\x02\xbd\x27\x85\x85\x75\xd8\x2c\xc9\xf0\xd1\x95\x30\x03\xa4\x35\xb2\x77\x8e\x4c\x88\x4c\xc9\x07\x0f\xe1\x08\xb6\x0f\x3e\x08\xa3\xb4\x69\x26\x5e\x51\xfb\x54\xd6\xa3\xc2\xd3\xf3\x81\xc5\x4f\x4b\x42\x2b\x7c\x80\x56\x10\x21\x08\xb9\x24\xc5\x34\xc4\xae\x28\x66\x07\x4a\x9d\xd0\xee\x50\x92\x8f\xdd\xb1\x9f\xd9\x8d\x08\x54\x1a\xbb\xc9\x72\xcc\x70\x71\x7e\x7e\x9e\xe3\x2f\x9c\x1f\x9a\x18\xda\x32\xb2\x21\x43\x4e\x04\xf2\xd0\xca\x63\xb3\xd4\x72\x89\x8d\x6e\x5b\x58\xd3\x0e\xa8\x09\x8e\x3a\x12\x81\x14\x68\x4d\x6e\xc0\xe5\x6f\x57\x97\x08\x7a\x45\x1e\x35\x69\xd3\xec\x0b\xa8\x91\xc4\xce\xa1\xa9\x7e\x96\x3f\x25\xc0\x6c\x86\x1f\x1d\xad\xd9\x96\xba\x6f\xb8\x0d\x39\x82\x36\x81\x1a\x72\xe8\x1c\x49\xed\xf9\xcc\xc6\x89\x8e\x0d\xb3\xbd\x51\xb0\x06\x8b\xd6\x8a\xc0\x4d\x3a\xab\x4d\x80\xe9\x57\x35\x39\x3f\x16\xcc\x7a\xdf\x8b\xb6\x1d\x76\xf0\xab\xcb\xb3\xab\x2f\x50\xeb\xe0\xf3\x04\x1c\x00\x76\xaf\x42\x36\x39\xf2\x06\x17\x93\x01\x80\x5e\x20\xe3\xcd\xaa\x9a\xfc\xca\xc1\x2c\x31\x9e\xb8\x60\xc8\x73\x82\x83\x97\x5a\xf1\x92\xa3\xd0\x3b\x83\xfb\x7d\x32\xae\x93\xe7\xbd\x9b\x5f\xc7\x18\x4f\xf1\x8a\xb9\xa8\xb5\x11\x6e\xc0\xdd\xec\xfd\xd1\x8d\x33\x00\xd5\x18\xfa\xd2\x77\x62\x63\x38\xc9\x2b\xa1\x4d\x5a\xe0\x09\x3e\x28\x6d\xe7\x78\x48\x3b\xdd\x51\x5a\x60\xf7\xbb\x8b\xad\x0f\x8a\x9c\x7b\xc4\x33\x87\x9e\x17\x4b\x6b\xb2\x94\x9c\xb3\x2e\x2d\xf6\xe1\xcc\xc8\xb9\x68\x3b\x67\xdf\xb6\x54\x46\x40\x96\x3e\xf8\xa5\x5e\x3d\x22\x7e\xcd\x71\xe2\xd3\x82\xff\xe7\xac\x6d\xff\x2e\xb6\x3a\x64\x17\xac\x2c\x3f\x6e\xb0\xd5\xe1\xb8\xbe\xb4\x8a\x0a\x78\xdd\x18\xd1\x7e\xae\xd1\x56\x87\x39\x18\x5c\x9d\xf8\x09\x5e\xc5\xb6\x9f\x14\xf8\xd7\xfe\x93\xb5\xef\x68\xc3\x0f\xfd\x4c\x51\xab\x57\x9a\x93\xf8\xdd\xfd\xfb\x77\xec\x95\xed\xc3\x91\xb7\xb6\x0f\xa8\xa6\x49\x91\x45\xee\x23\x24\x4f\x12\x06\xb2\x10\x25\x82\x38\x16\xc2\xd0\x28\x80\x13\x11\x67\x44\xbe\xd7\xd2\xda\x66\xaf\xa4\x13\xce\x6b\xd3\xcc\xf1\xf1\xc4\x7f\x4c\x0b\xc4\x73\xc9\x14\xb3\x95\x6f\x58\x42\x70\xc3\x94\xa2\x95\xe7\x51\xc3\x24\x4b\x3e\x48\x63\x9b\x98\x2a\x48\x11\xe4\x12\xf1\x86\x26\xf4\x4b\xfd\x7a\x43\xdb\x8e\x24\x6b\x35\xd6\x9c\xfd\xee\xad\x89\x3d\x3f\x25\x70\x1d\xcf\x8f\xb1\x8c\x91\x9d\x84\x84\xa1\x23\xbb\x60\x1a\xa5\x56\x78\x55\x55\x48\xc7\x71\x96\xfe\xcf\x9e\x71\xd6\x9e\x41\x59\x18\x1b\x78\xd2\x4d\x66\xff\x77\xfb\x71\xda\xc6\x88\xef\x66\xdb\xc3\xc8\xe3\x91\xe1\x8a\x5a\x0a\xf4\xd2\xde\x44\xfd\x95\xdc\x3f\xc5\xcf\xdf\xc8\x11\x5b\xd5\x77\xad\x96\x22\xf0\xa8\xf2\x9d\x35\xfe\x1f\x36\xbd\x44\x33\xe3\xc6\x31\xad\x45\xf4\x69\x2d\xda\x9e\x62\xec\xae\x93\x7d\xf0\xde\x0a\xa3\x5a\x42\x9c\x5b\x7e\x0c\x1a\x6d\x3b\xeb\x82\x2f\x97\xe3\x56\x75\xf4\xe6\x18\x55\x40\x86\x6d\x01\x59\x8f\x2a\x64\xd8\x96\x3b\xad\xbf\x08\x1d\xfc\x37\xd6\xdd\xae\xba\x30\xdc\x32\xf8\x7b\x6b\x3b\xae\x20\x5a\x4f\xd7\x07\xf3\xe2\x0c\xda\x0d\x4f\x36\xed\xe0\x96\x56\x8f\xec\x6c\x1d\xd1\xbb\x84\x6b\x53\x6e\x9c\x0e\x94\xc5\xc0\x8d\x17\xad\x17\x43\x36\xda\xf8\x5a\xab\xd7\x73\x68\x55\x8c\x5f\x91\xe5\xeb\xf9\xa8\x69\x5a\x93\xd6\x04\xda\xf2\xaa\x0c\x5b\x76\x28\x7f\x93\xfe\x6a\xd2\x38\xde\xfe\x0e\x00\x00\xff\xff\x8f\x23\x4e\xfc\xa3\x07\x00\x00")

func indexJsBytes() ([]byte, error) {
	return bindataRead(
		_indexJs,
		"index.js",
	)
}

func indexJs() (*asset, error) {
	bytes, err := indexJsBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "index.js", size: 1955, mode: os.FileMode(420), modTime: time.Unix(1554191268, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _shimGo = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x4c\xcc\xb1\x11\xc2\x30\x0c\x85\xe1\xde\x53\xbc\x05\x12\xf7\xcc\x40\xc1\x0a\xcf\x58\x08\x5f\x88\xe4\x93\x1d\xee\xd8\x9e\x22\x4d\xca\xff\x2f\xbe\x9c\xd5\x6f\x2a\x26\xc1\x29\x50\x5f\x4a\xb3\xca\x49\x2c\x7d\x53\x8c\x77\xdb\xb1\xa6\x94\x33\x1e\x7c\x6e\x54\x39\x57\x0f\xff\xb6\x2a\x03\x3c\xfb\xe5\x81\x38\xcc\x9a\x29\x18\xa5\xcd\x60\xfc\xf0\xa1\xe9\x41\x95\x01\x37\xdc\xb9\x97\xca\x35\xf5\x8b\x93\xfe\x01\x00\x00\xff\xff\xb4\x05\x8d\x5f\x7e\x00\x00\x00")

func shimGoBytes() ([]byte, error) {
	return bindataRead(
		_shimGo,
		"shim.go",
	)
}

func shimGo() (*asset, error) {
	bytes, err := shimGoBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "shim.go", size: 126, mode: os.FileMode(420), modTime: time.Unix(1554191268, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"bindata.go": bindataGo,
	"byline.js": bylineJs,
	"index.js": indexJs,
	"shim.go": shimGo,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}
var _bintree = &bintree{nil, map[string]*bintree{
	"bindata.go": &bintree{bindataGo, map[string]*bintree{}},
	"byline.js": &bintree{bylineJs, map[string]*bintree{}},
	"index.js": &bintree{indexJs, map[string]*bintree{}},
	"shim.go": &bintree{shimGo, map[string]*bintree{}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}

