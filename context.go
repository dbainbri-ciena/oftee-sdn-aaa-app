package main

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Structure to help capture information around an OF message, such
// as the DPID and the port on which the message was received.
type OpenFlowContext struct {
	DatapathID uint64
	Port       uint32
}

// Prety print the context
func (c *OpenFlowContext) String() string {
	return fmt.Sprintf("[0x%016x, 0x%04x]", c.DatapathID, c.Port)
}

// Length of the context, in bytes
func (c *OpenFlowContext) Len() uint64 {
	return 12
}

// Read a context from a byte stream reader
func (c *OpenFlowContext) ReadFrom(r io.Reader) (int, error) {
	buf := make([]byte, 12)
	n, err := r.Read(buf)
	if err != nil {
		return n, err
	}
	c.DatapathID = binary.BigEndian.Uint64(buf)
	c.Port = binary.BigEndian.Uint32(buf[8:])
	return n, err
}
