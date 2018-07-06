package main

import (
	"github.com/google/gopacket/layers"
	"layeh.com/radius"
)

const (
	EAPMessage radius.Type = 79
)

// Convert EAPCode to String
func EapCodeToString(code layers.EAPCode) string {
	switch code {
	case layers.EAPCodeRequest:
		return "EAPCodeRequest"
	case layers.EAPCodeResponse:
		return "EAPCodeResponse"
	case layers.EAPCodeSuccess:
		return "EAPCodeSuccess"
	case layers.EAPCodeFailure:
		return "EAPCodeFailure"
	}
	return "EAPCodeUNKNOWN"
}

// Convert EAPType to String
func EapTypeToString(t layers.EAPType) string {
	switch t {
	case layers.EAPTypeNone:
		return "EAPTypeNone"
	case layers.EAPTypeIdentity:
		return "EAPTypeIdentity"
	case layers.EAPTypeNotification:
		return "EAPTypeNotification"
	case layers.EAPTypeNACK:
		return "EAPTypeNACK"
	case layers.EAPTypeOTP:
		return "EAPTypeOTP"
	case layers.EAPTypeTokenCard:
		return "EAPTypeTokenCard"
	}
	return "EAPTypeUNKNOWN"
}
