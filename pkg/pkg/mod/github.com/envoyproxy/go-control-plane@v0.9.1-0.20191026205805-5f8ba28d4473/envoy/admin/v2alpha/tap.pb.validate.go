// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/admin/v2alpha/tap.proto

package envoy_admin_v2alpha

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang/protobuf/ptypes"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = ptypes.DynamicAny{}
)

// define the regex for a UUID once up-front
var _tap_uuidPattern = regexp.MustCompile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

// Validate checks the field values on TapRequest with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *TapRequest) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetConfigId()) < 1 {
		return TapRequestValidationError{
			field:  "ConfigId",
			reason: "value length must be at least 1 bytes",
		}
	}

	if m.GetTapConfig() == nil {
		return TapRequestValidationError{
			field:  "TapConfig",
			reason: "value is required",
		}
	}

	if v, ok := interface{}(m.GetTapConfig()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return TapRequestValidationError{
				field:  "TapConfig",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	return nil
}

// TapRequestValidationError is the validation error returned by
// TapRequest.Validate if the designated constraints aren't met.
type TapRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e TapRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e TapRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e TapRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e TapRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e TapRequestValidationError) ErrorName() string { return "TapRequestValidationError" }

// Error satisfies the builtin error interface
func (e TapRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sTapRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = TapRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = TapRequestValidationError{}
