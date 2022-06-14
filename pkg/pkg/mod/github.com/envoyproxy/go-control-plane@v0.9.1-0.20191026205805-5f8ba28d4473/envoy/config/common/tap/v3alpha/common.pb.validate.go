// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/config/common/tap/v3alpha/common.proto

package envoy_config_common_tap_v3alpha

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
var _common_uuidPattern = regexp.MustCompile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

// Validate checks the field values on CommonExtensionConfig with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *CommonExtensionConfig) Validate() error {
	if m == nil {
		return nil
	}

	switch m.ConfigType.(type) {

	case *CommonExtensionConfig_AdminConfig:

		if v, ok := interface{}(m.GetAdminConfig()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return CommonExtensionConfigValidationError{
					field:  "AdminConfig",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	case *CommonExtensionConfig_StaticConfig:

		if v, ok := interface{}(m.GetStaticConfig()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return CommonExtensionConfigValidationError{
					field:  "StaticConfig",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	case *CommonExtensionConfig_TapdsConfig:

		if v, ok := interface{}(m.GetTapdsConfig()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return CommonExtensionConfigValidationError{
					field:  "TapdsConfig",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	default:
		return CommonExtensionConfigValidationError{
			field:  "ConfigType",
			reason: "value is required",
		}

	}

	return nil
}

// CommonExtensionConfigValidationError is the validation error returned by
// CommonExtensionConfig.Validate if the designated constraints aren't met.
type CommonExtensionConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e CommonExtensionConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e CommonExtensionConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e CommonExtensionConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e CommonExtensionConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e CommonExtensionConfigValidationError) ErrorName() string {
	return "CommonExtensionConfigValidationError"
}

// Error satisfies the builtin error interface
func (e CommonExtensionConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCommonExtensionConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = CommonExtensionConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = CommonExtensionConfigValidationError{}

// Validate checks the field values on AdminConfig with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned.
func (m *AdminConfig) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetConfigId()) < 1 {
		return AdminConfigValidationError{
			field:  "ConfigId",
			reason: "value length must be at least 1 bytes",
		}
	}

	return nil
}

// AdminConfigValidationError is the validation error returned by
// AdminConfig.Validate if the designated constraints aren't met.
type AdminConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e AdminConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e AdminConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e AdminConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e AdminConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e AdminConfigValidationError) ErrorName() string { return "AdminConfigValidationError" }

// Error satisfies the builtin error interface
func (e AdminConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sAdminConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = AdminConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = AdminConfigValidationError{}

// Validate checks the field values on CommonExtensionConfig_TapDSConfig with
// the rules defined in the proto definition for this message. If any rules
// are violated, an error is returned.
func (m *CommonExtensionConfig_TapDSConfig) Validate() error {
	if m == nil {
		return nil
	}

	if m.GetConfigSource() == nil {
		return CommonExtensionConfig_TapDSConfigValidationError{
			field:  "ConfigSource",
			reason: "value is required",
		}
	}

	if v, ok := interface{}(m.GetConfigSource()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return CommonExtensionConfig_TapDSConfigValidationError{
				field:  "ConfigSource",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(m.GetName()) < 1 {
		return CommonExtensionConfig_TapDSConfigValidationError{
			field:  "Name",
			reason: "value length must be at least 1 bytes",
		}
	}

	return nil
}

// CommonExtensionConfig_TapDSConfigValidationError is the validation error
// returned by CommonExtensionConfig_TapDSConfig.Validate if the designated
// constraints aren't met.
type CommonExtensionConfig_TapDSConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e CommonExtensionConfig_TapDSConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e CommonExtensionConfig_TapDSConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e CommonExtensionConfig_TapDSConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e CommonExtensionConfig_TapDSConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e CommonExtensionConfig_TapDSConfigValidationError) ErrorName() string {
	return "CommonExtensionConfig_TapDSConfigValidationError"
}

// Error satisfies the builtin error interface
func (e CommonExtensionConfig_TapDSConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCommonExtensionConfig_TapDSConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = CommonExtensionConfig_TapDSConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = CommonExtensionConfig_TapDSConfigValidationError{}
