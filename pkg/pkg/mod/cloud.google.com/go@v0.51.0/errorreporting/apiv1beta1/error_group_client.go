// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go_gapic. DO NOT EDIT.

package errorreporting

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"time"

	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/api/option"
	"google.golang.org/api/transport"
	clouderrorreportingpb "google.golang.org/genproto/googleapis/devtools/clouderrorreporting/v1beta1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

// ErrorGroupCallOptions contains the retry settings for each method of ErrorGroupClient.
type ErrorGroupCallOptions struct {
	GetGroup    []gax.CallOption
	UpdateGroup []gax.CallOption
}

func defaultErrorGroupClientOptions() []option.ClientOption {
	return []option.ClientOption{
		option.WithEndpoint("clouderrorreporting.googleapis.com:443"),
		option.WithGRPCDialOption(grpc.WithDisableServiceConfig()),
		option.WithScopes(DefaultAuthScopes()...),
		option.WithGRPCDialOption(grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(math.MaxInt32))),
	}
}

func defaultErrorGroupCallOptions() *ErrorGroupCallOptions {
	return &ErrorGroupCallOptions{
		GetGroup: []gax.CallOption{
			gax.WithRetry(func() gax.Retryer {
				return gax.OnCodes([]codes.Code{
					codes.Unavailable,
					codes.DeadlineExceeded,
				}, gax.Backoff{
					Initial:    100 * time.Millisecond,
					Max:        60000 * time.Millisecond,
					Multiplier: 1.30,
				})
			}),
		},
		UpdateGroup: []gax.CallOption{
			gax.WithRetry(func() gax.Retryer {
				return gax.OnCodes([]codes.Code{
					codes.Unavailable,
					codes.DeadlineExceeded,
				}, gax.Backoff{
					Initial:    100 * time.Millisecond,
					Max:        60000 * time.Millisecond,
					Multiplier: 1.30,
				})
			}),
		},
	}
}

// ErrorGroupClient is a client for interacting with Stackdriver Error Reporting API.
//
// Methods, except Close, may be called concurrently. However, fields must not be modified concurrently with method calls.
type ErrorGroupClient struct {
	// The connection to the service.
	conn *grpc.ClientConn

	// The gRPC API client.
	errorGroupClient clouderrorreportingpb.ErrorGroupServiceClient

	// The call options for this service.
	CallOptions *ErrorGroupCallOptions

	// The x-goog-* metadata to be sent with each request.
	xGoogMetadata metadata.MD
}

// NewErrorGroupClient creates a new error group service client.
//
// Service for retrieving and updating individual error groups.
func NewErrorGroupClient(ctx context.Context, opts ...option.ClientOption) (*ErrorGroupClient, error) {
	conn, err := transport.DialGRPC(ctx, append(defaultErrorGroupClientOptions(), opts...)...)
	if err != nil {
		return nil, err
	}
	c := &ErrorGroupClient{
		conn:        conn,
		CallOptions: defaultErrorGroupCallOptions(),

		errorGroupClient: clouderrorreportingpb.NewErrorGroupServiceClient(conn),
	}
	c.SetGoogleClientInfo()

	return c, nil
}

// Connection returns the client's connection to the API service.
func (c *ErrorGroupClient) Connection() *grpc.ClientConn {
	return c.conn
}

// Close closes the connection to the API service. The user should invoke this when
// the client is no longer required.
func (c *ErrorGroupClient) Close() error {
	return c.conn.Close()
}

// SetGoogleClientInfo sets the name and version of the application in
// the `x-goog-api-client` header passed on each request. Intended for
// use by Google-written clients.
func (c *ErrorGroupClient) SetGoogleClientInfo(keyval ...string) {
	kv := append([]string{"gl-go", versionGo()}, keyval...)
	kv = append(kv, "gapic", versionClient, "gax", gax.Version, "grpc", grpc.Version)
	c.xGoogMetadata = metadata.Pairs("x-goog-api-client", gax.XGoogHeader(kv...))
}

// GetGroup get the specified group.
func (c *ErrorGroupClient) GetGroup(ctx context.Context, req *clouderrorreportingpb.GetGroupRequest, opts ...gax.CallOption) (*clouderrorreportingpb.ErrorGroup, error) {
	md := metadata.Pairs("x-goog-request-params", fmt.Sprintf("%s=%v", "group_name", url.QueryEscape(req.GetGroupName())))
	ctx = insertMetadata(ctx, c.xGoogMetadata, md)
	opts = append(c.CallOptions.GetGroup[0:len(c.CallOptions.GetGroup):len(c.CallOptions.GetGroup)], opts...)
	var resp *clouderrorreportingpb.ErrorGroup
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.errorGroupClient.GetGroup(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// UpdateGroup replace the data for the specified group.
// Fails if the group does not exist.
func (c *ErrorGroupClient) UpdateGroup(ctx context.Context, req *clouderrorreportingpb.UpdateGroupRequest, opts ...gax.CallOption) (*clouderrorreportingpb.ErrorGroup, error) {
	md := metadata.Pairs("x-goog-request-params", fmt.Sprintf("%s=%v", "group.name", url.QueryEscape(req.GetGroup().GetName())))
	ctx = insertMetadata(ctx, c.xGoogMetadata, md)
	opts = append(c.CallOptions.UpdateGroup[0:len(c.CallOptions.UpdateGroup):len(c.CallOptions.UpdateGroup)], opts...)
	var resp *clouderrorreportingpb.ErrorGroup
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.errorGroupClient.UpdateGroup(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
