// Code generated by smithy-go-codegen DO NOT EDIT.

package route53

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Disassociates an Amazon Virtual Private Cloud (Amazon VPC) from an Amazon Route
// 53 private hosted zone. Note the following:
//
// * You can't disassociate the last
// Amazon VPC from a private hosted zone.
//
// * You can't convert a private hosted
// zone into a public hosted zone.
//
// * You can submit a
// DisassociateVPCFromHostedZone request using either the account that created the
// hosted zone or the account that created the Amazon VPC.
//
// * Some services, such
// as AWS Cloud Map and Amazon Elastic File System (Amazon EFS) automatically
// create hosted zones and associate VPCs with the hosted zones. A service can
// create a hosted zone using your account or using its own account. You can
// disassociate a VPC from a hosted zone only if the service created the hosted
// zone using your account. When you run DisassociateVPCFromHostedZone
// (https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListHostedZonesByVPC.html),
// if the hosted zone has a value for OwningAccount, you can use
// DisassociateVPCFromHostedZone. If the hosted zone has a value for OwningService,
// you can't use DisassociateVPCFromHostedZone.
func (c *Client) DisassociateVPCFromHostedZone(ctx context.Context, params *DisassociateVPCFromHostedZoneInput, optFns ...func(*Options)) (*DisassociateVPCFromHostedZoneOutput, error) {
	if params == nil {
		params = &DisassociateVPCFromHostedZoneInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DisassociateVPCFromHostedZone", params, optFns, addOperationDisassociateVPCFromHostedZoneMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DisassociateVPCFromHostedZoneOutput)
	out.ResultMetadata = metadata
	return out, nil
}

// A complex type that contains information about the VPC that you want to
// disassociate from a specified private hosted zone.
type DisassociateVPCFromHostedZoneInput struct {

	// The ID of the private hosted zone that you want to disassociate a VPC from.
	//
	// This member is required.
	HostedZoneId *string

	// A complex type that contains information about the VPC that you're
	// disassociating from the specified hosted zone.
	//
	// This member is required.
	VPC *types.VPC

	// Optional: A comment about the disassociation request.
	Comment *string
}

// A complex type that contains the response information for the disassociate
// request.
type DisassociateVPCFromHostedZoneOutput struct {

	// A complex type that describes the changes made to the specified private hosted
	// zone.
	//
	// This member is required.
	ChangeInfo *types.ChangeInfo

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata
}

func addOperationDisassociateVPCFromHostedZoneMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsRestxml_serializeOpDisassociateVPCFromHostedZone{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsRestxml_deserializeOpDisassociateVPCFromHostedZone{}, middleware.After)
	if err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddClientRequestIDMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddComputeContentLengthMiddleware(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = v4.AddComputePayloadSHA256Middleware(stack); err != nil {
		return err
	}
	if err = addRetryMiddlewares(stack, options); err != nil {
		return err
	}
	if err = addHTTPSignerV4Middleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = awsmiddleware.AddRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addOpDisassociateVPCFromHostedZoneValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDisassociateVPCFromHostedZone(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addSanitizeURLMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	return nil
}

func newServiceMetadataMiddleware_opDisassociateVPCFromHostedZone(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "route53",
		OperationName: "DisassociateVPCFromHostedZone",
	}
}
