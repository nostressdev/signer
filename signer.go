package signer

import (
	"context"
	"fmt"
	"github.com/nostressdev/nerrors"
	"google.golang.org/grpc/metadata"
)

const AccessToken = "access_token"

var ErrNoMetadata = fmt.Errorf("no metadata")
var ErrNoPayload = fmt.Errorf("no payload")

type Signer struct {
	TokenProvider
	AccessRulesProvider
}

func NewSignerJWT(config TokenProviderConfig) *Signer {
	return &Signer{
		TokenProvider:       NewTokenProviderJWT(config),
		AccessRulesProvider: NewAccessRulesProviderJSON(),
	}
}

func (signer *Signer) SignContext(ctx context.Context, payload TokenPayload, rules TokenAccessRules) (context.Context, error) {
	token, err := signer.CreateToken(payload, rules)
	if err != nil {
		return nil, nerrors.GetType(err).Wrap(err, "signing context")
	}
	return metadata.AppendToOutgoingContext(ctx,
		AccessToken, token,
	), nil
}

func (signer *Signer) VerifyContext(ctx context.Context, rule string) (TokenPayload, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		md, ok = metadata.FromOutgoingContext(ctx)
	}
	if !ok {
		return nil, nerrors.Validation.Wrap(ErrNoMetadata, "verify context")
	}
	payloads := md.Get(AccessToken)
	if len(payloads) == 0 || len(payloads[0]) == 0 {
		return nil, nerrors.Validation.Wrap(ErrNoPayload, "verify context")
	}
	payload := payloads[0]
	payloadClaims, accessRules, err := signer.VerifyToken(payload)
	if err != nil {
		return nil, err
	}
	if err := signer.CheckAccessRules(accessRules, rule); err != nil {
		return nil, nerrors.GetType(err).Wrap(err, "verify context")
	}
	return payloadClaims, nil
}
