package signer

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/nostressdev/nerrors"
	"time"
)

const PropertyAccessTokenID = "token_id"
const PropertyExpiration = "exp"
const PropertyAccessRules = "access_rules"

type tokenProviderJWT struct {
	TokenProviderConfig
}

func NewTokenProviderJWT(config TokenProviderConfig) TokenProvider {
	return &tokenProviderJWT{
		TokenProviderConfig: config,
	}
}

func (tokenProvider *tokenProviderJWT) CreateToken(payload TokenPayload, rules TokenAccessRules) (string, error) {
	claims := jwt.MapClaims{}
	for key, value := range payload {
		claims[key] = value
	}
	claims[PropertyAccessTokenID] = uuid.New().String()
	claims[PropertyExpiration] = time.Now().Add(tokenProvider.Expiration).Unix()
	claims[PropertyAccessRules] = rules
	signedPayload, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(tokenProvider.SecretKey)
	if err != nil {
		return "", nerrors.Internal.Wrap(err, "sign token error")
	}
	return signedPayload, nil
}

func (tokenProvider *tokenProviderJWT) VerifyToken(tokenString string) (TokenPayload, TokenAccessRules, error) {
	parser := jwt.Parser{
		UseJSONNumber:        true,
		SkipClaimsValidation: false,
		ValidMethods:         nil,
	}
	token, err := parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, nerrors.Validation.Wrap(ErrInvalidPayloadSignature, "validating token")
		}
		return tokenProvider.SecretKey, nil
	})
	if err != nil {
		var validationError *jwt.ValidationError
		if errors.As(err, &validationError) {
			if (validationError.Errors & jwt.ValidationErrorExpired) > 0 {
				return nil, nil, nerrors.Validation.Wrap(ErrPayloadExpired, "validating token")
			}
			if (validationError.Errors & (jwt.ValidationErrorSignatureInvalid)) > 0 {
				return nil, nil, nerrors.Validation.Wrap(ErrInvalidPayloadSignature, "validating token")
			}
			return nil, nil, nerrors.Validation.Wrap(ErrInvalidPayload, "validating token")
		}
		return nil, nil, nerrors.Internal.Wrap(ErrUnknown, "validating token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid || claims.Valid() != nil {
		return nil, nil, nerrors.Validation.Wrap(ErrInvalidPayload, "validating token")
	}
	return TokenPayload(claims), claims[PropertyAccessRules], nil
}
