package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/xmtp/xmtpd/pkg/gateway"
)

const (
	worldChatAuthEnabledEnv    = "WORLD_CHAT_GATEWAY_AUTH_ENABLED"
	worldChatAuthModeEnv       = "WORLD_CHAT_GATEWAY_AUTH_MODE"
	worldChatJWTIssuerEnv      = "WORLD_CHAT_GATEWAY_AUTH_ISSUER"
	worldChatJWTIssuedAfterEnv = "WORLD_CHAT_GATEWAY_AUTH_ISSUED_AFTER"
	worldChatJWTKidEnv         = "WORLD_CHAT_GATEWAY_AUTH_KID"
	worldChatJWTPublicKeyEnv   = "WORLD_CHAT_GATEWAY_AUTH_PUBLIC_KEY_PEM"
	xmtpdContractsEnv          = "XMTPD_CONTRACTS_ENVIRONMENT"

	defaultWorldChatJWTIssuerProd  = "chat.toolsforhumanity.com"
	defaultWorldChatJWTIssuerStage = "chat-staging.toolsforhumanity.com"
	defaultWorldChatJWTIssuedAfter = "2025-12-07T00:00:00Z"
	jwtClockSkew                   = 60 * time.Second
)

type worldChatAuthMode string

const (
	worldChatAuthModeDisabled   worldChatAuthMode = "disabled"
	worldChatAuthModeReportOnly worldChatAuthMode = "report_only"
	worldChatAuthModeEnforce    worldChatAuthMode = "enforce"
)

var (
	errMissingAuthorizationHeader = errors.New("missing authorization header")
	errInvalidAuthorizationHeader = errors.New("invalid authorization header")
	errInvalidTokenHeader         = errors.New("invalid token header")
	errMissingRequiredClaim       = errors.New("missing required claim")
	errIssuedBeforeCutoff         = errors.New("token issued before cutoff")
)

type worldChatTokenValidator struct {
	expectedIssuer string
	expectedKid    string
	publicKey      *ecdsa.PublicKey
	issuedAfter    *time.Time
}

type worldChatAuthConfig struct {
	mode      worldChatAuthMode
	validator *worldChatTokenValidator
}

func newWorldChatPublishAuthorizerFromEnv() (gateway.AuthorizePublishFn, error) {
	config, err := loadWorldChatAuthConfigFromEnv()
	if err != nil {
		return nil, err
	}

	return config.authorizePublish, nil
}

func loadWorldChatAuthConfigFromEnv() (*worldChatAuthConfig, error) {
	mode, err := loadWorldChatAuthModeFromEnv()
	if err != nil {
		return nil, err
	}

	if !mode.enabled() {
		return &worldChatAuthConfig{mode: mode}, nil
	}

	expectedKid := strings.TrimSpace(os.Getenv(worldChatJWTKidEnv))
	if expectedKid == "" {
		return nil, fmt.Errorf("%s must be set when %s=%s", worldChatJWTKidEnv, worldChatAuthModeEnv, mode)
	}

	publicKeyPEM := strings.TrimSpace(os.Getenv(worldChatJWTPublicKeyEnv))
	if publicKeyPEM == "" {
		return nil, fmt.Errorf("%s must be set when %s=%s", worldChatJWTPublicKeyEnv, worldChatAuthModeEnv, mode)
	}

	publicKey, err := jwt.ParseECPublicKeyFromPEM([]byte(normalizePEM(publicKeyPEM)))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", worldChatJWTPublicKeyEnv, err)
	}

	issuedAfter, err := loadIssuedAfterCutoff()
	if err != nil {
		return nil, err
	}

	issuer := defaultWorldChatJWTIssuer()
	if configuredIssuer := strings.TrimSpace(os.Getenv(worldChatJWTIssuerEnv)); configuredIssuer != "" {
		issuer = configuredIssuer
	}

	return &worldChatAuthConfig{
		mode: mode,
		validator: &worldChatTokenValidator{
			expectedIssuer: issuer,
			expectedKid:    expectedKid,
			publicKey:      publicKey,
			issuedAfter:    issuedAfter,
		},
	}, nil
}

func (c *worldChatAuthConfig) authorizePublish(
	ctx context.Context,
	_ gateway.Identity,
	_ gateway.PublishRequestSummary,
) (bool, error) {
	if !c.mode.enabled() {
		return true, nil
	}

	if _, err := c.validator.validateAuthorizationHeader(gateway.AuthorizationHeaderFromContext(ctx)); err != nil {
		log.Printf("world chat gateway auth mode=%s validation failed: %v", c.mode, err)
		if c.mode == worldChatAuthModeReportOnly {
			return true, nil
		}
		return false, nil
	}

	return true, nil
}

func loadWorldChatAuthModeFromEnv() (worldChatAuthMode, error) {
	if value := strings.TrimSpace(os.Getenv(worldChatAuthModeEnv)); value != "" {
		switch normalizeAuthMode(value) {
		case worldChatAuthModeDisabled:
			return worldChatAuthModeDisabled, nil
		case worldChatAuthModeReportOnly:
			return worldChatAuthModeReportOnly, nil
		case worldChatAuthModeEnforce:
			return worldChatAuthModeEnforce, nil
		default:
			return "", fmt.Errorf("%s must be one of disabled, report_only, enforce", worldChatAuthModeEnv)
		}
	}

	if parseBoolEnv(worldChatAuthEnabledEnv) {
		return worldChatAuthModeEnforce, nil
	}

	return worldChatAuthModeDisabled, nil
}

func normalizeAuthMode(value string) worldChatAuthMode {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", "_")) {
	case string(worldChatAuthModeDisabled):
		return worldChatAuthModeDisabled
	case string(worldChatAuthModeReportOnly), "reportonly":
		return worldChatAuthModeReportOnly
	case string(worldChatAuthModeEnforce):
		return worldChatAuthModeEnforce
	default:
		return worldChatAuthMode("")
	}
}

func (m worldChatAuthMode) enabled() bool {
	return m != worldChatAuthModeDisabled
}

func (v *worldChatTokenValidator) validateAuthorizationHeader(header string) (*jwt.RegisteredClaims, error) {
	token, err := bearerTokenFromHeader(header)
	if err != nil {
		return nil, err
	}

	return v.validateToken(token)
}

func (v *worldChatTokenValidator) validateToken(tokenString string) (*jwt.RegisteredClaims, error) {
	claims := &jwt.RegisteredClaims{}
	parser := jwt.NewParser(
		jwt.WithIssuer(v.expectedIssuer),
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(jwtClockSkew),
	)

	token, err := parser.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Header["typ"] != "JWT" {
			return nil, errInvalidTokenHeader
		}

		kid, ok := token.Header["kid"].(string)
		if !ok || kid != v.expectedKid {
			return nil, errInvalidTokenHeader
		}

		return v.publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}

	if claims.Subject == "" || claims.IssuedAt == nil || claims.ExpiresAt == nil || claims.NotBefore == nil {
		return nil, errMissingRequiredClaim
	}

	if v.issuedAfter != nil && claims.IssuedAt.Time.Before(*v.issuedAfter) {
		return nil, errIssuedBeforeCutoff
	}

	return claims, nil
}

func bearerTokenFromHeader(header string) (string, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", errMissingAuthorizationHeader
	}

	if len(header) >= len("Bearer ") && strings.EqualFold(header[:len("Bearer ")], "Bearer ") {
		token := strings.TrimSpace(header[len("Bearer "):])
		if token == "" {
			return "", errInvalidAuthorizationHeader
		}
		return token, nil
	}

	return header, nil
}

func loadIssuedAfterCutoff() (*time.Time, error) {
	value, ok := os.LookupEnv(worldChatJWTIssuedAfterEnv)
	if !ok {
		value = defaultWorldChatJWTIssuedAfter
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}

	issuedAfter, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", worldChatJWTIssuedAfterEnv, err)
	}

	return &issuedAfter, nil
}

func parseBoolEnv(key string) bool {
	value := strings.TrimSpace(os.Getenv(key))
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func defaultWorldChatJWTIssuer() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(xmtpdContractsEnv))) {
	case "testnet-staging", "staging", "stage", "testnet":
		return defaultWorldChatJWTIssuerStage
	default:
		return defaultWorldChatJWTIssuerProd
	}
}

func normalizePEM(pem string) string {
	return strings.ReplaceAll(pem, `\n`, "\n")
}
