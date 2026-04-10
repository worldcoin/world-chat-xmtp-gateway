package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/xmtp/xmtpd/pkg/gateway"
	"github.com/xmtp/xmtpd/pkg/proto/xmtpv4/envelopes"
	"github.com/xmtp/xmtpd/pkg/proto/xmtpv4/payer_api"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestWorldChatTokenValidatorValidateTokenAcceptsValidToken(t *testing.T) {
	t.Parallel()

	privateKey, validator := newTestValidator(t, time.Now().Add(-time.Hour))
	token := newTestToken(t, privateKey, validator.expectedKid, validator.expectedIssuer, time.Now())

	claims, err := validator.validateToken(token)
	if err != nil {
		t.Fatalf("validateToken() error = %v", err)
	}

	if claims.Subject != "push-id-123" {
		t.Fatalf("expected subject push-id-123, got %q", claims.Subject)
	}
}

func TestWorldChatTokenValidatorValidateAuthorizationHeaderRejectsMissingHeader(t *testing.T) {
	t.Parallel()

	_, validator := newTestValidator(t, time.Now().Add(-time.Hour))

	if _, err := validator.validateAuthorizationHeader(""); err == nil {
		t.Fatal("expected missing header to fail validation")
	}
}

func TestWorldChatTokenValidatorValidateTokenRejectsWrongKid(t *testing.T) {
	t.Parallel()

	privateKey, validator := newTestValidator(t, time.Now().Add(-time.Hour))
	token := newTestToken(t, privateKey, "wrong-kid", validator.expectedIssuer, time.Now())

	if _, err := validator.validateToken(token); err == nil {
		t.Fatal("expected wrong kid to fail validation")
	}
}

func TestWorldChatTokenValidatorValidateTokenRejectsWrongIssuer(t *testing.T) {
	t.Parallel()

	privateKey, validator := newTestValidator(t, time.Now().Add(-time.Hour))
	token := newTestToken(t, privateKey, validator.expectedKid, "wrong-issuer", time.Now())

	if _, err := validator.validateToken(token); err == nil {
		t.Fatal("expected wrong issuer to fail validation")
	}
}

func TestWorldChatTokenValidatorValidateTokenRejectsIssuedBeforeCutoff(t *testing.T) {
	t.Parallel()

	cutoff := time.Now().Add(-30 * time.Minute)
	privateKey, validator := newTestValidator(t, cutoff)
	token := newTestToken(t, privateKey, validator.expectedKid, validator.expectedIssuer, cutoff.Add(-time.Hour))

	if _, err := validator.validateToken(token); err == nil {
		t.Fatal("expected token issued before cutoff to fail validation")
	}
}

func TestWorldChatTokenValidatorValidateTokenRejectsExpiredToken(t *testing.T) {
	t.Parallel()

	privateKey, validator := newTestValidator(t, time.Now().Add(-time.Hour))
	token := newExpiredTestToken(t, privateKey, validator.expectedKid, validator.expectedIssuer)

	if _, err := validator.validateToken(token); err == nil {
		t.Fatal("expected expired token to fail validation")
	}
}

func TestWorldChatAuthConfigAuthorizePublishAllowsWhenDisabled(t *testing.T) {
	t.Parallel()

	config := &worldChatAuthConfig{mode: worldChatAuthModeDisabled}
	allowed, err := config.authorizePublish(context.Background(), gateway.Identity{}, gateway.PublishRequestSummary{})
	if err != nil {
		t.Fatalf("authorizePublish() error = %v", err)
	}
	if !allowed {
		t.Fatal("expected disabled auth to allow publish")
	}
}

func TestWorldChatAuthConfigAuthorizePublishRejectsInvalidToken(t *testing.T) {
	t.Parallel()

	_, validator := newTestValidator(t, time.Now().Add(-time.Hour))
	config := &worldChatAuthConfig{mode: worldChatAuthModeEnforce, validator: validator}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer invalid-token"))

	allowed, err := config.authorizePublish(ctx, gateway.Identity{}, gateway.PublishRequestSummary{})
	if err != nil {
		t.Fatalf("authorizePublish() error = %v", err)
	}
	if allowed {
		t.Fatal("expected invalid token to be rejected")
	}
}

func TestWorldChatAuthConfigAuthorizePublishAllowsInvalidTokenWhenReportOnly(t *testing.T) {
	t.Parallel()

	_, validator := newTestValidator(t, time.Now().Add(-time.Hour))
	config := &worldChatAuthConfig{mode: worldChatAuthModeReportOnly, validator: validator}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer invalid-token"))

	allowed, err := config.authorizePublish(ctx, gateway.Identity{}, gateway.PublishRequestSummary{})
	if err != nil {
		t.Fatalf("authorizePublish() error = %v", err)
	}
	if !allowed {
		t.Fatal("expected invalid token to be allowed in report_only mode")
	}
}

func TestWorldChatAuthConfigAuthorizePublishAcceptsValidBearerToken(t *testing.T) {
	t.Parallel()

	privateKey, validator := newTestValidator(t, time.Now().Add(-time.Hour))
	config := &worldChatAuthConfig{mode: worldChatAuthModeEnforce, validator: validator}
	token := newTestToken(t, privateKey, validator.expectedKid, validator.expectedIssuer, time.Now())
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))

	allowed, err := config.authorizePublish(ctx, gateway.Identity{}, gateway.PublishRequestSummary{})
	if err != nil {
		t.Fatalf("authorizePublish() error = %v", err)
	}
	if !allowed {
		t.Fatal("expected valid token to be accepted")
	}
}

func TestGatewayInterceptorRejectsPublishWithoutAuthorizationHeader(t *testing.T) {
	t.Parallel()

	_, validator := newTestValidator(t, time.Now().Add(-time.Hour))
	config := &worldChatAuthConfig{mode: worldChatAuthModeEnforce, validator: validator}
	interceptor := gateway.NewGatewayInterceptor(
		zap.NewNop(),
		func(ctx context.Context) (gateway.Identity, error) {
			return gateway.Identity{Kind: "ip", Identity: "127.0.0.1"}, nil
		},
		[]gateway.AuthorizePublishFn{config.authorizePublish},
	)

	handlerCalled := false
	_, err := interceptor.Unary()(
		context.Background(),
		&payer_api.PublishClientEnvelopesRequest{Envelopes: []*envelopes.ClientEnvelope{{}}},
		&grpc.UnaryServerInfo{FullMethod: "/xmtp.xmtpv4.payer_api.PayerApi/PublishClientEnvelopes"},
		func(ctx context.Context, req interface{}) (interface{}, error) {
			handlerCalled = true
			return nil, nil
		},
	)
	if err == nil {
		t.Fatal("expected publish without auth header to be rejected")
	}
	if handlerCalled {
		t.Fatal("expected handler not to be called for unauthorized publish")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v (%v)", status.Code(err), err)
	}
}

func TestGatewayInterceptorAllowsPublishWithoutAuthorizationHeaderInReportOnlyMode(t *testing.T) {
	t.Parallel()

	_, validator := newTestValidator(t, time.Now().Add(-time.Hour))
	config := &worldChatAuthConfig{mode: worldChatAuthModeReportOnly, validator: validator}
	interceptor := gateway.NewGatewayInterceptor(
		zap.NewNop(),
		func(ctx context.Context) (gateway.Identity, error) {
			return gateway.Identity{Kind: "ip", Identity: "127.0.0.1"}, nil
		},
		[]gateway.AuthorizePublishFn{config.authorizePublish},
	)

	handlerCalled := false
	_, err := interceptor.Unary()(
		context.Background(),
		&payer_api.PublishClientEnvelopesRequest{Envelopes: []*envelopes.ClientEnvelope{{}}},
		&grpc.UnaryServerInfo{FullMethod: "/xmtp.xmtpv4.payer_api.PayerApi/PublishClientEnvelopes"},
		func(ctx context.Context, req interface{}) (interface{}, error) {
			handlerCalled = true
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("expected report_only mode to allow publish without auth header, got %v", err)
	}
	if !handlerCalled {
		t.Fatal("expected handler to be called in report_only mode")
	}
}

func TestGatewayInterceptorAcceptsPublishWithValidAuthorizationHeader(t *testing.T) {
	t.Parallel()

	privateKey, validator := newTestValidator(t, time.Now().Add(-time.Hour))
	config := &worldChatAuthConfig{mode: worldChatAuthModeEnforce, validator: validator}
	token := newTestToken(t, privateKey, validator.expectedKid, validator.expectedIssuer, time.Now())
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
	interceptor := gateway.NewGatewayInterceptor(
		zap.NewNop(),
		func(ctx context.Context) (gateway.Identity, error) {
			return gateway.Identity{Kind: "ip", Identity: "127.0.0.1"}, nil
		},
		[]gateway.AuthorizePublishFn{config.authorizePublish},
	)

	handlerCalled := false
	_, err := interceptor.Unary()(
		ctx,
		&payer_api.PublishClientEnvelopesRequest{Envelopes: []*envelopes.ClientEnvelope{{}, {}}},
		&grpc.UnaryServerInfo{FullMethod: "/xmtp.xmtpv4.payer_api.PayerApi/PublishClientEnvelopes"},
		func(ctx context.Context, req interface{}) (interface{}, error) {
			handlerCalled = true
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("expected publish with valid auth header to succeed, got %v", err)
	}
	if !handlerCalled {
		t.Fatal("expected handler to be called for authorized publish")
	}
}

func TestNormalizePEMAcceptsEscapedNewlines(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	pemValue := publicKeyPEM(t, &privateKey.PublicKey)
	normalized := normalizePEM(escapePEMLineBreaks(pemValue))
	if _, err := jwt.ParseECPublicKeyFromPEM([]byte(normalized)); err != nil {
		t.Fatalf("ParseECPublicKeyFromPEM() error = %v", err)
	}
}

func TestLoadWorldChatAuthModeFromEnvDefaultsToDisabled(t *testing.T) {
	t.Setenv(worldChatAuthEnabledEnv, "")
	t.Setenv(worldChatAuthModeEnv, "")

	mode, err := loadWorldChatAuthModeFromEnv()
	if err != nil {
		t.Fatalf("loadWorldChatAuthModeFromEnv() error = %v", err)
	}
	if mode != worldChatAuthModeDisabled {
		t.Fatalf("expected disabled mode, got %q", mode)
	}
}

func TestLoadWorldChatAuthModeFromEnvUsesLegacyEnabledFlag(t *testing.T) {
	t.Setenv(worldChatAuthEnabledEnv, "true")
	t.Setenv(worldChatAuthModeEnv, "")

	mode, err := loadWorldChatAuthModeFromEnv()
	if err != nil {
		t.Fatalf("loadWorldChatAuthModeFromEnv() error = %v", err)
	}
	if mode != worldChatAuthModeEnforce {
		t.Fatalf("expected enforce mode, got %q", mode)
	}
}

func TestLoadWorldChatAuthModeFromEnvPrefersExplicitMode(t *testing.T) {
	t.Setenv(worldChatAuthEnabledEnv, "false")
	t.Setenv(worldChatAuthModeEnv, "report_only")

	mode, err := loadWorldChatAuthModeFromEnv()
	if err != nil {
		t.Fatalf("loadWorldChatAuthModeFromEnv() error = %v", err)
	}
	if mode != worldChatAuthModeReportOnly {
		t.Fatalf("expected report_only mode, got %q", mode)
	}
}

func TestLoadWorldChatAuthModeFromEnvRejectsInvalidMode(t *testing.T) {
	t.Setenv(worldChatAuthModeEnv, "maybe")

	if _, err := loadWorldChatAuthModeFromEnv(); err == nil {
		t.Fatal("expected invalid auth mode to fail")
	}
}

func newTestValidator(t *testing.T, cutoff time.Time) (*ecdsa.PrivateKey, *worldChatTokenValidator) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	publicKey, err := jwt.ParseECPublicKeyFromPEM([]byte(publicKeyPEM(t, &privateKey.PublicKey)))
	if err != nil {
		t.Fatalf("ParseECPublicKeyFromPEM() error = %v", err)
	}

	return privateKey, &worldChatTokenValidator{
		expectedIssuer: defaultWorldChatJWTIssuerProd,
		expectedKid:    "key_test",
		publicKey:      publicKey,
		issuedAfter:    &cutoff,
	}
}

func newTestToken(t *testing.T, privateKey *ecdsa.PrivateKey, kid string, issuer string, issuedAt time.Time) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Subject:   "push-id-123",
		Issuer:    issuer,
		IssuedAt:  jwt.NewNumericDate(issuedAt),
		NotBefore: jwt.NewNumericDate(issuedAt),
		ExpiresAt: jwt.NewNumericDate(issuedAt.Add(24 * time.Hour)),
	})
	token.Header["typ"] = "JWT"
	token.Header["kid"] = kid

	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	return signed
}

func newExpiredTestToken(t *testing.T, privateKey *ecdsa.PrivateKey, kid string, issuer string) string {
	t.Helper()

	issuedAt := time.Now().Add(-2 * time.Hour)
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Subject:   "push-id-123",
		Issuer:    issuer,
		IssuedAt:  jwt.NewNumericDate(issuedAt),
		NotBefore: jwt.NewNumericDate(issuedAt),
		ExpiresAt: jwt.NewNumericDate(issuedAt.Add(-time.Hour)),
	})
	token.Header["typ"] = "JWT"
	token.Header["kid"] = kid

	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	return signed
}

func publicKeyPEM(t *testing.T, publicKey *ecdsa.PublicKey) string {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}))
}

func escapePEMLineBreaks(value string) string {
	return strings.ReplaceAll(value, "\n", `\n`)
}
