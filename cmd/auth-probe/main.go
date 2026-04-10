package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/xmtp/xmtpd/pkg/gateway"
	"github.com/xmtp/xmtpd/pkg/proto/xmtpv4/payer_api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	defaultListenAddr     = "127.0.0.1:5872"
	defaultJWTIssuerProd  = "chat.toolsforhumanity.com"
	defaultJWTIssuerStage = "chat-staging.toolsforhumanity.com"
	defaultJWTIssuedAfter = "2025-12-07T00:00:00Z"
	defaultNodeMap        = "1=https://grpc.dev.xmtp.network"
	jwtClockSkew          = 60 * time.Second

	authListenAddrEnv  = "WORLD_CHAT_GATEWAY_AUTH_PROBE_ADDR"
	nodeMapEnv         = "WORLD_CHAT_GATEWAY_AUTH_PROBE_NODE_MAP"
	jwtIssuerEnv       = "WORLD_CHAT_GATEWAY_AUTH_ISSUER"
	jwtIssuedAfterEnv  = "WORLD_CHAT_GATEWAY_AUTH_ISSUED_AFTER"
	jwtKidEnv          = "WORLD_CHAT_GATEWAY_AUTH_KID"
	jwtPublicKeyPEMEnv = "WORLD_CHAT_GATEWAY_AUTH_PUBLIC_KEY_PEM"
	xmtpdContractsEnv   = "XMTPD_CONTRACTS_ENVIRONMENT"
)

var (
	errMissingAuthorizationHeader = errors.New("missing authorization header")
	errInvalidAuthorizationHeader = errors.New("invalid authorization header")
	errInvalidTokenHeader         = errors.New("invalid token header")
	errMissingRequiredClaim       = errors.New("missing required claim")
	errIssuedBeforeCutoff         = errors.New("token issued before cutoff")
)

type authProbeServer struct {
	payer_api.UnimplementedPayerApiServer
	healthgrpc.UnimplementedHealthServer

	validator *tokenValidator
	nodeMap   map[uint32]string
}

type tokenValidator struct {
	expectedIssuer string
	expectedKid    string
	publicKey      *ecdsa.PublicKey
	issuedAfter    *time.Time
}

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

	validator, err := newTokenValidatorFromEnv()
	if err != nil {
		logger.Fatalf("load validator: %v", err)
	}

	listenAddr := strings.TrimSpace(os.Getenv(authListenAddrEnv))
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		logger.Fatalf("listen %s: %v", listenAddr, err)
	}

	server := grpc.NewServer()
	probe := &authProbeServer{validator: validator}
	payer_api.RegisterPayerApiServer(server, probe)
	healthgrpc.RegisterHealthServer(server, probe)

	nodeMap, err := loadNodeMap()
	if err != nil {
		logger.Fatalf("load node map: %v", err)
	}
	probe.nodeMap = nodeMap

	logger.Printf("auth probe listening on %s", listenAddr)
	logger.Printf("expecting kid=%s issuer=%s", validator.expectedKid, validator.expectedIssuer)
	logger.Printf("serving GetNodes with %d node(s)", len(nodeMap))

	if err := server.Serve(lis); err != nil {
		logger.Fatalf("serve: %v", err)
	}
}

func (s *authProbeServer) PublishClientEnvelopes(
	ctx context.Context,
	req *payer_api.PublishClientEnvelopesRequest,
) (*payer_api.PublishClientEnvelopesResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		keys := make([]string, 0, len(md))
		for key := range md {
			keys = append(keys, key)
		}
		log.Printf(
			"publish metadata: envelopes=%d keys=%v authorization_values=%d bearer_values=%d",
			len(req.GetEnvelopes()),
			keys,
			len(md.Get("authorization")),
			len(md.Get("bearer")),
		)
	}

	header := gateway.AuthorizationHeaderFromContext(ctx)
	claims, err := s.validator.validateAuthorizationHeader(header)
	if err != nil {
		log.Printf("publish denied: envelopes=%d err=%v", len(req.GetEnvelopes()), err)
		if errors.Is(err, errMissingAuthorizationHeader) || errors.Is(err, errInvalidAuthorizationHeader) {
			return nil, status.Error(codes.Unauthenticated, "authorization required")
		}
		return nil, status.Error(codes.PermissionDenied, "invalid authorization")
	}

	log.Printf(
		"publish authorized: envelopes=%d subject=%s expires_at=%d",
		len(req.GetEnvelopes()),
		claims.Subject,
		claims.ExpiresAt.Time.Unix(),
	)

	return &payer_api.PublishClientEnvelopesResponse{}, nil
}

func (s *authProbeServer) GetNodes(
	ctx context.Context,
	req *payer_api.GetNodesRequest,
) (*payer_api.GetNodesResponse, error) {
	_ = ctx
	_ = req
	log.Printf("get-nodes served: nodes=%d", len(s.nodeMap))
	return &payer_api.GetNodesResponse{Nodes: s.nodeMap}, nil
}

func (s *authProbeServer) Check(_ context.Context, _ *healthgrpc.HealthCheckRequest) (*healthgrpc.HealthCheckResponse, error) {
	return &healthgrpc.HealthCheckResponse{Status: healthgrpc.HealthCheckResponse_SERVING}, nil
}

func (s *authProbeServer) Watch(*healthgrpc.HealthCheckRequest, healthgrpc.Health_WatchServer) error {
	return status.Error(codes.Unimplemented, "watch not implemented")
}

func newTokenValidatorFromEnv() (*tokenValidator, error) {
	expectedKid := strings.TrimSpace(os.Getenv(jwtKidEnv))
	if expectedKid == "" {
		return nil, fmt.Errorf("%s must be set", jwtKidEnv)
	}

	publicKeyPEM := strings.TrimSpace(os.Getenv(jwtPublicKeyPEMEnv))
	if publicKeyPEM == "" {
		return nil, fmt.Errorf("%s must be set", jwtPublicKeyPEMEnv)
	}

	publicKey, err := jwt.ParseECPublicKeyFromPEM([]byte(normalizePEM(publicKeyPEM)))
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	issuer := defaultJWTIssuer()
	if configuredIssuer := strings.TrimSpace(os.Getenv(jwtIssuerEnv)); configuredIssuer != "" {
		issuer = configuredIssuer
	}

	issuedAfter, err := loadIssuedAfterCutoff()
	if err != nil {
		return nil, err
	}

	return &tokenValidator{
		expectedIssuer: issuer,
		expectedKid:    expectedKid,
		publicKey:      publicKey,
		issuedAfter:    issuedAfter,
	}, nil
}

func (v *tokenValidator) validateAuthorizationHeader(header string) (*jwt.RegisteredClaims, error) {
	token, err := bearerTokenFromHeader(header)
	if err != nil {
		return nil, err
	}

	return v.validateToken(token)
}

func (v *tokenValidator) validateToken(tokenString string) (*jwt.RegisteredClaims, error) {
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
	value, ok := os.LookupEnv(jwtIssuedAfterEnv)
	if !ok {
		value = defaultJWTIssuedAfter
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}

	issuedAfter, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", jwtIssuedAfterEnv, err)
	}

	return &issuedAfter, nil
}

func defaultJWTIssuer() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(xmtpdContractsEnv))) {
	case "testnet-staging", "staging", "stage", "testnet":
		return defaultJWTIssuerStage
	default:
		return defaultJWTIssuerProd
	}
}

func normalizePEM(pem string) string {
	return strings.ReplaceAll(pem, `\n`, "\n")
}

func loadNodeMap() (map[uint32]string, error) {
	raw := strings.TrimSpace(os.Getenv(nodeMapEnv))
	if raw == "" {
		raw = defaultNodeMap
	}

	nodeMap := make(map[uint32]string)
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid node map entry %q", entry)
		}
		nodeID, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parse node id %q: %w", parts[0], err)
		}
		address := strings.TrimSpace(parts[1])
		if address == "" {
			return nil, fmt.Errorf("empty address for node id %d", nodeID)
		}
		nodeMap[uint32(nodeID)] = address
	}
	if len(nodeMap) == 0 {
		return nil, errors.New("node map must not be empty")
	}
	return nodeMap, nil
}
