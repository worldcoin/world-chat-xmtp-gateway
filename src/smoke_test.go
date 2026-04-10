package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/xmtp/xmtpd/pkg/proto/xmtpv4/envelopes"
	"github.com/xmtp/xmtpd/pkg/proto/xmtpv4/payer_api"
	"github.com/xmtp/xmtpd/pkg/testutils"
	"github.com/xmtp/xmtpd/pkg/testutils/anvil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestGatewayPublishAuthLocalSmoke(t *testing.T) {
	if os.Getenv("WORLD_CHAT_GATEWAY_SMOKE") != "1" {
		t.Skip("set WORLD_CHAT_GATEWAY_SMOKE=1 to run the local Docker-backed smoke test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	wsURL, rpcURL := anvil.StartAnvil(t, false)
	redisURL := startRedis(t, ctx)
	port := freePort(t)

	privateKey, validator := newTestValidator(t, time.Now().Add(-time.Hour))
	token := newTestToken(t, privateKey, validator.expectedKid, validator.expectedIssuer, time.Now())

	cmd := exec.CommandContext(ctx, "go", "run", "./src")
	cmd.Dir = "/Users/yon.harlicaj/Documents/Dev/world-chat-xmtp-gateway"
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	cmd.Env = append(
		os.Environ(),
		"XMTPD_APP_CHAIN_WSS_URL="+wsURL,
		"XMTPD_APP_CHAIN_RPC_URL="+rpcURL,
		"XMTPD_SETTLEMENT_CHAIN_WSS_URL="+wsURL,
		"XMTPD_SETTLEMENT_CHAIN_RPC_URL="+rpcURL,
		"XMTPD_CONTRACTS_ENVIRONMENT=anvil",
		"XMTPD_PAYER_PRIVATE_KEY="+testutils.TestPrivateKey,
		"XMTPD_REDIS_URL="+redisURL,
		"XMTPD_REDIS_KEY_PREFIX=smoke:"+strconv.FormatInt(time.Now().UnixNano(), 10)+":",
		"XMTPD_API_PORT="+strconv.Itoa(port),
		"XMTPD_LOG_LEVEL=error",
		"WORLD_CHAT_GATEWAY_AUTH_ENABLED=true",
		"WORLD_CHAT_GATEWAY_AUTH_KID="+validator.expectedKid,
		"WORLD_CHAT_GATEWAY_AUTH_PUBLIC_KEY_PEM="+escapePEMLineBreaks(publicKeyPEM(t, validator.publicKey)),
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("gateway failed to start: %v\n%s", err, output.String())
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	conn := waitForGateway(t, ctx, port, &output)
	defer func() { _ = conn.Close() }()

	client := payer_api.NewPayerApiClient(conn)
	req := &payer_api.PublishClientEnvelopesRequest{
		Envelopes: []*envelopes.ClientEnvelope{{}},
	}

	_, err := client.PublishClientEnvelopes(ctx, req)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected unauthenticated publish to fail with PermissionDenied, got %v (%v)", status.Code(err), err)
	}

	authorizedCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	_, err = client.PublishClientEnvelopes(authorizedCtx, req)
	if status.Code(err) == codes.PermissionDenied {
		t.Fatalf("expected authorized publish to get past auth layer, got %v", err)
	}
}

func startRedis(t *testing.T, ctx context.Context) string {
	t.Helper()

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "redis:7-alpine",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForListeningPort("6379/tcp"),
		},
		Started: true,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = container.Terminate(context.Background())
	})

	port, err := container.MappedPort(ctx, "6379/tcp")
	require.NoError(t, err)

	return "redis://localhost:" + port.Port()
}

func freePort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()

	return listener.Addr().(*net.TCPAddr).Port
}

func waitForGateway(t *testing.T, ctx context.Context, port int, output *bytes.Buffer) *grpc.ClientConn {
	t.Helper()

	target := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(20 * time.Second)

	for {
		conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err == nil {
			healthClient := healthgrpc.NewHealthClient(conn)
			checkCtx, cancel := context.WithTimeout(ctx, time.Second)
			_, healthErr := healthClient.Check(checkCtx, &healthgrpc.HealthCheckRequest{})
			cancel()
			if healthErr == nil {
				return conn
			}
			_ = conn.Close()
		}

		if time.Now().After(deadline) {
			if err == nil {
				err = errors.New("gateway health check never succeeded")
			}
			t.Fatalf("timed out waiting for gateway on %s: %v\n%s", target, err, output.String())
		}

		time.Sleep(200 * time.Millisecond)
	}
}
