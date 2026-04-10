package main

import (
	"log"

	"github.com/xmtp/xmtpd/pkg/gateway"
)

func main() {
	publishAuthorizer, err := newWorldChatPublishAuthorizerFromEnv()
	if err != nil {
		log.Fatalf("Failed to configure publish authorizer: %v", err)
	}

	gatewayService, err := gateway.NewGatewayServiceBuilder(gateway.MustLoadConfig()).
		WithAuthorizers(publishAuthorizer).
		Build() // This will gather all the config from environment variables and flags
	if err != nil {
		log.Fatalf("Failed to build gateway service: %v", err)
	}

	gatewayService.WaitForShutdown()
}
