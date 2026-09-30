package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/ndx-technologies/go-apple/applejwt"
)

func main() {
	var config applejwt.JWTIssuerConfig
	var privateKeyPath string
	var audience string

	flag.StringVar(&config.IssuerID, "issuer-id", "", "Issuer ID from App Store Connect")
	flag.StringVar(&config.BundleID, "bundle-id", "", "Bundle ID for App Store Connect API (sets bid claim)")
	flag.StringVar(&config.Subject, "subject", "", "Subject for Sign in with Apple client secret (sets sub claim, e.g. com.example.app)")
	flag.StringVar(&config.KeyID, "key-id", "", "Private key ID from App Store Connect")
	flag.DurationVar(&config.TTL, "ttl", 5*time.Minute, "Token TTL (max 1h for App Store Connect, up to 6mo for Sign in with Apple)")
	flag.StringVar(&privateKeyPath, "private-key", os.Getenv("PRIVATE_KEY_PATH"), "Path to private key file")
	flag.StringVar(&audience, "audience", "", "JWT audience")
	flag.Parse()

	config = config.WithDefaults()

	privateKey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		log.Fatalf("cannot load private key: %s", err)
	}

	jwtIssuer, err := applejwt.NewJWTIssuer(config, privateKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	token, _, err := jwtIssuer.GenerateJWT(audience)
	if err != nil {
		log.Fatalf("cannot make jwt: %s", err)
	}

	os.Stdout.WriteString(token)
}
