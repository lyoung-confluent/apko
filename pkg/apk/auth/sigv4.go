package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sigv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

var patternS3Host = regexp.MustCompile(`^([^.]+)\.s3(?:-fips)?(?:\.dualstack)?(?:\.([^.]+))?\.amazonaws\.com$`)

// SigV4Auth adds an AWS SigV4 signature to the request
type SigV4Auth struct {
	signer *sigv4.Signer
	creds  aws.CredentialsProvider
}

func (a SigV4Auth) AddAuth(ctx context.Context, req *http.Request) error {
	// Only sign requests to S3 hostnames
	matches := patternS3Host.FindStringSubmatch(req.URL.Host)
	if matches == nil {
		return nil
	}
	region := matches[2]
	if region == "" {
		region = "us-east-1"
	}

	// Calculate the hash of the request body, typically it's an empty body (GET/HEAD requests)
	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if req.Body != nil {
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(req.Body); err != nil {
			return fmt.Errorf("(*bufio.Buffer).ReadFrom failed: %w", err)
		}
		hashed := sha256.Sum256(buf.Bytes())
		payloadHash = hex.EncodeToString(hashed[:])
		req.Body = io.NopCloser(&buf)
	}
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	// chainguard.dev/apko/pkg/apk/apk/cache.go (fetchAndCache) adds this header, breaking the payload hash calculation
	req.Header.Del("I-Cant-Believe-Its-Not-If-None-Match")

	// Fetch the credentials and sign the request
	creds, err := a.creds.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("(aws.CredentialsProvider).Retrieve failed: %w", err)
	}
	if err := a.signer.SignHTTP(ctx, creds, req, payloadHash, "s3", region, time.Now()); err != nil {
		return fmt.Errorf("(*sigv4.Signer).SignHTTP failed: %w", err)
	}
	return nil
}

func NewSigV4Auth(creds aws.CredentialsProvider, opts ...func(options *sigv4.SignerOptions)) *SigV4Auth {
	if creds == nil {
		cfg, err := awsconfig.LoadDefaultConfig(context.TODO())
		if err != nil {
			log.Fatalf("awsconfig.LoadDefaultConfig failed: %v", err)
		}
		creds = cfg.Credentials
	}

	return &SigV4Auth{
		signer: sigv4.NewSigner(opts...),
		creds:  creds,
	}
}
