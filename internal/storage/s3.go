package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"shivasync/internal/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Client wraps the AWS S3 client with our configuration
type S3Client struct {
	client    *s3.Client
	presigner *s3.PresignClient
	bucket    string
}

// ObjectKey generates a content-addressed key from SHA256 hash
func ObjectKey(sha256Hash string) string {
	return fmt.Sprintf("mods/%s/%s", sha256Hash[:2], sha256Hash)
}

// MetadataKey generates a metadata key from SHA256 hash
func MetadataKey(sha256Hash string) string {
	return fmt.Sprintf("meta/%s/%s.json", sha256Hash[:2], sha256Hash)
}

// NewS3Client creates a new S3 client with the given configuration
func NewS3Client(cfg *config.Config) (*S3Client, error) {
	// Create AWS config
	awsCfg, err := awsconfig.LoadDefaultConfig(context.TODO(),
		awsconfig.WithRegion(cfg.S3Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cfg.S3AccessKeyID,
			cfg.S3SecretAccessKey,
			"",
		)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create S3 client with custom endpoint if specified
	var s3Client *s3.Client
	if cfg.S3Endpoint != "" {
		s3Client = s3.NewFromConfig(awsCfg, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.S3Endpoint)
			o.UsePathStyle = true // Required for most S3-compatible services
		})
	} else {
		s3Client = s3.NewFromConfig(awsCfg)
	}

	// Create presigner
	presigner := s3.NewPresignClient(s3Client)

	return &S3Client{
		client:    s3Client,
		presigner: presigner,
		bucket:    cfg.S3Bucket,
	}, nil
}

// HeadBucket checks if the bucket exists and is accessible
func (s *S3Client) HeadBucket(ctx context.Context) error {
	_, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(s.bucket),
	})
	return err
}

// HeadObject checks if an object exists
func (s *S3Client) HeadObject(ctx context.Context, key string) (*s3.HeadObjectOutput, error) {
	return s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
}

// PresignPutObject creates a presigned URL for PUT operations
func (s *S3Client) PresignPutObject(ctx context.Context, key string, metadata map[string]string) (string, map[string]string, error) {
	input := &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(key),
		Metadata:    metadata,
		ContentType: aws.String("application/octet-stream"),
	}

	// Create presigned URL with 10 minute expiry
	request, err := s.presigner.PresignPutObject(ctx, input, func(opts *s3.PresignOptions) {
		opts.Expires = 10 * time.Minute
	})
	if err != nil {
		return "", nil, fmt.Errorf("failed to create presigned PUT URL: %w", err)
	}

	// Extract headers for the client to use
	headers := make(map[string]string)
	if metadata != nil {
		for k, v := range metadata {
			headers[fmt.Sprintf("x-amz-meta-%s", k)] = v
		}
	}
	headers["Content-Type"] = "application/octet-stream"

	return request.URL, headers, nil
}

// PresignGetObject creates a presigned URL for GET operations
func (s *S3Client) PresignGetObject(ctx context.Context, key string) (string, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	}

	// Create presigned URL with 10 minute expiry
	request, err := s.presigner.PresignGetObject(ctx, input, func(opts *s3.PresignOptions) {
		opts.Expires = 10 * time.Minute
	})
	if err != nil {
		return "", fmt.Errorf("failed to create presigned GET URL: %w", err)
	}

	return request.URL, nil
}

// PutObjectMetadata stores metadata for an object
func (s *S3Client) PutObjectMetadata(ctx context.Context, key string, metadata interface{}) error {
	// Marshal metadata to JSON
	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Upload metadata as JSON
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(data),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return fmt.Errorf("failed to store metadata: %w", err)
	}

	return nil
}

// GetObjectMetadata retrieves metadata for an object
func (s *S3Client) GetObjectMetadata(ctx context.Context, key string) (interface{}, error) {
	// Get metadata object
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve metadata: %w", err)
	}
	defer result.Body.Close()

	// Decode JSON
	var metadata interface{}
	if err := json.NewDecoder(result.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %w", err)
	}

	return metadata, nil
}
