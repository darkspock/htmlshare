package htmlshare

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

type S3Client struct {
	Endpoint  string
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	Client    *http.Client
}

func NewS3ClientFromEnv() *S3Client {
	endpoint := os.Getenv("S3_ENDPOINT")
	bucket := os.Getenv("S3_BUCKET")
	accessKey := os.Getenv("S3_ACCESS_KEY_ID")
	secretKey := os.Getenv("S3_SECRET_ACCESS_KEY")
	if endpoint == "" || bucket == "" || accessKey == "" || secretKey == "" {
		return nil
	}
	return &S3Client{
		Endpoint:  strings.TrimRight(endpoint, "/"),
		Region:    envOr("S3_REGION", "us-east-1"),
		Bucket:    bucket,
		AccessKey: accessKey,
		SecretKey: secretKey,
		Client:    http.DefaultClient,
	}
}

func (c *S3Client) EnsureBucket() error {
	req, err := c.newRequest(http.MethodPut, "", nil)
	if err != nil {
		return err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusConflict {
		return nil
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil
	}
	raw, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("create bucket failed: %s %s", resp.Status, string(raw))
}

func (c *S3Client) PutObject(key string, content []byte) error {
	if err := c.EnsureBucket(); err != nil {
		return err
	}
	req, err := c.newRequest(http.MethodPut, key, bytes.NewReader(content))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", http.DetectContentType(content))
	req.ContentLength = int64(len(content))
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("put object failed: %s %s", resp.Status, string(raw))
	}
	return nil
}

func (c *S3Client) GetObject(key string) ([]byte, error) {
	req, err := c.newRequest(http.MethodGet, key, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get object failed: %s %s", resp.Status, string(raw))
	}
	return io.ReadAll(resp.Body)
}

func (c *S3Client) DeletePrefix(prefix string) error {
	keys, err := c.listKeys(prefix)
	if err != nil {
		return err
	}
	for _, key := range keys {
		req, err := c.newRequest(http.MethodDelete, key, nil)
		if err != nil {
			return err
		}
		resp, err := c.Client.Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("delete object failed: %s", resp.Status)
		}
	}
	return nil
}

func (c *S3Client) MovePrefix(oldPrefix, newPrefix string) error {
	keys, err := c.listKeys(oldPrefix)
	if err != nil {
		return err
	}
	for _, key := range keys {
		content, err := c.GetObject(key)
		if err != nil {
			return err
		}
		nextKey := newPrefix + strings.TrimPrefix(key, oldPrefix)
		if err := c.PutObject(nextKey, content); err != nil {
			return err
		}
		if err := c.DeleteObject(key); err != nil {
			return err
		}
	}
	return nil
}

func (c *S3Client) DeleteObject(key string) error {
	req, err := c.newRequest(http.MethodDelete, key, nil)
	if err != nil {
		return err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("delete object failed: %s", resp.Status)
	}
	return nil
}

func (c *S3Client) listKeys(prefix string) ([]string, error) {
	req, err := c.newRequest(http.MethodGet, "", nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Set("list-type", "2")
	q.Set("prefix", prefix)
	req.URL.RawQuery = q.Encode()
	c.sign(req, nil)
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list objects failed: %s %s", resp.Status, string(raw))
	}
	var result struct {
		Contents []struct {
			Key string `xml:"Key"`
		} `xml:"Contents"`
	}
	if err := xml.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(result.Contents))
	for _, item := range result.Contents {
		keys = append(keys, item.Key)
	}
	return keys, nil
}

func (c *S3Client) newRequest(method, key string, body io.Reader) (*http.Request, error) {
	escapedKey := strings.TrimLeft(key, "/")
	u, err := url.Parse(c.Endpoint + "/" + c.Bucket)
	if err != nil {
		return nil, err
	}
	if escapedKey != "" {
		u.Path += "/" + strings.ReplaceAll(escapedKey, " ", "%20")
	}
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, err
	}
	c.sign(req, body)
	return req, nil
}

func (c *S3Client) sign(req *http.Request, body io.Reader) {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	payloadHash := "UNSIGNED-PAYLOAD"
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("host", req.URL.Host)

	signedHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	canonicalHeaders := ""
	for _, header := range signedHeaders {
		canonicalHeaders += header + ":" + strings.TrimSpace(req.Header.Get(header)) + "\n"
	}
	query := req.URL.Query()
	var queryKeys []string
	for key := range query {
		queryKeys = append(queryKeys, key)
	}
	sort.Strings(queryKeys)
	var canonicalQuery []string
	for _, key := range queryKeys {
		canonicalQuery = append(canonicalQuery, url.QueryEscape(key)+"="+url.QueryEscape(query.Get(key)))
	}
	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		strings.Join(canonicalQuery, "&"),
		canonicalHeaders,
		strings.Join(signedHeaders, ";"),
		payloadHash,
	}, "\n")
	scope := date + "/" + c.Region + "/s3/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hexSHA256([]byte(canonicalRequest)),
	}, "\n")
	signingKey := awsSigningKey(c.SecretKey, date, c.Region, "s3")
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	req.Header.Set("authorization", "AWS4-HMAC-SHA256 Credential="+c.AccessKey+"/"+scope+", SignedHeaders="+strings.Join(signedHeaders, ";")+", Signature="+signature)
}

func awsSigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return mac.Sum(nil)
}

func hexSHA256(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
