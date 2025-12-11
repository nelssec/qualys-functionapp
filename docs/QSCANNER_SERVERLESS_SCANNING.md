# QScanner Serverless Function Scanning - Multi-Cloud Implementation

## Executive Summary

This document proposes extending qscanner to support serverless function scanning across AWS Lambda (existing), Azure Functions (new), and GCP Cloud Functions (new). The architecture ensures **source code never leaves the customer's cloud environment** while providing comprehensive vulnerability scanning.

---

## Security Model

### Core Principle: Code Never Leaves Customer Environment

```
┌────────────────────────────────────────────────────────────────────────┐
│                      CUSTOMER'S CLOUD ENVIRONMENT                       │
│                                                                         │
│   ┌─────────────┐      ┌─────────────┐      ┌─────────────┐           │
│   │   Lambda    │      │   Azure     │      │    GCP      │           │
│   │  Functions  │      │  Functions  │      │  Functions  │           │
│   └──────┬──────┘      └──────┬──────┘      └──────┬──────┘           │
│          │                    │                    │                   │
│          ▼                    ▼                    ▼                   │
│   ┌─────────────────────────────────────────────────────────┐         │
│   │                      QSCANNER                            │         │
│   │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐    │         │
│   │  │ Fetch   │─▶│Download │─▶│  Scan   │─▶│ Cleanup │    │         │
│   │  │Metadata │  │  Code   │  │  Code   │  │  Code   │    │         │
│   │  └─────────┘  └─────────┘  └─────────┘  └─────────┘    │         │
│   │       │                          │                      │         │
│   │       │    Source code stays     │                      │         │
│   │       │    in /tmp (ephemeral)   │                      │         │
│   │       │                          │                      │         │
│   └───────┼──────────────────────────┼──────────────────────┘         │
│           │                          │                                 │
└───────────┼──────────────────────────┼─────────────────────────────────┘
            │                          │
            ▼                          ▼
    ┌───────────────┐          ┌───────────────┐
    │  Cloud APIs   │          │  Qualys API   │
    │  (metadata)   │          │ (results only)│
    └───────────────┘          └───────────────┘
```

### What Stays In vs. What Leaves

| Data | Stays In Customer Environment | Sent to Qualys |
|------|------------------------------|----------------|
| Source code | Yes (downloaded, scanned, deleted) | No |
| Function metadata | Yes (used locally) | Partial (name, runtime, hash) |
| Vulnerability results | Generated locally | Yes |
| Secrets detected | Identified locally | Yes (location only, not values) |
| Signed URLs | Generated & used locally | No |
| Auth tokens | Used locally | No |

### Authentication & Authorization

| Cloud | Auth Method | Credential Type | Rotation |
|-------|-------------|-----------------|----------|
| AWS | IAM Role | Instance role / env vars | Automatic |
| Azure | Managed Identity | Azure AD bearer token | Automatic (~1 hour) |
| GCP | ADC | Service account / Workload Identity | Automatic |

**No long-lived secrets required** - all clouds support identity-based authentication that auto-rotates.

---

## Current State

| Command | Cloud | Status | Notes |
|---------|-------|--------|-------|
| `lambda` | AWS | **Supported** | Production ready |
| `azure-function` | Azure | **Not supported** | Proposed in this doc |
| `gcp-function` | GCP | **Not supported** | Proposed in this doc |
| `repo` | Any | **Buggy** | Panics on serverless code structure |

### Bug: `repo` Command Panic

When using the `repo` command on extracted serverless function code:

```
panic: runtime error: index out of range [0] with length 0
goroutine 16 [running]:
.../pkg/target.(*RepositoryTarget).GetTargetMetadata(...)
    /data/pkg/target/repository.go:202 +0x466
```

**Root cause**: `GetTargetMetadata()` expects repository markers (`.git/`, `package.json`, etc.) that don't exist in serverless deployments.

**Fix**: Handle empty metadata gracefully or implement native serverless commands.

---

## Implementation Architecture

### Package Structure

```
pkg/
├── target/
│   ├── target.go              # Target interface
│   ├── lambda.go              # AWS Lambda (existing)
│   ├── azure_function.go      # Azure Functions (new)
│   ├── gcp_function.go        # GCP Cloud Functions (new)
│   └── repository.go          # Generic repo (fix panic)
│
├── cloud/
│   ├── aws/
│   │   ├── client.go          # AWS SDK wrapper
│   │   ├── lambda.go          # Lambda-specific operations
│   │   └── ecr.go             # ECR for container images
│   │
│   ├── azure/
│   │   ├── client.go          # Azure SDK wrapper
│   │   ├── functions.go       # Function App operations
│   │   ├── kudu.go            # Kudu SCM API
│   │   └── acr.go             # ACR for container images
│   │
│   └── gcp/
│       ├── client.go          # GCP SDK wrapper
│       ├── functions.go       # Cloud Functions operations
│       └── gcr.go             # GCR/Artifact Registry
│
└── scanner/
    └── scanner.go             # Core scanning logic
```

### Target Interface

```go
// Target represents a scannable serverless function
type Target interface {
    // GetMetadata returns function metadata for reporting
    GetMetadata(ctx context.Context) (*TargetMetadata, error)

    // Download fetches source code to local filesystem
    // Returns path to downloaded code (zip or directory)
    Download(ctx context.Context, outputDir string) (string, error)

    // GetContainerImage returns image reference for container deployments
    // Returns empty string for zip deployments
    GetContainerImage() string

    // Cleanup removes downloaded artifacts
    Cleanup() error
}

type TargetMetadata struct {
    // Common fields
    Cloud        string            `json:"cloud"`         // aws, azure, gcp
    Type         string            `json:"type"`          // lambda, azure-function, gcp-function
    Name         string            `json:"name"`
    ID           string            `json:"id"`            // ARN, ARM ID, or resource name
    Runtime      string            `json:"runtime"`
    Handler      string            `json:"handler,omitempty"`
    CodeHash     string            `json:"code_hash"`
    CodeSize     int64             `json:"code_size"`
    LastModified time.Time         `json:"last_modified"`
    Labels       map[string]string `json:"labels,omitempty"`

    // Cloud-specific metadata
    CloudSpecific map[string]interface{} `json:"cloud_specific,omitempty"`
}
```

---

## AWS Lambda Implementation (Reference)

Existing implementation for comparison.

### Authentication

```go
import (
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/lambda"
)

func NewAWSClient(ctx context.Context, region string) (*lambda.Client, error) {
    cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
    if err != nil {
        return nil, err
    }
    return lambda.NewFromConfig(cfg), nil
}
```

### Code Download

```go
func (t *LambdaTarget) Download(ctx context.Context, outputDir string) (string, error) {
    // GetFunction returns a presigned S3 URL (~10 min validity)
    result, err := t.client.GetFunction(ctx, &lambda.GetFunctionInput{
        FunctionName: aws.String(t.functionName),
    })
    if err != nil {
        return "", err
    }

    // Download from presigned URL (internal to customer's AWS)
    downloadURL := *result.Code.Location
    outputPath := filepath.Join(outputDir, t.functionName+".zip")

    if err := downloadFromURL(ctx, downloadURL, outputPath); err != nil {
        return "", err
    }

    return outputPath, nil
}
```

### Required IAM Permissions

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "lambda:GetFunction",
                "lambda:ListFunctions"
            ],
            "Resource": "*"
        }
    ]
}
```

### CLI Usage

```bash
# Scan single function
./qscanner --pod US2 lambda my-function-name

# Scan by ARN
./qscanner --pod US2 lambda arn:aws:lambda:us-west-2:123456789:function:my-function

# Environment variables
export AWS_REGION=us-west-2
export AWS_ACCESS_KEY_ID=...      # Or use IAM role
export AWS_SECRET_ACCESS_KEY=...
```

---

## Azure Functions Implementation (New)

### Go SDK Dependencies

```go
import (
    "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
    "github.com/Azure/azure-sdk-for-go/sdk/azcore"
    "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v4"
)
```

```bash
go get github.com/Azure/azure-sdk-for-go/sdk/azidentity@latest
go get github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v4@latest
```

### Authentication

```go
type AzureClient struct {
    credential     azcore.TokenCredential
    subscriptionID string
    webAppsClient  *armappservice.WebAppsClient
}

func NewAzureClient(ctx context.Context, subscriptionID string) (*AzureClient, error) {
    // DefaultAzureCredential tries in order:
    // 1. Environment variables (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
    // 2. Managed Identity
    // 3. Azure CLI credentials
    // 4. Visual Studio / VS Code credentials
    cred, err := azidentity.NewDefaultAzureCredential(nil)
    if err != nil {
        return nil, fmt.Errorf("azure auth failed: %w", err)
    }

    webAppsClient, err := armappservice.NewWebAppsClient(subscriptionID, cred, nil)
    if err != nil {
        return nil, err
    }

    return &AzureClient{
        credential:     cred,
        subscriptionID: subscriptionID,
        webAppsClient:  webAppsClient,
    }, nil
}
```

### Metadata Collection

```go
func (c *AzureClient) GetFunctionApp(ctx context.Context, resourceGroup, name string) (*AzureFunctionMetadata, error) {
    site, err := c.webAppsClient.Get(ctx, resourceGroup, name, nil)
    if err != nil {
        return nil, err
    }

    metadata := &AzureFunctionMetadata{
        SubscriptionID: c.subscriptionID,
        ResourceGroup:  resourceGroup,
        Name:           name,
        ID:             *site.ID,
    }

    // Parse Kind: "functionapp,linux" or "functionapp"
    if site.Kind != nil {
        metadata.IsLinux = strings.Contains(strings.ToLower(*site.Kind), "linux")
        metadata.IsContainer = strings.Contains(strings.ToLower(*site.Kind), "container")
    }

    // Get runtime from LinuxFxVersion: "DOTNET|8.0" or "DOCKER|image:tag"
    config, _ := c.webAppsClient.GetConfiguration(ctx, resourceGroup, name, nil)
    if config.Properties != nil && config.Properties.LinuxFxVersion != nil {
        parseLinuxFxVersion(metadata, *config.Properties.LinuxFxVersion)
    }

    // Get functions list
    metadata.Functions = c.listFunctions(ctx, resourceGroup, name)

    return metadata, nil
}
```

### Code Download (Bearer Token Auth)

```go
// GetSCMBearerToken returns a token for Kudu SCM authentication
// Uses classic management endpoint, not ARM
func (c *AzureClient) GetSCMBearerToken(ctx context.Context) (string, error) {
    token, err := c.credential.GetToken(ctx, policy.TokenRequestOptions{
        Scopes: []string{"https://management.core.windows.net/.default"},
    })
    if err != nil {
        return "", err
    }
    return token.Token, nil
}

func (t *AzureFunctionTarget) Download(ctx context.Context, outputDir string) (string, error) {
    token, err := t.client.GetSCMBearerToken(ctx)
    if err != nil {
        return "", fmt.Errorf("failed to get SCM token: %w", err)
    }

    // Kudu SCM zip endpoint
    scmURL := fmt.Sprintf("https://%s.scm.azurewebsites.net/api/zip/site/wwwroot/",
        t.metadata.Name)

    req, _ := http.NewRequestWithContext(ctx, "GET", scmURL, nil)
    req.Header.Set("Authorization", "Bearer "+token)

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusForbidden {
        // Try Linux path
        scmURL = fmt.Sprintf("https://%s.scm.azurewebsites.net/api/zip/home/site/wwwroot/",
            t.metadata.Name)
        req, _ = http.NewRequestWithContext(ctx, "GET", scmURL, nil)
        req.Header.Set("Authorization", "Bearer "+token)
        resp, err = http.DefaultClient.Do(req)
        if err != nil {
            return "", err
        }
        defer resp.Body.Close()
    }

    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
    }

    outputPath := filepath.Join(outputDir, t.metadata.Name+".zip")
    return outputPath, writeToFile(resp.Body, outputPath)
}
```

### Required Azure RBAC

```json
{
    "Name": "QScanner Function Reader",
    "Actions": [
        "Microsoft.Web/sites/read",
        "Microsoft.Web/sites/config/read",
        "Microsoft.Web/sites/functions/read",
        "Microsoft.Web/sites/publishxml/action"
    ],
    "AssignableScopes": ["/subscriptions/{subscription-id}"]
}
```

Or use built-in role: `Website Contributor`

### CLI Usage

```bash
# Scan single function app
./qscanner --pod US2 azure-function \
    --subscription <subscription-id> \
    --resource-group <rg-name> \
    <function-app-name>

# Scan by ARM resource ID
./qscanner --pod US2 azure-function \
    /subscriptions/.../providers/Microsoft.Web/sites/<name>

# Environment variables for Service Principal auth
export AZURE_SUBSCRIPTION_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
export AZURE_TENANT_ID=...

# Or use Managed Identity (automatic in Azure)
```

---

## GCP Cloud Functions Implementation (New)

### Go SDK Dependencies

```go
import (
    functions "cloud.google.com/go/functions/apiv2"
    functionspb "cloud.google.com/go/functions/apiv2/functionspb"
    "google.golang.org/api/iterator"
)
```

```bash
go get cloud.google.com/go/functions/apiv2@latest
```

### Authentication

```go
type GCPClient struct {
    functionsClient *functions.FunctionClient
    projectID       string
}

func NewGCPClient(ctx context.Context, projectID string) (*GCPClient, error) {
    // Application Default Credentials tries in order:
    // 1. GOOGLE_APPLICATION_CREDENTIALS env var (service account key file)
    // 2. gcloud CLI credentials
    // 3. Compute Engine metadata service
    // 4. GKE Workload Identity
    client, err := functions.NewFunctionClient(ctx)
    if err != nil {
        return nil, fmt.Errorf("gcp auth failed: %w", err)
    }

    return &GCPClient{
        functionsClient: client,
        projectID:       projectID,
    }, nil
}
```

### Metadata Collection

```go
func (c *GCPClient) GetFunction(ctx context.Context, name string) (*GCPFunctionMetadata, error) {
    fn, err := c.functionsClient.GetFunction(ctx, &functionspb.GetFunctionRequest{
        Name: name, // projects/{project}/locations/{location}/functions/{function}
    })
    if err != nil {
        return nil, err
    }

    metadata := &GCPFunctionMetadata{
        ResourceName: fn.Name,
        State:        fn.State.String(),
        URL:          fn.Url,
        Environment:  fn.Environment.String(), // GEN_1 or GEN_2
        Labels:       fn.Labels,
    }

    // Parse resource name
    parts := strings.Split(fn.Name, "/")
    if len(parts) >= 6 {
        metadata.ProjectID = parts[1]
        metadata.Location = parts[3]
        metadata.FunctionName = parts[5]
    }

    // Extract build config
    if fn.BuildConfig != nil {
        metadata.Runtime = fn.BuildConfig.Runtime
        metadata.EntryPoint = fn.BuildConfig.EntryPoint

        if fn.BuildConfig.SourceProvenance != nil {
            if ss := fn.BuildConfig.SourceProvenance.ResolvedStorageSource; ss != nil {
                metadata.SourceBucket = ss.Bucket
                metadata.SourceObject = ss.Object
            }
        }
    }

    return metadata, nil
}

// ListAllFunctions uses "-" as location wildcard
func (c *GCPClient) ListAllFunctions(ctx context.Context) ([]*GCPFunctionMetadata, error) {
    parent := fmt.Sprintf("projects/%s/locations/-", c.projectID)

    var results []*GCPFunctionMetadata
    it := c.functionsClient.ListFunctions(ctx, &functionspb.ListFunctionsRequest{
        Parent: parent,
    })

    for {
        fn, err := it.Next()
        if err == iterator.Done {
            break
        }
        if err != nil {
            return nil, err
        }
        metadata, _ := c.GetFunction(ctx, fn.Name)
        if metadata != nil {
            results = append(results, metadata)
        }
    }
    return results, nil
}
```

### Code Download (Signed URL)

```go
func (t *GCPFunctionTarget) Download(ctx context.Context, outputDir string) (string, error) {
    // Generate short-lived signed URL (valid ~minutes)
    resp, err := t.client.functionsClient.GenerateDownloadUrl(ctx,
        &functionspb.GenerateDownloadUrlRequest{
            Name: t.metadata.ResourceName,
        })
    if err != nil {
        return "", fmt.Errorf("failed to generate download URL: %w", err)
    }

    // Download immediately - URL expires quickly
    // URL is never logged or stored
    req, _ := http.NewRequestWithContext(ctx, "GET", resp.DownloadUrl, nil)
    httpResp, err := http.DefaultClient.Do(req)
    if err != nil {
        return "", err
    }
    defer httpResp.Body.Close()

    if httpResp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("download failed: HTTP %d", httpResp.StatusCode)
    }

    outputPath := filepath.Join(outputDir, t.metadata.FunctionName+".zip")
    return outputPath, writeToFile(httpResp.Body, outputPath)
}
```

### Required GCP IAM Permissions

```yaml
title: "QScanner Cloud Functions Reader"
includedPermissions:
  - cloudfunctions.functions.get
  - cloudfunctions.functions.list
  - cloudfunctions.functions.sourceCodeGet  # Required for GenerateDownloadUrl
  - cloudfunctions.locations.list
```

Or use predefined role: `roles/cloudfunctions.viewer` + custom for `sourceCodeGet`

### CLI Usage

```bash
# Scan single function
./qscanner --pod US2 gcp-function \
    projects/<project>/locations/<region>/functions/<name>

# Scan with explicit flags
./qscanner --pod US2 gcp-function \
    --project <project-id> \
    --location <region> \
    <function-name>

# Scan all in project (all regions)
./qscanner --pod US2 gcp-function --project <project-id>

# Environment variables
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
# Or use Workload Identity (automatic in GKE/Cloud Run)
```

---

## Security Implementation Details

### Secure Download Pattern

```go
func secureDownload(ctx context.Context, url, outputPath string) error {
    // 1. Create temp file with restricted permissions
    f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
    if err != nil {
        return err
    }
    defer f.Close()

    // 2. Download with timeout
    ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
    defer cancel()

    req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        os.Remove(outputPath)
        return err
    }
    defer resp.Body.Close()

    // 3. Calculate hash while writing
    hasher := sha256.New()
    writer := io.MultiWriter(f, hasher)

    if _, err := io.Copy(writer, resp.Body); err != nil {
        os.Remove(outputPath)
        return err
    }

    // 4. Return hash for integrity verification
    return nil
}
```

### Secure Cleanup Pattern

```go
func (t *Target) Cleanup() error {
    if t.codePath == "" {
        return nil
    }

    // Remove downloaded code (directory or file)
    if err := os.RemoveAll(t.codePath); err != nil {
        // Log but don't fail - best effort cleanup
        slog.Warn("Failed to cleanup code", "path", t.codePath, "error", err)
    }
    t.codePath = ""
    return nil
}

// Use defer to ensure cleanup
func scanFunction(ctx context.Context, target Target) (*ScanResult, error) {
    codePath, err := target.Download(ctx, "/tmp/qscanner")
    if err != nil {
        return nil, err
    }
    defer target.Cleanup() // Always cleanup, even on error

    return runScan(ctx, codePath)
}
```

### Never Log Sensitive Data

```go
func (c *Client) Download(ctx context.Context, url string) error {
    // WRONG: Don't log URLs (may contain tokens/signatures)
    // slog.Info("Downloading", "url", url)

    // RIGHT: Log sanitized info only
    slog.Info("Downloading function code",
        "function", c.functionName,
        "cloud", c.cloud)

    // WRONG: Don't log tokens
    // slog.Debug("Using token", "token", token)

    // RIGHT: Log token metadata only
    slog.Debug("Using bearer token",
        "expires_in", token.ExpiresOn.Sub(time.Now()))
}
```

---

## Comparison Matrix

| Feature | AWS Lambda | Azure Functions | GCP Cloud Functions |
|---------|------------|-----------------|---------------------|
| **Go SDK** | `aws-sdk-go-v2` | `azure-sdk-for-go` | `cloud.google.com/go` |
| **Auth** | IAM role | Managed Identity | ADC / Workload Identity |
| **Code Access** | Presigned S3 URL in GetFunction | Bearer token to Kudu SCM | GenerateDownloadUrl API |
| **URL Validity** | ~10 minutes | N/A (direct auth) | Minutes |
| **Container Registry** | ECR | ACR | GCR / Artifact Registry |
| **Resource ID Format** | ARN | ARM resource ID | Resource name path |
| **Multi-region List** | Per-region calls | Per-subscription | Wildcard `-` location |
| **Generations** | Single | N/A | 1st Gen / 2nd Gen |

---

## Testing Matrix

| Cloud | Runtime | Deployment | Test Case |
|-------|---------|------------|-----------|
| AWS | Node.js 20 | Zip | Scan npm packages |
| AWS | Python 3.12 | Zip | Scan pip packages |
| AWS | Node.js 20 | Container | Scan container image |
| Azure | Node.js 20 | Zip | Scan npm packages |
| Azure | .NET 8 | Zip | Scan NuGet packages |
| Azure | Python 3.11 | Container | Scan container image |
| GCP | Node.js 20 | Zip | Scan npm packages |
| GCP | Go 1.22 | Zip | Scan go.mod |
| GCP | Python 3.12 | Zip | Scan requirements.txt |

---

## Error Handling

### Unified Error Types

```go
type CloudError struct {
    Cloud     string // aws, azure, gcp
    Operation string // get_function, download, list
    Code      string // not_found, permission_denied, etc.
    Message   string
    Cause     error
}

func (e *CloudError) Error() string {
    return fmt.Sprintf("[%s] %s failed: %s (%s)", e.Cloud, e.Operation, e.Message, e.Code)
}

// Cloud-specific error mapping
func mapAWSError(err error) *CloudError { ... }
func mapAzureError(err error) *CloudError { ... }
func mapGCPError(err error) *CloudError { ... }
```

### Common Error Scenarios

| Error | AWS | Azure | GCP |
|-------|-----|-------|-----|
| Not Found | `ResourceNotFoundException` | `ResourceNotFoundError` | `codes.NotFound` |
| Permission Denied | `AccessDeniedException` | `AuthorizationFailedError` | `codes.PermissionDenied` |
| Auth Failed | `InvalidSignatureException` | `AuthenticationFailedError` | `codes.Unauthenticated` |
| Rate Limited | `TooManyRequestsException` | `429 response` | `codes.ResourceExhausted` |

---

## References

### AWS
- [AWS SDK for Go v2](https://pkg.go.dev/github.com/aws/aws-sdk-go-v2)
- [Lambda GetFunction API](https://docs.aws.amazon.com/lambda/latest/api/API_GetFunction.html)
- [Presigned URL Security](https://docs.aws.amazon.com/prescriptive-guidance/latest/presigned-url-best-practices/appendix-a.html)

### Azure
- [Azure SDK for Go](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk)
- [App Service REST API](https://learn.microsoft.com/en-us/rest/api/appservice/)
- [Kudu REST API](https://github.com/projectkudu/kudu/wiki/REST-API)
- [Kudu Bearer Token Auth](https://github.com/projectkudu/kudu/issues/2957)

### GCP
- [Cloud Functions Go SDK](https://pkg.go.dev/cloud.google.com/go/functions/apiv2)
- [Cloud Functions REST API](https://cloud.google.com/functions/docs/reference/rest)
- [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials)
- [Signed URL Security](https://cloud.google.com/storage/docs/access-control/signed-urls)
