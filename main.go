package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"strings"

	workflowservice "go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/server/common/api"
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/config"
	"go.temporal.io/server/common/dynamicconfig"
	tlog "go.temporal.io/server/common/log"
	"go.temporal.io/server/temporal"
)

// CustomClaimMapper maps JWT claims with "custom" field to Temporal Claims
type CustomClaimMapper struct{}

func NewCustomClaimMapper() *CustomClaimMapper {
	return &CustomClaimMapper{}
}

// GetClaims implements authorization.ClaimMapper interface
func (c *CustomClaimMapper) GetClaims(authInfo *authorization.AuthInfo) (*authorization.Claims, error) {
	claims := &authorization.Claims{
		System:     authorization.RoleUndefined,
		Namespaces: make(map[string]authorization.Role),
	}

	if authInfo == nil || authInfo.AuthToken == "" {
		log.Println("[CustomClaimMapper] No auth token provided")
		return claims, nil
	}

	// Parse the JWT token to extract the "custom" field
	customPermissions, subject, err := parseJWTCustomField(authInfo.AuthToken)
	if err != nil {
		log.Printf("[CustomClaimMapper] Error parsing JWT: %v", err)
		return claims, nil
	}

	claims.Subject = subject

	// Track if any valid permission was found
	hasValidPermission := false

	// Map custom permissions to Temporal roles
	for _, perm := range customPermissions {
		switch perm {
		case "admin":
			// "admin" = temporal-system: admin (full admin access to everything)
			claims.System = authorization.RoleAdmin
			hasValidPermission = true
			log.Printf("[CustomClaimMapper] Mapped 'admin' -> System Admin role")
		case "only-default-read":
			// "only-default-read" = default: read (read access to default namespace)
			claims.Namespaces["default"] = authorization.RoleReader
			hasValidPermission = true
			log.Printf("[CustomClaimMapper] Mapped 'only-default-read' -> default namespace Reader role")
		default:
			log.Printf("[CustomClaimMapper] Unknown permission '%s' - ignoring", perm)
		}
	}

	if !hasValidPermission {
		log.Println("[CustomClaimMapper] No valid permissions found in token")
	}

	return claims, nil
}

// parseJWTCustomField extracts the "custom" array and subject from a JWT token
func parseJWTCustomField(authToken string) ([]string, string, error) {
	// Remove "Bearer " prefix if present
	token := authToken
	if strings.HasPrefix(strings.ToLower(authToken), "bearer ") {
		token = authToken[7:]
	}

	// JWT format: header.payload.signature
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, "", fmt.Errorf("invalid JWT format")
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Try with standard base64
		payload, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, "", fmt.Errorf("failed to decode JWT payload:  %v", err)
		}
	}

	// Parse JSON payload
	var jwtClaims map[string]interface{}
	if err := json.Unmarshal(payload, &jwtClaims); err != nil {
		return nil, "", fmt.Errorf("failed to parse JWT claims:  %v", err)
	}

	// Extract subject
	subject, _ := jwtClaims["sub"].(string)

	// Extract "custom" field
	customField, ok := jwtClaims["custom"]
	if !ok {
		return nil, subject, nil
	}

	customArray, ok := customField.([]interface{})
	if !ok {
		return nil, subject, fmt.Errorf("custom field is not an array")
	}

	var permissions []string
	for _, item := range customArray {
		if str, ok := item.(string); ok {
			permissions = append(permissions, str)
		}
	}

	return permissions, subject, nil
}

// CustomAuthorizer authorizes requests based on mapped claims
// Uses Temporal's built-in api.GetMethodMetadata() to determine access requirements
type CustomAuthorizer struct{}

func NewCustomAuthorizer() *CustomAuthorizer {
	return &CustomAuthorizer{}
}

func (a *CustomAuthorizer) Authorize(
	ctx context.Context,
	claims *authorization.Claims,
	target *authorization.CallTarget,
) (authorization.Result, error) {
	fmt.Printf("[CustomAuth] API:  %s, Namespace: %s\n", target.APIName, target.Namespace)

	// Extract WorkflowType based on the API being called
	workflowType := extractWorkflowType(target)
	if workflowType != "" {
		fmt.Printf("[CustomAuth] WorkflowType: %s\n", workflowType)
	}

	if claims != nil {
		fmt.Printf("[CustomAuth] Subject: %s\n", claims.Subject)
		fmt.Printf("[CustomAuth] System Role: %s\n", roleToString(claims.System))

		fmt.Println("[CustomAuth] Namespace Roles:")
		for ns, role := range claims.Namespaces {
			fmt.Printf("  - %s: %s\n", ns, roleToString(role))
		}
	}

	// Health check APIs are always allowed (same as default authorizer)
	if authorization.IsHealthCheckAPI(target.APIName) {
		fmt.Println("[CustomAuth] Health check API - Access GRANTED")
		return authorization.Result{Decision: authorization.DecisionAllow}, nil
	}

	// If no claims provided, deny access
	if claims == nil {
		fmt.Println("[CustomAuth] No claims provided - Access DENIED")
		return authorization.Result{Decision: authorization.DecisionDeny}, nil
	}

	// Check if user has system admin role (from "admin" permission)
	if claims.System == authorization.RoleAdmin {
		fmt.Println("[CustomAuth] System Admin - Access GRANTED")
		return authorization.Result{Decision: authorization.DecisionAllow}, nil
	}

	// Get the API metadata from Temporal's built-in registry
	metadata := api.GetMethodMetadata(target.APIName)

	// Determine the user's role for this target
	var hasRole authorization.Role
	switch metadata.Scope {
	case api.ScopeCluster:
		// Cluster-scoped APIs only check system-level roles
		hasRole = claims.System
	case api.ScopeNamespace:
		// Namespace-scoped APIs check both system and namespace roles
		hasRole = claims.System | claims.Namespaces[target.Namespace]
	default:
		// Unknown scope - deny
		fmt.Printf("[CustomAuth] Unknown API scope - Access DENIED\n")
		return authorization.Result{Decision: authorization.DecisionDeny}, nil
	}

	// Check if the user's role meets the required access level
	requiredRole := getRequiredRole(metadata.Access)
	if hasRole >= requiredRole {
		fmt.Printf("[CustomAuth] Role check passed (has:  %s, required: %s) - Access GRANTED\n",
			roleToString(hasRole), roleToString(requiredRole))
		return authorization.Result{Decision: authorization.DecisionAllow}, nil
	}

	fmt.Printf("[CustomAuth] Role check failed (has: %s, required: %s) - Access DENIED\n",
		roleToString(hasRole), roleToString(requiredRole))
	return authorization.Result{Decision: authorization.DecisionDeny}, nil
}

func extractWorkflowType(target *authorization.CallTarget) string {
	if target.Request == nil {
		return ""
	}

	switch req := target.Request.(type) {
	// StartWorkflowExecution
	case *workflowservice.StartWorkflowExecutionRequest:
		return req.GetWorkflowType().GetName()

	// SignalWithStartWorkflowExecution
	case *workflowservice.SignalWithStartWorkflowExecutionRequest:
		return req.GetWorkflowType().GetName()

	// ExecuteMultiOperation (can contain StartWorkflow)
	case *workflowservice.ExecuteMultiOperationRequest:
		for _, op := range req.GetOperations() {
			if startReq := op.GetStartWorkflow(); startReq != nil {
				return startReq.GetWorkflowType().GetName()
			}
		}

	// For listing/describing workflows, you might want to filter based on query
	case *workflowservice.ListWorkflowExecutionsRequest:
		// You could parse the Query field to extract WorkflowType filter
		return "" // Query parsing would be needed

	// DescribeWorkflowExecution - workflow type not directly available in request
	// but you could look it up if needed
	case *workflowservice.DescribeWorkflowExecutionRequest:
		return ""

	// For TaskQueue-based operations, WorkflowType comes from the task itself
	case *workflowservice.PollWorkflowTaskQueueRequest:
		return "" // WorkflowType is not known until task is returned

	// RespondWorkflowTaskCompleted - can contain child workflow starts
	case *workflowservice.RespondWorkflowTaskCompletedRequest:
		// Check commands for child workflow starts
		for _, cmd := range req.GetCommands() {
			if attr := cmd.GetStartChildWorkflowExecutionCommandAttributes(); attr != nil {
				return attr.GetWorkflowType().GetName()
			}
		}
	}

	return ""
}

// getRequiredRole converts api.Access to authorization. Role
func getRequiredRole(access api.Access) authorization.Role {
	switch access {
	case api.AccessReadOnly:
		return authorization.RoleReader
	case api.AccessWrite:
		return authorization.RoleWriter
	default:
		return authorization.RoleAdmin
	}
}

func roleToString(role authorization.Role) string {
	if role == authorization.RoleUndefined {
		return "Undefined (no permissions)"
	}

	var roles []string
	if role&authorization.RoleAdmin != 0 {
		roles = append(roles, "Admin")
	}
	if role&authorization.RoleWriter != 0 {
		roles = append(roles, "Writer")
	}
	if role&authorization.RoleReader != 0 {
		roles = append(roles, "Reader")
	}
	if role&authorization.RoleWorker != 0 {
		roles = append(roles, "Worker")
	}
	return strings.Join(roles, " | ")
}

func getServices() []string {
	env := os.Getenv("SERVICES")
	if env == "" {
		return temporal.DefaultServices
	}
	env = strings.ReplaceAll(env, ":", ",")
	var result []string
	for _, s := range strings.Split(env, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

func main() {
	log.Println("Starting Temporal with Custom Authorizer and ClaimMapper...")

	configDir := path.Join(os.Getenv("TEMPORAL_ROOT"), os.Getenv("TEMPORAL_CONFIG_DIR"))
	if configDir == "" || configDir == "/" {
		configDir = "/etc/temporal/config"
	}

	cfg, err := config.LoadConfig("docker", configDir, "")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	logger := tlog.NewZapLogger(tlog.BuildZapLogger(cfg.Log))

	var dynCfgClient dynamicconfig.Client
	if cfg.DynamicConfigClient != nil {
		dynCfgClient, err = dynamicconfig.NewFileBasedClient(cfg.DynamicConfigClient, logger, temporal.InterruptCh())
		if err != nil {
			log.Fatalf("Failed to create dynamic config:  %v", err)
		}
	} else {
		dynCfgClient = dynamicconfig.NewNoopClient()
	}

	services := getServices()
	log.Printf("Starting services: %v", services)

	server, err := temporal.NewServer(
		temporal.ForServices(services),
		temporal.WithConfig(cfg),
		temporal.WithLogger(logger),
		temporal.WithDynamicConfigClient(dynCfgClient),
		// WithClaimMapper expects a function that takes *config.Config and returns ClaimMapper
		temporal.WithClaimMapper(func(_ *config.Config) authorization.ClaimMapper {
			return NewCustomClaimMapper()
		}),
		temporal.WithAuthorizer(NewCustomAuthorizer()),
		temporal.InterruptOn(temporal.InterruptCh()),
	)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
