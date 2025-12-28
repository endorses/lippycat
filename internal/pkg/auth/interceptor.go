package auth

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// InterceptorConfig holds configuration for auth interceptors.
type InterceptorConfig struct {
	Validator   *Validator
	RateLimiter *RateLimiter // Optional, if nil rate limiting is disabled
}

// methodRoles defines the required role for each gRPC method.
// Method paths must match the proto package names exactly.
var methodRoles = map[string]Role{
	// Data service methods (lippycat.data package)
	"/lippycat.data.DataService/StreamPackets":            RoleHunter,
	"/lippycat.data.DataService/SubscribePackets":         RoleSubscriber,
	"/lippycat.data.DataService/SubscribeCorrelatedCalls": RoleSubscriber,

	// Management service methods (lippycat.management package)
	"/lippycat.management.ManagementService/RegisterHunter":          RoleHunter,
	"/lippycat.management.ManagementService/RegisterProcessor":       RoleHunter,
	"/lippycat.management.ManagementService/Heartbeat":               RoleHunter,
	"/lippycat.management.ManagementService/GetFilters":              RoleHunter,
	"/lippycat.management.ManagementService/SubscribeFilters":        RoleHunter,
	"/lippycat.management.ManagementService/GetHunterStatus":         RoleSubscriber,
	"/lippycat.management.ManagementService/UpdateFilter":            RoleAdmin,
	"/lippycat.management.ManagementService/DeleteFilter":            RoleAdmin,
	"/lippycat.management.ManagementService/ListAvailableHunters":    RoleSubscriber,
	"/lippycat.management.ManagementService/GetTopology":             RoleSubscriber,
	"/lippycat.management.ManagementService/SubscribeTopology":       RoleSubscriber,
	"/lippycat.management.ManagementService/UpdateFilterOnProcessor": RoleAdmin,
	"/lippycat.management.ManagementService/DeleteFilterOnProcessor": RoleAdmin,
	"/lippycat.management.ManagementService/GetFiltersFromProcessor": RoleSubscriber,
	"/lippycat.management.ManagementService/RequestAuthToken":        RoleSubscriber,
}

// UnaryServerInterceptor returns a gRPC unary interceptor for API key authentication.
func UnaryServerInterceptor(validator *Validator) grpc.UnaryServerInterceptor {
	return UnaryServerInterceptorWithConfig(InterceptorConfig{Validator: validator})
}

// UnaryServerInterceptorWithConfig returns a gRPC unary interceptor with rate limiting support.
func UnaryServerInterceptorWithConfig(config InterceptorConfig) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Skip authentication if disabled
		if !config.Validator.IsEnabled() {
			return handler(ctx, req)
		}

		// Check rate limiting first
		if config.RateLimiter != nil && config.RateLimiter.IsBlocked(ctx) {
			LogAuthFailure(ctx, ErrRateLimited, info.FullMethod)
			return nil, status.Error(codes.ResourceExhausted, ErrRateLimited.Error())
		}

		// Get required role for this method
		requiredRole, ok := methodRoles[info.FullMethod]
		if !ok {
			// Unknown method - default to admin role for safety
			requiredRole = RoleAdmin
		}

		// Validate API key
		_, err := config.Validator.ValidateContext(ctx, requiredRole)
		if err != nil {
			LogAuthFailure(ctx, err, info.FullMethod)
			if config.RateLimiter != nil {
				config.RateLimiter.RecordFailure(ctx)
			}
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}

		// Clear failure count on success
		if config.RateLimiter != nil {
			config.RateLimiter.RecordSuccess(ctx)
		}

		// Call the actual handler
		return handler(ctx, req)
	}
}

// StreamServerInterceptor returns a gRPC stream interceptor for API key authentication.
func StreamServerInterceptor(validator *Validator) grpc.StreamServerInterceptor {
	return StreamServerInterceptorWithConfig(InterceptorConfig{Validator: validator})
}

// StreamServerInterceptorWithConfig returns a gRPC stream interceptor with rate limiting support.
func StreamServerInterceptorWithConfig(config InterceptorConfig) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Skip authentication if disabled
		if !config.Validator.IsEnabled() {
			return handler(srv, ss)
		}

		ctx := ss.Context()

		// Check rate limiting first
		if config.RateLimiter != nil && config.RateLimiter.IsBlocked(ctx) {
			LogAuthFailure(ctx, ErrRateLimited, info.FullMethod)
			return status.Error(codes.ResourceExhausted, ErrRateLimited.Error())
		}

		// Get required role for this method
		requiredRole, ok := methodRoles[info.FullMethod]
		if !ok {
			// Unknown method - default to admin role for safety
			requiredRole = RoleAdmin
		}

		// Validate API key
		_, err := config.Validator.ValidateContext(ctx, requiredRole)
		if err != nil {
			LogAuthFailure(ctx, err, info.FullMethod)
			if config.RateLimiter != nil {
				config.RateLimiter.RecordFailure(ctx)
			}
			return status.Error(codes.Unauthenticated, err.Error())
		}

		// Clear failure count on success
		if config.RateLimiter != nil {
			config.RateLimiter.RecordSuccess(ctx)
		}

		// Call the actual handler
		return handler(srv, ss)
	}
}
