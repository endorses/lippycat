package auth

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Skip authentication if disabled
		if !validator.IsEnabled() {
			return handler(ctx, req)
		}

		// Get required role for this method
		requiredRole, ok := methodRoles[info.FullMethod]
		if !ok {
			// Unknown method - default to admin role for safety
			requiredRole = RoleAdmin
		}

		// Validate API key
		_, err := validator.ValidateContext(ctx, requiredRole)
		if err != nil {
			LogAuthFailure(ctx, err, info.FullMethod)
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}

		// Call the actual handler
		return handler(ctx, req)
	}
}

// StreamServerInterceptor returns a gRPC stream interceptor for API key authentication.
func StreamServerInterceptor(validator *Validator) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Skip authentication if disabled
		if !validator.IsEnabled() {
			return handler(srv, ss)
		}

		// Get required role for this method
		requiredRole, ok := methodRoles[info.FullMethod]
		if !ok {
			// Unknown method - default to admin role for safety
			requiredRole = RoleAdmin
		}

		// Validate API key
		ctx := ss.Context()
		_, err := validator.ValidateContext(ctx, requiredRole)
		if err != nil {
			LogAuthFailure(ctx, err, info.FullMethod)
			return status.Error(codes.Unauthenticated, err.Error())
		}

		// Call the actual handler
		return handler(srv, ss)
	}
}
