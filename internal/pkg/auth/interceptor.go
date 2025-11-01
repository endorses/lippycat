package auth

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// methodRoles defines the required role for each gRPC method.
var methodRoles = map[string]Role{
	// Data service methods
	"/data.DataService/RegisterHunter":     RoleHunter,
	"/data.DataService/SendPacketBatch":    RoleHunter,
	"/data.DataService/SubscribeToPackets": RoleSubscriber,
	"/data.DataService/GetTopology":        RoleSubscriber,
	"/data.DataService/TopologyUpdates":    RoleSubscriber,

	// Management service methods
	"/management.ManagementService/GetHealth":             RoleSubscriber,
	"/management.ManagementService/GetMetrics":            RoleSubscriber,
	"/management.ManagementService/GetHunters":            RoleSubscriber,
	"/management.ManagementService/GetCalls":              RoleSubscriber,
	"/management.ManagementService/UpdateCallFilters":     RoleAdmin,
	"/management.ManagementService/UpdateProtocolFilters": RoleAdmin,
	"/management.ManagementService/GetProcessorInfo":      RoleSubscriber,
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
