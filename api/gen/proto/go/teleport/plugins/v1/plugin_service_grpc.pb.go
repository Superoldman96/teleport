// Copyright 2023 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             (unknown)
// source: teleport/plugins/v1/plugin_service.proto

package pluginsv1

import (
	context "context"
	types "github.com/gravitational/teleport/api/types"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	PluginService_CreatePlugin_FullMethodName                  = "/teleport.plugins.v1.PluginService/CreatePlugin"
	PluginService_GetPlugin_FullMethodName                     = "/teleport.plugins.v1.PluginService/GetPlugin"
	PluginService_UpdatePlugin_FullMethodName                  = "/teleport.plugins.v1.PluginService/UpdatePlugin"
	PluginService_DeletePlugin_FullMethodName                  = "/teleport.plugins.v1.PluginService/DeletePlugin"
	PluginService_ListPlugins_FullMethodName                   = "/teleport.plugins.v1.PluginService/ListPlugins"
	PluginService_SetPluginCredentials_FullMethodName          = "/teleport.plugins.v1.PluginService/SetPluginCredentials"
	PluginService_SetPluginStatus_FullMethodName               = "/teleport.plugins.v1.PluginService/SetPluginStatus"
	PluginService_GetAvailablePluginTypes_FullMethodName       = "/teleport.plugins.v1.PluginService/GetAvailablePluginTypes"
	PluginService_SearchPluginStaticCredentials_FullMethodName = "/teleport.plugins.v1.PluginService/SearchPluginStaticCredentials"
	PluginService_NeedsCleanup_FullMethodName                  = "/teleport.plugins.v1.PluginService/NeedsCleanup"
	PluginService_Cleanup_FullMethodName                       = "/teleport.plugins.v1.PluginService/Cleanup"
	PluginService_CreatePluginOauthToken_FullMethodName        = "/teleport.plugins.v1.PluginService/CreatePluginOauthToken"
)

// PluginServiceClient is the client API for PluginService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// PluginService provides CRUD operations for Plugin resources.
type PluginServiceClient interface {
	// CreatePlugin creates a new plugin instance.
	CreatePlugin(ctx context.Context, in *CreatePluginRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	// GetPlugin returns a plugin instance by name.
	GetPlugin(ctx context.Context, in *GetPluginRequest, opts ...grpc.CallOption) (*types.PluginV1, error)
	// UpdatePlugin updates a plugin instance.
	UpdatePlugin(ctx context.Context, in *UpdatePluginRequest, opts ...grpc.CallOption) (*types.PluginV1, error)
	// DeletePlugin removes the specified plugin instance.
	DeletePlugin(ctx context.Context, in *DeletePluginRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	// ListPlugins returns a paginated view of plugin instances.
	ListPlugins(ctx context.Context, in *ListPluginsRequest, opts ...grpc.CallOption) (*ListPluginsResponse, error)
	// SetPluginCredentials sets the credentials for the given plugin.
	SetPluginCredentials(ctx context.Context, in *SetPluginCredentialsRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	// SetPluginCredentials sets the status for the given plugin.
	SetPluginStatus(ctx context.Context, in *SetPluginStatusRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	// GetAvailablePluginTypes returns the types of plugins
	// that the auth server supports onboarding.
	GetAvailablePluginTypes(ctx context.Context, in *GetAvailablePluginTypesRequest, opts ...grpc.CallOption) (*GetAvailablePluginTypesResponse, error)
	// SearchPluginStaticCredentials returns static credentials that are searched
	// for. Only accessible by RoleAdmin and, in the case of Teleport Assist,
	// RoleProxy.
	SearchPluginStaticCredentials(ctx context.Context, in *SearchPluginStaticCredentialsRequest, opts ...grpc.CallOption) (*SearchPluginStaticCredentialsResponse, error)
	// NeedsCleanup will indicate whether a plugin of the given type needs cleanup
	// before it can be created.
	NeedsCleanup(ctx context.Context, in *NeedsCleanupRequest, opts ...grpc.CallOption) (*NeedsCleanupResponse, error)
	// Cleanup will clean up the resources for the given plugin type.
	Cleanup(ctx context.Context, in *CleanupRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	// CreatePluginOauthToken issues a short-lived OAuth access token for the specified plugin.
	//
	// This endpoint supports the OAuth 2.0 "client_credentials" grant type, where the plugin
	// authenticates using its client ID and client secret
	CreatePluginOauthToken(ctx context.Context, in *CreatePluginOauthTokenRequest, opts ...grpc.CallOption) (*CreatePluginOauthTokenResponse, error)
}

type pluginServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewPluginServiceClient(cc grpc.ClientConnInterface) PluginServiceClient {
	return &pluginServiceClient{cc}
}

func (c *pluginServiceClient) CreatePlugin(ctx context.Context, in *CreatePluginRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, PluginService_CreatePlugin_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pluginServiceClient) GetPlugin(ctx context.Context, in *GetPluginRequest, opts ...grpc.CallOption) (*types.PluginV1, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(types.PluginV1)
	err := c.cc.Invoke(ctx, PluginService_GetPlugin_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pluginServiceClient) UpdatePlugin(ctx context.Context, in *UpdatePluginRequest, opts ...grpc.CallOption) (*types.PluginV1, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(types.PluginV1)
	err := c.cc.Invoke(ctx, PluginService_UpdatePlugin_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pluginServiceClient) DeletePlugin(ctx context.Context, in *DeletePluginRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, PluginService_DeletePlugin_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pluginServiceClient) ListPlugins(ctx context.Context, in *ListPluginsRequest, opts ...grpc.CallOption) (*ListPluginsResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListPluginsResponse)
	err := c.cc.Invoke(ctx, PluginService_ListPlugins_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pluginServiceClient) SetPluginCredentials(ctx context.Context, in *SetPluginCredentialsRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, PluginService_SetPluginCredentials_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pluginServiceClient) SetPluginStatus(ctx context.Context, in *SetPluginStatusRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, PluginService_SetPluginStatus_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pluginServiceClient) GetAvailablePluginTypes(ctx context.Context, in *GetAvailablePluginTypesRequest, opts ...grpc.CallOption) (*GetAvailablePluginTypesResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GetAvailablePluginTypesResponse)
	err := c.cc.Invoke(ctx, PluginService_GetAvailablePluginTypes_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pluginServiceClient) SearchPluginStaticCredentials(ctx context.Context, in *SearchPluginStaticCredentialsRequest, opts ...grpc.CallOption) (*SearchPluginStaticCredentialsResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(SearchPluginStaticCredentialsResponse)
	err := c.cc.Invoke(ctx, PluginService_SearchPluginStaticCredentials_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pluginServiceClient) NeedsCleanup(ctx context.Context, in *NeedsCleanupRequest, opts ...grpc.CallOption) (*NeedsCleanupResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(NeedsCleanupResponse)
	err := c.cc.Invoke(ctx, PluginService_NeedsCleanup_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pluginServiceClient) Cleanup(ctx context.Context, in *CleanupRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, PluginService_Cleanup_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pluginServiceClient) CreatePluginOauthToken(ctx context.Context, in *CreatePluginOauthTokenRequest, opts ...grpc.CallOption) (*CreatePluginOauthTokenResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CreatePluginOauthTokenResponse)
	err := c.cc.Invoke(ctx, PluginService_CreatePluginOauthToken_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PluginServiceServer is the server API for PluginService service.
// All implementations must embed UnimplementedPluginServiceServer
// for forward compatibility.
//
// PluginService provides CRUD operations for Plugin resources.
type PluginServiceServer interface {
	// CreatePlugin creates a new plugin instance.
	CreatePlugin(context.Context, *CreatePluginRequest) (*emptypb.Empty, error)
	// GetPlugin returns a plugin instance by name.
	GetPlugin(context.Context, *GetPluginRequest) (*types.PluginV1, error)
	// UpdatePlugin updates a plugin instance.
	UpdatePlugin(context.Context, *UpdatePluginRequest) (*types.PluginV1, error)
	// DeletePlugin removes the specified plugin instance.
	DeletePlugin(context.Context, *DeletePluginRequest) (*emptypb.Empty, error)
	// ListPlugins returns a paginated view of plugin instances.
	ListPlugins(context.Context, *ListPluginsRequest) (*ListPluginsResponse, error)
	// SetPluginCredentials sets the credentials for the given plugin.
	SetPluginCredentials(context.Context, *SetPluginCredentialsRequest) (*emptypb.Empty, error)
	// SetPluginCredentials sets the status for the given plugin.
	SetPluginStatus(context.Context, *SetPluginStatusRequest) (*emptypb.Empty, error)
	// GetAvailablePluginTypes returns the types of plugins
	// that the auth server supports onboarding.
	GetAvailablePluginTypes(context.Context, *GetAvailablePluginTypesRequest) (*GetAvailablePluginTypesResponse, error)
	// SearchPluginStaticCredentials returns static credentials that are searched
	// for. Only accessible by RoleAdmin and, in the case of Teleport Assist,
	// RoleProxy.
	SearchPluginStaticCredentials(context.Context, *SearchPluginStaticCredentialsRequest) (*SearchPluginStaticCredentialsResponse, error)
	// NeedsCleanup will indicate whether a plugin of the given type needs cleanup
	// before it can be created.
	NeedsCleanup(context.Context, *NeedsCleanupRequest) (*NeedsCleanupResponse, error)
	// Cleanup will clean up the resources for the given plugin type.
	Cleanup(context.Context, *CleanupRequest) (*emptypb.Empty, error)
	// CreatePluginOauthToken issues a short-lived OAuth access token for the specified plugin.
	//
	// This endpoint supports the OAuth 2.0 "client_credentials" grant type, where the plugin
	// authenticates using its client ID and client secret
	CreatePluginOauthToken(context.Context, *CreatePluginOauthTokenRequest) (*CreatePluginOauthTokenResponse, error)
	mustEmbedUnimplementedPluginServiceServer()
}

// UnimplementedPluginServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedPluginServiceServer struct{}

func (UnimplementedPluginServiceServer) CreatePlugin(context.Context, *CreatePluginRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreatePlugin not implemented")
}
func (UnimplementedPluginServiceServer) GetPlugin(context.Context, *GetPluginRequest) (*types.PluginV1, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPlugin not implemented")
}
func (UnimplementedPluginServiceServer) UpdatePlugin(context.Context, *UpdatePluginRequest) (*types.PluginV1, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdatePlugin not implemented")
}
func (UnimplementedPluginServiceServer) DeletePlugin(context.Context, *DeletePluginRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeletePlugin not implemented")
}
func (UnimplementedPluginServiceServer) ListPlugins(context.Context, *ListPluginsRequest) (*ListPluginsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListPlugins not implemented")
}
func (UnimplementedPluginServiceServer) SetPluginCredentials(context.Context, *SetPluginCredentialsRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetPluginCredentials not implemented")
}
func (UnimplementedPluginServiceServer) SetPluginStatus(context.Context, *SetPluginStatusRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetPluginStatus not implemented")
}
func (UnimplementedPluginServiceServer) GetAvailablePluginTypes(context.Context, *GetAvailablePluginTypesRequest) (*GetAvailablePluginTypesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAvailablePluginTypes not implemented")
}
func (UnimplementedPluginServiceServer) SearchPluginStaticCredentials(context.Context, *SearchPluginStaticCredentialsRequest) (*SearchPluginStaticCredentialsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SearchPluginStaticCredentials not implemented")
}
func (UnimplementedPluginServiceServer) NeedsCleanup(context.Context, *NeedsCleanupRequest) (*NeedsCleanupResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method NeedsCleanup not implemented")
}
func (UnimplementedPluginServiceServer) Cleanup(context.Context, *CleanupRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Cleanup not implemented")
}
func (UnimplementedPluginServiceServer) CreatePluginOauthToken(context.Context, *CreatePluginOauthTokenRequest) (*CreatePluginOauthTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreatePluginOauthToken not implemented")
}
func (UnimplementedPluginServiceServer) mustEmbedUnimplementedPluginServiceServer() {}
func (UnimplementedPluginServiceServer) testEmbeddedByValue()                       {}

// UnsafePluginServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PluginServiceServer will
// result in compilation errors.
type UnsafePluginServiceServer interface {
	mustEmbedUnimplementedPluginServiceServer()
}

func RegisterPluginServiceServer(s grpc.ServiceRegistrar, srv PluginServiceServer) {
	// If the following call pancis, it indicates UnimplementedPluginServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&PluginService_ServiceDesc, srv)
}

func _PluginService_CreatePlugin_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreatePluginRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PluginServiceServer).CreatePlugin(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PluginService_CreatePlugin_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PluginServiceServer).CreatePlugin(ctx, req.(*CreatePluginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PluginService_GetPlugin_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetPluginRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PluginServiceServer).GetPlugin(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PluginService_GetPlugin_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PluginServiceServer).GetPlugin(ctx, req.(*GetPluginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PluginService_UpdatePlugin_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdatePluginRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PluginServiceServer).UpdatePlugin(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PluginService_UpdatePlugin_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PluginServiceServer).UpdatePlugin(ctx, req.(*UpdatePluginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PluginService_DeletePlugin_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeletePluginRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PluginServiceServer).DeletePlugin(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PluginService_DeletePlugin_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PluginServiceServer).DeletePlugin(ctx, req.(*DeletePluginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PluginService_ListPlugins_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListPluginsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PluginServiceServer).ListPlugins(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PluginService_ListPlugins_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PluginServiceServer).ListPlugins(ctx, req.(*ListPluginsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PluginService_SetPluginCredentials_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SetPluginCredentialsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PluginServiceServer).SetPluginCredentials(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PluginService_SetPluginCredentials_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PluginServiceServer).SetPluginCredentials(ctx, req.(*SetPluginCredentialsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PluginService_SetPluginStatus_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SetPluginStatusRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PluginServiceServer).SetPluginStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PluginService_SetPluginStatus_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PluginServiceServer).SetPluginStatus(ctx, req.(*SetPluginStatusRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PluginService_GetAvailablePluginTypes_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAvailablePluginTypesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PluginServiceServer).GetAvailablePluginTypes(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PluginService_GetAvailablePluginTypes_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PluginServiceServer).GetAvailablePluginTypes(ctx, req.(*GetAvailablePluginTypesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PluginService_SearchPluginStaticCredentials_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SearchPluginStaticCredentialsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PluginServiceServer).SearchPluginStaticCredentials(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PluginService_SearchPluginStaticCredentials_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PluginServiceServer).SearchPluginStaticCredentials(ctx, req.(*SearchPluginStaticCredentialsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PluginService_NeedsCleanup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(NeedsCleanupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PluginServiceServer).NeedsCleanup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PluginService_NeedsCleanup_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PluginServiceServer).NeedsCleanup(ctx, req.(*NeedsCleanupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PluginService_Cleanup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CleanupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PluginServiceServer).Cleanup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PluginService_Cleanup_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PluginServiceServer).Cleanup(ctx, req.(*CleanupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PluginService_CreatePluginOauthToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreatePluginOauthTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PluginServiceServer).CreatePluginOauthToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PluginService_CreatePluginOauthToken_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PluginServiceServer).CreatePluginOauthToken(ctx, req.(*CreatePluginOauthTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// PluginService_ServiceDesc is the grpc.ServiceDesc for PluginService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var PluginService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "teleport.plugins.v1.PluginService",
	HandlerType: (*PluginServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreatePlugin",
			Handler:    _PluginService_CreatePlugin_Handler,
		},
		{
			MethodName: "GetPlugin",
			Handler:    _PluginService_GetPlugin_Handler,
		},
		{
			MethodName: "UpdatePlugin",
			Handler:    _PluginService_UpdatePlugin_Handler,
		},
		{
			MethodName: "DeletePlugin",
			Handler:    _PluginService_DeletePlugin_Handler,
		},
		{
			MethodName: "ListPlugins",
			Handler:    _PluginService_ListPlugins_Handler,
		},
		{
			MethodName: "SetPluginCredentials",
			Handler:    _PluginService_SetPluginCredentials_Handler,
		},
		{
			MethodName: "SetPluginStatus",
			Handler:    _PluginService_SetPluginStatus_Handler,
		},
		{
			MethodName: "GetAvailablePluginTypes",
			Handler:    _PluginService_GetAvailablePluginTypes_Handler,
		},
		{
			MethodName: "SearchPluginStaticCredentials",
			Handler:    _PluginService_SearchPluginStaticCredentials_Handler,
		},
		{
			MethodName: "NeedsCleanup",
			Handler:    _PluginService_NeedsCleanup_Handler,
		},
		{
			MethodName: "Cleanup",
			Handler:    _PluginService_Cleanup_Handler,
		},
		{
			MethodName: "CreatePluginOauthToken",
			Handler:    _PluginService_CreatePluginOauthToken_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "teleport/plugins/v1/plugin_service.proto",
}
