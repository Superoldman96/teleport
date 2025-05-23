// Copyright 2025 Gravitational, Inc
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

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        (unknown)
// source: teleport/workloadidentity/v1/revocation_resource.proto

package workloadidentityv1

import (
	v1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// WorkloadIdentityX509Revocation represents the revocation of a single X509
// workload identity credential. Creating or deleting these resources triggers
// the regeneration of the trust domain CRL.
//
// The name of a WorkloadIdentityX509Revocation must be the base16, lower case,
// encoded serial number of the revoked X509 certificate. Therefore, only a
// single revocation entry can exist for a given certificate.
type WorkloadIdentityX509Revocation struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The kind of resource represented. For WorkloadIdentityX509Revocation
	// resources, this is always `workload_identity_x509_revocation`.
	Kind string `protobuf:"bytes,1,opt,name=kind,proto3" json:"kind,omitempty"`
	// Differentiates variations of the same kind. All resources should
	// contain one, even if it is never populated.
	SubKind string `protobuf:"bytes,2,opt,name=sub_kind,json=subKind,proto3" json:"sub_kind,omitempty"`
	// The version of the resource being represented.
	Version string `protobuf:"bytes,3,opt,name=version,proto3" json:"version,omitempty"`
	// Common metadata that all resources share.
	Metadata *v1.Metadata `protobuf:"bytes,4,opt,name=metadata,proto3" json:"metadata,omitempty"`
	// The configured properties of the WorkloadIdentityX509Revocation
	Spec          *WorkloadIdentityX509RevocationSpec `protobuf:"bytes,5,opt,name=spec,proto3" json:"spec,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *WorkloadIdentityX509Revocation) Reset() {
	*x = WorkloadIdentityX509Revocation{}
	mi := &file_teleport_workloadidentity_v1_revocation_resource_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *WorkloadIdentityX509Revocation) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WorkloadIdentityX509Revocation) ProtoMessage() {}

func (x *WorkloadIdentityX509Revocation) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_workloadidentity_v1_revocation_resource_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WorkloadIdentityX509Revocation.ProtoReflect.Descriptor instead.
func (*WorkloadIdentityX509Revocation) Descriptor() ([]byte, []int) {
	return file_teleport_workloadidentity_v1_revocation_resource_proto_rawDescGZIP(), []int{0}
}

func (x *WorkloadIdentityX509Revocation) GetKind() string {
	if x != nil {
		return x.Kind
	}
	return ""
}

func (x *WorkloadIdentityX509Revocation) GetSubKind() string {
	if x != nil {
		return x.SubKind
	}
	return ""
}

func (x *WorkloadIdentityX509Revocation) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *WorkloadIdentityX509Revocation) GetMetadata() *v1.Metadata {
	if x != nil {
		return x.Metadata
	}
	return nil
}

func (x *WorkloadIdentityX509Revocation) GetSpec() *WorkloadIdentityX509RevocationSpec {
	if x != nil {
		return x.Spec
	}
	return nil
}

// Configuration specific to WorkloadIdentityX509Revocation.
type WorkloadIdentityX509RevocationSpec struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Describes why this revocation entry was created.
	// Required.
	Reason string `protobuf:"bytes,1,opt,name=reason,proto3" json:"reason,omitempty"`
	// The time at which the revocation entry was created.
	// Required.
	RevokedAt     *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=revoked_at,json=revokedAt,proto3" json:"revoked_at,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *WorkloadIdentityX509RevocationSpec) Reset() {
	*x = WorkloadIdentityX509RevocationSpec{}
	mi := &file_teleport_workloadidentity_v1_revocation_resource_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *WorkloadIdentityX509RevocationSpec) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WorkloadIdentityX509RevocationSpec) ProtoMessage() {}

func (x *WorkloadIdentityX509RevocationSpec) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_workloadidentity_v1_revocation_resource_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WorkloadIdentityX509RevocationSpec.ProtoReflect.Descriptor instead.
func (*WorkloadIdentityX509RevocationSpec) Descriptor() ([]byte, []int) {
	return file_teleport_workloadidentity_v1_revocation_resource_proto_rawDescGZIP(), []int{1}
}

func (x *WorkloadIdentityX509RevocationSpec) GetReason() string {
	if x != nil {
		return x.Reason
	}
	return ""
}

func (x *WorkloadIdentityX509RevocationSpec) GetRevokedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.RevokedAt
	}
	return nil
}

var File_teleport_workloadidentity_v1_revocation_resource_proto protoreflect.FileDescriptor

const file_teleport_workloadidentity_v1_revocation_resource_proto_rawDesc = "" +
	"\n" +
	"6teleport/workloadidentity/v1/revocation_resource.proto\x12\x1cteleport.workloadidentity.v1\x1a\x1fgoogle/protobuf/timestamp.proto\x1a!teleport/header/v1/metadata.proto\"\xf9\x01\n" +
	"\x1eWorkloadIdentityX509Revocation\x12\x12\n" +
	"\x04kind\x18\x01 \x01(\tR\x04kind\x12\x19\n" +
	"\bsub_kind\x18\x02 \x01(\tR\asubKind\x12\x18\n" +
	"\aversion\x18\x03 \x01(\tR\aversion\x128\n" +
	"\bmetadata\x18\x04 \x01(\v2\x1c.teleport.header.v1.MetadataR\bmetadata\x12T\n" +
	"\x04spec\x18\x05 \x01(\v2@.teleport.workloadidentity.v1.WorkloadIdentityX509RevocationSpecR\x04spec\"w\n" +
	"\"WorkloadIdentityX509RevocationSpec\x12\x16\n" +
	"\x06reason\x18\x01 \x01(\tR\x06reason\x129\n" +
	"\n" +
	"revoked_at\x18\x02 \x01(\v2\x1a.google.protobuf.TimestampR\trevokedAtBdZbgithub.com/gravitational/teleport/api/gen/proto/go/teleport/workloadidentity/v1;workloadidentityv1b\x06proto3"

var (
	file_teleport_workloadidentity_v1_revocation_resource_proto_rawDescOnce sync.Once
	file_teleport_workloadidentity_v1_revocation_resource_proto_rawDescData []byte
)

func file_teleport_workloadidentity_v1_revocation_resource_proto_rawDescGZIP() []byte {
	file_teleport_workloadidentity_v1_revocation_resource_proto_rawDescOnce.Do(func() {
		file_teleport_workloadidentity_v1_revocation_resource_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_teleport_workloadidentity_v1_revocation_resource_proto_rawDesc), len(file_teleport_workloadidentity_v1_revocation_resource_proto_rawDesc)))
	})
	return file_teleport_workloadidentity_v1_revocation_resource_proto_rawDescData
}

var file_teleport_workloadidentity_v1_revocation_resource_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_teleport_workloadidentity_v1_revocation_resource_proto_goTypes = []any{
	(*WorkloadIdentityX509Revocation)(nil),     // 0: teleport.workloadidentity.v1.WorkloadIdentityX509Revocation
	(*WorkloadIdentityX509RevocationSpec)(nil), // 1: teleport.workloadidentity.v1.WorkloadIdentityX509RevocationSpec
	(*v1.Metadata)(nil),                        // 2: teleport.header.v1.Metadata
	(*timestamppb.Timestamp)(nil),              // 3: google.protobuf.Timestamp
}
var file_teleport_workloadidentity_v1_revocation_resource_proto_depIdxs = []int32{
	2, // 0: teleport.workloadidentity.v1.WorkloadIdentityX509Revocation.metadata:type_name -> teleport.header.v1.Metadata
	1, // 1: teleport.workloadidentity.v1.WorkloadIdentityX509Revocation.spec:type_name -> teleport.workloadidentity.v1.WorkloadIdentityX509RevocationSpec
	3, // 2: teleport.workloadidentity.v1.WorkloadIdentityX509RevocationSpec.revoked_at:type_name -> google.protobuf.Timestamp
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_teleport_workloadidentity_v1_revocation_resource_proto_init() }
func file_teleport_workloadidentity_v1_revocation_resource_proto_init() {
	if File_teleport_workloadidentity_v1_revocation_resource_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_teleport_workloadidentity_v1_revocation_resource_proto_rawDesc), len(file_teleport_workloadidentity_v1_revocation_resource_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_workloadidentity_v1_revocation_resource_proto_goTypes,
		DependencyIndexes: file_teleport_workloadidentity_v1_revocation_resource_proto_depIdxs,
		MessageInfos:      file_teleport_workloadidentity_v1_revocation_resource_proto_msgTypes,
	}.Build()
	File_teleport_workloadidentity_v1_revocation_resource_proto = out.File
	file_teleport_workloadidentity_v1_revocation_resource_proto_goTypes = nil
	file_teleport_workloadidentity_v1_revocation_resource_proto_depIdxs = nil
}
