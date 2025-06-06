// Copyright 2022 Gravitational, Inc
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
// source: teleport/devicetrust/v1/user_certificates.proto

package devicetrustv1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
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

// UserCertificates is used to transport X.509 and SSH certificates during
// device authentication.
// See the AuthenticateDevice RPC.
type UserCertificates struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// DER-encoded X.509 user certificate.
	X509Der []byte `protobuf:"bytes,1,opt,name=x509_der,json=x509Der,proto3" json:"x509_der,omitempty"`
	// SSH certificate marshaled in the authorized key format.
	SshAuthorizedKey []byte `protobuf:"bytes,2,opt,name=ssh_authorized_key,json=sshAuthorizedKey,proto3" json:"ssh_authorized_key,omitempty"`
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

func (x *UserCertificates) Reset() {
	*x = UserCertificates{}
	mi := &file_teleport_devicetrust_v1_user_certificates_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *UserCertificates) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UserCertificates) ProtoMessage() {}

func (x *UserCertificates) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_devicetrust_v1_user_certificates_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UserCertificates.ProtoReflect.Descriptor instead.
func (*UserCertificates) Descriptor() ([]byte, []int) {
	return file_teleport_devicetrust_v1_user_certificates_proto_rawDescGZIP(), []int{0}
}

func (x *UserCertificates) GetX509Der() []byte {
	if x != nil {
		return x.X509Der
	}
	return nil
}

func (x *UserCertificates) GetSshAuthorizedKey() []byte {
	if x != nil {
		return x.SshAuthorizedKey
	}
	return nil
}

var File_teleport_devicetrust_v1_user_certificates_proto protoreflect.FileDescriptor

const file_teleport_devicetrust_v1_user_certificates_proto_rawDesc = "" +
	"\n" +
	"/teleport/devicetrust/v1/user_certificates.proto\x12\x17teleport.devicetrust.v1\"[\n" +
	"\x10UserCertificates\x12\x19\n" +
	"\bx509_der\x18\x01 \x01(\fR\ax509Der\x12,\n" +
	"\x12ssh_authorized_key\x18\x02 \x01(\fR\x10sshAuthorizedKeyBZZXgithub.com/gravitational/teleport/api/gen/proto/go/teleport/devicetrust/v1;devicetrustv1b\x06proto3"

var (
	file_teleport_devicetrust_v1_user_certificates_proto_rawDescOnce sync.Once
	file_teleport_devicetrust_v1_user_certificates_proto_rawDescData []byte
)

func file_teleport_devicetrust_v1_user_certificates_proto_rawDescGZIP() []byte {
	file_teleport_devicetrust_v1_user_certificates_proto_rawDescOnce.Do(func() {
		file_teleport_devicetrust_v1_user_certificates_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_teleport_devicetrust_v1_user_certificates_proto_rawDesc), len(file_teleport_devicetrust_v1_user_certificates_proto_rawDesc)))
	})
	return file_teleport_devicetrust_v1_user_certificates_proto_rawDescData
}

var file_teleport_devicetrust_v1_user_certificates_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_teleport_devicetrust_v1_user_certificates_proto_goTypes = []any{
	(*UserCertificates)(nil), // 0: teleport.devicetrust.v1.UserCertificates
}
var file_teleport_devicetrust_v1_user_certificates_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_teleport_devicetrust_v1_user_certificates_proto_init() }
func file_teleport_devicetrust_v1_user_certificates_proto_init() {
	if File_teleport_devicetrust_v1_user_certificates_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_teleport_devicetrust_v1_user_certificates_proto_rawDesc), len(file_teleport_devicetrust_v1_user_certificates_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_devicetrust_v1_user_certificates_proto_goTypes,
		DependencyIndexes: file_teleport_devicetrust_v1_user_certificates_proto_depIdxs,
		MessageInfos:      file_teleport_devicetrust_v1_user_certificates_proto_msgTypes,
	}.Build()
	File_teleport_devicetrust_v1_user_certificates_proto = out.File
	file_teleport_devicetrust_v1_user_certificates_proto_goTypes = nil
	file_teleport_devicetrust_v1_user_certificates_proto_depIdxs = nil
}
