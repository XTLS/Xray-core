// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v5.28.0
// source: transport/internet/splithttp/config.proto

package splithttp

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Host                 string            `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
	Path                 string            `protobuf:"bytes,2,opt,name=path,proto3" json:"path,omitempty"`
	Header               map[string]string `protobuf:"bytes,3,rep,name=header,proto3" json:"header,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	ScMaxConcurrentPosts *RandRangeConfig  `protobuf:"bytes,4,opt,name=scMaxConcurrentPosts,proto3" json:"scMaxConcurrentPosts,omitempty"`
	ScMaxEachPostBytes   *RandRangeConfig  `protobuf:"bytes,5,opt,name=scMaxEachPostBytes,proto3" json:"scMaxEachPostBytes,omitempty"`
	ScMinPostsIntervalMs *RandRangeConfig  `protobuf:"bytes,6,opt,name=scMinPostsIntervalMs,proto3" json:"scMinPostsIntervalMs,omitempty"`
	NoSSEHeader          bool              `protobuf:"varint,7,opt,name=noSSEHeader,proto3" json:"noSSEHeader,omitempty"`
	XPaddingBytes        *RandRangeConfig  `protobuf:"bytes,8,opt,name=xPaddingBytes,proto3" json:"xPaddingBytes,omitempty"`
	Xmux                 *Multiplexing     `protobuf:"bytes,9,opt,name=xmux,proto3" json:"xmux,omitempty"`
	CorsHeader           bool              `protobuf:"varint,10,opt,name=corsHeader,proto3" json:"corsHeader,omitempty"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_internet_splithttp_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_transport_internet_splithttp_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Config.ProtoReflect.Descriptor instead.
func (*Config) Descriptor() ([]byte, []int) {
	return file_transport_internet_splithttp_config_proto_rawDescGZIP(), []int{0}
}

func (x *Config) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *Config) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *Config) GetHeader() map[string]string {
	if x != nil {
		return x.Header
	}
	return nil
}

func (x *Config) GetScMaxConcurrentPosts() *RandRangeConfig {
	if x != nil {
		return x.ScMaxConcurrentPosts
	}
	return nil
}

func (x *Config) GetScMaxEachPostBytes() *RandRangeConfig {
	if x != nil {
		return x.ScMaxEachPostBytes
	}
	return nil
}

func (x *Config) GetScMinPostsIntervalMs() *RandRangeConfig {
	if x != nil {
		return x.ScMinPostsIntervalMs
	}
	return nil
}

func (x *Config) GetNoSSEHeader() bool {
	if x != nil {
		return x.NoSSEHeader
	}
	return false
}

func (x *Config) GetXPaddingBytes() *RandRangeConfig {
	if x != nil {
		return x.XPaddingBytes
	}
	return nil
}

func (x *Config) GetXmux() *Multiplexing {
	if x != nil {
		return x.Xmux
	}
	return nil
}

func (x *Config) GetCorsHeader() bool {
	if x != nil {
		return x.CorsHeader
	}
	return false
}

type RandRangeConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	From int32 `protobuf:"varint,1,opt,name=from,proto3" json:"from,omitempty"`
	To   int32 `protobuf:"varint,2,opt,name=to,proto3" json:"to,omitempty"`
}

func (x *RandRangeConfig) Reset() {
	*x = RandRangeConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_internet_splithttp_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RandRangeConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RandRangeConfig) ProtoMessage() {}

func (x *RandRangeConfig) ProtoReflect() protoreflect.Message {
	mi := &file_transport_internet_splithttp_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RandRangeConfig.ProtoReflect.Descriptor instead.
func (*RandRangeConfig) Descriptor() ([]byte, []int) {
	return file_transport_internet_splithttp_config_proto_rawDescGZIP(), []int{1}
}

func (x *RandRangeConfig) GetFrom() int32 {
	if x != nil {
		return x.From
	}
	return 0
}

func (x *RandRangeConfig) GetTo() int32 {
	if x != nil {
		return x.To
	}
	return 0
}

type Multiplexing struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MaxConcurrency *RandRangeConfig `protobuf:"bytes,1,opt,name=maxConcurrency,proto3" json:"maxConcurrency,omitempty"`
	MaxConnections *RandRangeConfig `protobuf:"bytes,2,opt,name=maxConnections,proto3" json:"maxConnections,omitempty"`
	CMaxReuseTimes *RandRangeConfig `protobuf:"bytes,3,opt,name=cMaxReuseTimes,proto3" json:"cMaxReuseTimes,omitempty"`
	CMaxLifetimeMs *RandRangeConfig `protobuf:"bytes,4,opt,name=cMaxLifetimeMs,proto3" json:"cMaxLifetimeMs,omitempty"`
}

func (x *Multiplexing) Reset() {
	*x = Multiplexing{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_internet_splithttp_config_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Multiplexing) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Multiplexing) ProtoMessage() {}

func (x *Multiplexing) ProtoReflect() protoreflect.Message {
	mi := &file_transport_internet_splithttp_config_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Multiplexing.ProtoReflect.Descriptor instead.
func (*Multiplexing) Descriptor() ([]byte, []int) {
	return file_transport_internet_splithttp_config_proto_rawDescGZIP(), []int{2}
}

func (x *Multiplexing) GetMaxConcurrency() *RandRangeConfig {
	if x != nil {
		return x.MaxConcurrency
	}
	return nil
}

func (x *Multiplexing) GetMaxConnections() *RandRangeConfig {
	if x != nil {
		return x.MaxConnections
	}
	return nil
}

func (x *Multiplexing) GetCMaxReuseTimes() *RandRangeConfig {
	if x != nil {
		return x.CMaxReuseTimes
	}
	return nil
}

func (x *Multiplexing) GetCMaxLifetimeMs() *RandRangeConfig {
	if x != nil {
		return x.CMaxLifetimeMs
	}
	return nil
}

var File_transport_internet_splithttp_config_proto protoreflect.FileDescriptor

var file_transport_internet_splithttp_config_proto_rawDesc = []byte{
	0x0a, 0x29, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x69, 0x6e, 0x74, 0x65,
	0x72, 0x6e, 0x65, 0x74, 0x2f, 0x73, 0x70, 0x6c, 0x69, 0x74, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x63,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x21, 0x78, 0x72, 0x61,
	0x79, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65,
	0x72, 0x6e, 0x65, 0x74, 0x2e, 0x73, 0x70, 0x6c, 0x69, 0x74, 0x68, 0x74, 0x74, 0x70, 0x22, 0xcf,
	0x05, 0x0a, 0x06, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x6f, 0x73,
	0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x12, 0x12, 0x0a,
	0x04, 0x70, 0x61, 0x74, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x70, 0x61, 0x74,
	0x68, 0x12, 0x4d, 0x0a, 0x06, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x18, 0x03, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x35, 0x2e, 0x78, 0x72, 0x61, 0x79, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f,
	0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x73, 0x70, 0x6c, 0x69,
	0x74, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x48, 0x65, 0x61,
	0x64, 0x65, 0x72, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x06, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
	0x12, 0x66, 0x0a, 0x14, 0x73, 0x63, 0x4d, 0x61, 0x78, 0x43, 0x6f, 0x6e, 0x63, 0x75, 0x72, 0x72,
	0x65, 0x6e, 0x74, 0x50, 0x6f, 0x73, 0x74, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x32,
	0x2e, 0x78, 0x72, 0x61, 0x79, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e,
	0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x73, 0x70, 0x6c, 0x69, 0x74, 0x68, 0x74,
	0x74, 0x70, 0x2e, 0x52, 0x61, 0x6e, 0x64, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x52, 0x14, 0x73, 0x63, 0x4d, 0x61, 0x78, 0x43, 0x6f, 0x6e, 0x63, 0x75, 0x72, 0x72,
	0x65, 0x6e, 0x74, 0x50, 0x6f, 0x73, 0x74, 0x73, 0x12, 0x62, 0x0a, 0x12, 0x73, 0x63, 0x4d, 0x61,
	0x78, 0x45, 0x61, 0x63, 0x68, 0x50, 0x6f, 0x73, 0x74, 0x42, 0x79, 0x74, 0x65, 0x73, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x32, 0x2e, 0x78, 0x72, 0x61, 0x79, 0x2e, 0x74, 0x72, 0x61, 0x6e,
	0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x73,
	0x70, 0x6c, 0x69, 0x74, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x52, 0x61, 0x6e, 0x64, 0x52, 0x61, 0x6e,
	0x67, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x12, 0x73, 0x63, 0x4d, 0x61, 0x78, 0x45,
	0x61, 0x63, 0x68, 0x50, 0x6f, 0x73, 0x74, 0x42, 0x79, 0x74, 0x65, 0x73, 0x12, 0x66, 0x0a, 0x14,
	0x73, 0x63, 0x4d, 0x69, 0x6e, 0x50, 0x6f, 0x73, 0x74, 0x73, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x76,
	0x61, 0x6c, 0x4d, 0x73, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x32, 0x2e, 0x78, 0x72, 0x61,
	0x79, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65,
	0x72, 0x6e, 0x65, 0x74, 0x2e, 0x73, 0x70, 0x6c, 0x69, 0x74, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x52,
	0x61, 0x6e, 0x64, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x14,
	0x73, 0x63, 0x4d, 0x69, 0x6e, 0x50, 0x6f, 0x73, 0x74, 0x73, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x76,
	0x61, 0x6c, 0x4d, 0x73, 0x12, 0x20, 0x0a, 0x0b, 0x6e, 0x6f, 0x53, 0x53, 0x45, 0x48, 0x65, 0x61,
	0x64, 0x65, 0x72, 0x18, 0x07, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x6e, 0x6f, 0x53, 0x53, 0x45,
	0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x58, 0x0a, 0x0d, 0x78, 0x50, 0x61, 0x64, 0x64, 0x69,
	0x6e, 0x67, 0x42, 0x79, 0x74, 0x65, 0x73, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x32, 0x2e,
	0x78, 0x72, 0x61, 0x79, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69,
	0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x73, 0x70, 0x6c, 0x69, 0x74, 0x68, 0x74, 0x74,
	0x70, 0x2e, 0x52, 0x61, 0x6e, 0x64, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x52, 0x0d, 0x78, 0x50, 0x61, 0x64, 0x64, 0x69, 0x6e, 0x67, 0x42, 0x79, 0x74, 0x65, 0x73,
	0x12, 0x43, 0x0a, 0x04, 0x78, 0x6d, 0x75, 0x78, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2f,
	0x2e, 0x78, 0x72, 0x61, 0x79, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e,
	0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x73, 0x70, 0x6c, 0x69, 0x74, 0x68, 0x74,
	0x74, 0x70, 0x2e, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x70, 0x6c, 0x65, 0x78, 0x69, 0x6e, 0x67, 0x52,
	0x04, 0x78, 0x6d, 0x75, 0x78, 0x12, 0x1e, 0x0a, 0x0a, 0x63, 0x6f, 0x72, 0x73, 0x48, 0x65, 0x61,
	0x64, 0x65, 0x72, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a, 0x63, 0x6f, 0x72, 0x73, 0x48,
	0x65, 0x61, 0x64, 0x65, 0x72, 0x1a, 0x39, 0x0a, 0x0b, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01,
	0x22, 0x35, 0x0a, 0x0f, 0x52, 0x61, 0x6e, 0x64, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x43, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x12, 0x12, 0x0a, 0x04, 0x66, 0x72, 0x6f, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x05, 0x52, 0x04, 0x66, 0x72, 0x6f, 0x6d, 0x12, 0x0e, 0x0a, 0x02, 0x74, 0x6f, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x05, 0x52, 0x02, 0x74, 0x6f, 0x22, 0xfe, 0x02, 0x0a, 0x0c, 0x4d, 0x75, 0x6c, 0x74,
	0x69, 0x70, 0x6c, 0x65, 0x78, 0x69, 0x6e, 0x67, 0x12, 0x5a, 0x0a, 0x0e, 0x6d, 0x61, 0x78, 0x43,
	0x6f, 0x6e, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x63, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x32, 0x2e, 0x78, 0x72, 0x61, 0x79, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x73, 0x70, 0x6c, 0x69, 0x74,
	0x68, 0x74, 0x74, 0x70, 0x2e, 0x52, 0x61, 0x6e, 0x64, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x52, 0x0e, 0x6d, 0x61, 0x78, 0x43, 0x6f, 0x6e, 0x63, 0x75, 0x72, 0x72,
	0x65, 0x6e, 0x63, 0x79, 0x12, 0x5a, 0x0a, 0x0e, 0x6d, 0x61, 0x78, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x32, 0x2e, 0x78,
	0x72, 0x61, 0x79, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e,
	0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x73, 0x70, 0x6c, 0x69, 0x74, 0x68, 0x74, 0x74, 0x70,
	0x2e, 0x52, 0x61, 0x6e, 0x64, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x52, 0x0e, 0x6d, 0x61, 0x78, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x12, 0x5a, 0x0a, 0x0e, 0x63, 0x4d, 0x61, 0x78, 0x52, 0x65, 0x75, 0x73, 0x65, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x32, 0x2e, 0x78, 0x72, 0x61, 0x79, 0x2e,
	0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e,
	0x65, 0x74, 0x2e, 0x73, 0x70, 0x6c, 0x69, 0x74, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x52, 0x61, 0x6e,
	0x64, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x0e, 0x63, 0x4d,
	0x61, 0x78, 0x52, 0x65, 0x75, 0x73, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x12, 0x5a, 0x0a, 0x0e,
	0x63, 0x4d, 0x61, 0x78, 0x4c, 0x69, 0x66, 0x65, 0x74, 0x69, 0x6d, 0x65, 0x4d, 0x73, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x32, 0x2e, 0x78, 0x72, 0x61, 0x79, 0x2e, 0x74, 0x72, 0x61, 0x6e,
	0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x73,
	0x70, 0x6c, 0x69, 0x74, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x52, 0x61, 0x6e, 0x64, 0x52, 0x61, 0x6e,
	0x67, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x0e, 0x63, 0x4d, 0x61, 0x78, 0x4c, 0x69,
	0x66, 0x65, 0x74, 0x69, 0x6d, 0x65, 0x4d, 0x73, 0x42, 0x85, 0x01, 0x0a, 0x25, 0x63, 0x6f, 0x6d,
	0x2e, 0x78, 0x72, 0x61, 0x79, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e,
	0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x73, 0x70, 0x6c, 0x69, 0x74, 0x68, 0x74,
	0x74, 0x70, 0x50, 0x01, 0x5a, 0x36, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x78, 0x74, 0x6c, 0x73, 0x2f, 0x78, 0x72, 0x61, 0x79, 0x2d, 0x63, 0x6f, 0x72, 0x65, 0x2f,
	0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e,
	0x65, 0x74, 0x2f, 0x73, 0x70, 0x6c, 0x69, 0x74, 0x68, 0x74, 0x74, 0x70, 0xaa, 0x02, 0x21, 0x58,
	0x72, 0x61, 0x79, 0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x49, 0x6e,
	0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2e, 0x53, 0x70, 0x6c, 0x69, 0x74, 0x48, 0x74, 0x74, 0x70,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_transport_internet_splithttp_config_proto_rawDescOnce sync.Once
	file_transport_internet_splithttp_config_proto_rawDescData = file_transport_internet_splithttp_config_proto_rawDesc
)

func file_transport_internet_splithttp_config_proto_rawDescGZIP() []byte {
	file_transport_internet_splithttp_config_proto_rawDescOnce.Do(func() {
		file_transport_internet_splithttp_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_transport_internet_splithttp_config_proto_rawDescData)
	})
	return file_transport_internet_splithttp_config_proto_rawDescData
}

var file_transport_internet_splithttp_config_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_transport_internet_splithttp_config_proto_goTypes = []any{
	(*Config)(nil),          // 0: xray.transport.internet.splithttp.Config
	(*RandRangeConfig)(nil), // 1: xray.transport.internet.splithttp.RandRangeConfig
	(*Multiplexing)(nil),    // 2: xray.transport.internet.splithttp.Multiplexing
	nil,                     // 3: xray.transport.internet.splithttp.Config.HeaderEntry
}
var file_transport_internet_splithttp_config_proto_depIdxs = []int32{
	3,  // 0: xray.transport.internet.splithttp.Config.header:type_name -> xray.transport.internet.splithttp.Config.HeaderEntry
	1,  // 1: xray.transport.internet.splithttp.Config.scMaxConcurrentPosts:type_name -> xray.transport.internet.splithttp.RandRangeConfig
	1,  // 2: xray.transport.internet.splithttp.Config.scMaxEachPostBytes:type_name -> xray.transport.internet.splithttp.RandRangeConfig
	1,  // 3: xray.transport.internet.splithttp.Config.scMinPostsIntervalMs:type_name -> xray.transport.internet.splithttp.RandRangeConfig
	1,  // 4: xray.transport.internet.splithttp.Config.xPaddingBytes:type_name -> xray.transport.internet.splithttp.RandRangeConfig
	2,  // 5: xray.transport.internet.splithttp.Config.xmux:type_name -> xray.transport.internet.splithttp.Multiplexing
	1,  // 6: xray.transport.internet.splithttp.Multiplexing.maxConcurrency:type_name -> xray.transport.internet.splithttp.RandRangeConfig
	1,  // 7: xray.transport.internet.splithttp.Multiplexing.maxConnections:type_name -> xray.transport.internet.splithttp.RandRangeConfig
	1,  // 8: xray.transport.internet.splithttp.Multiplexing.cMaxReuseTimes:type_name -> xray.transport.internet.splithttp.RandRangeConfig
	1,  // 9: xray.transport.internet.splithttp.Multiplexing.cMaxLifetimeMs:type_name -> xray.transport.internet.splithttp.RandRangeConfig
	10, // [10:10] is the sub-list for method output_type
	10, // [10:10] is the sub-list for method input_type
	10, // [10:10] is the sub-list for extension type_name
	10, // [10:10] is the sub-list for extension extendee
	0,  // [0:10] is the sub-list for field type_name
}

func init() { file_transport_internet_splithttp_config_proto_init() }
func file_transport_internet_splithttp_config_proto_init() {
	if File_transport_internet_splithttp_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_transport_internet_splithttp_config_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*Config); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_transport_internet_splithttp_config_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*RandRangeConfig); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_transport_internet_splithttp_config_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*Multiplexing); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_transport_internet_splithttp_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_transport_internet_splithttp_config_proto_goTypes,
		DependencyIndexes: file_transport_internet_splithttp_config_proto_depIdxs,
		MessageInfos:      file_transport_internet_splithttp_config_proto_msgTypes,
	}.Build()
	File_transport_internet_splithttp_config_proto = out.File
	file_transport_internet_splithttp_config_proto_rawDesc = nil
	file_transport_internet_splithttp_config_proto_goTypes = nil
	file_transport_internet_splithttp_config_proto_depIdxs = nil
}
