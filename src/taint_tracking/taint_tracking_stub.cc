// Copyright 2025 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Stub implementation for taint tracking when used in build tools like mksnapshot.
// Provides empty implementations of taint tracking functions.

// Minimal includes to avoid pulling in heavy dependencies
#include "src/taint_tracking.h"
#include "src/handles/handles.h"

// Forward declarations to avoid including full headers
namespace v8 {
namespace internal {
class Isolate;
class String;
class SeqString;
class SeqOneByteString;
class SeqTwoByteString;
class FixedArray;
class JSRegExp;
class ParseInfo;
}
}

namespace tainttracking {

using namespace v8::internal;

// Stub implementation of TaintTracker::Impl
class TaintTracker::Impl {
public:
  Impl() {}
  ~Impl() {}
};

// NodeLabel implementation
NodeLabel::NodeLabel() : rand_(0), counter_(0) {}

NodeLabel::NodeLabel(Rand r, Counter c) : rand_(r), counter_(c) {}

NodeLabel::NodeLabel(const NodeLabel& other)
    : rand_(other.rand_), counter_(other.counter_) {}

NodeLabel& NodeLabel::operator=(const NodeLabel& other) {
  rand_ = other.rand_;
  counter_ = other.counter_;
  return *this;
}

NodeLabel::Rand NodeLabel::GetRand() const { return rand_; }

NodeLabel::Counter NodeLabel::GetCounter() const { return counter_; }

bool NodeLabel::IsValid() const { return rand_ != 0 || counter_ != 0; }

bool NodeLabel::Equals(const NodeLabel& other) const {
  return rand_ == other.rand_ && counter_ == other.counter_;
}

void NodeLabel::CopyFrom(const NodeLabel& other) {
  rand_ = other.rand_;
  counter_ = other.counter_;
}

std::size_t NodeLabel::Hash::operator()(NodeLabel const& val) const {
  return underlying_(val.rand_) ^ underlying_(val.counter_);
}

bool NodeLabel::EqualTo::operator()(const NodeLabel& one, const NodeLabel& two) const {
  return one.Equals(two);
}

// V8NodeLabelSerializer stub
V8NodeLabelSerializer::V8NodeLabelSerializer(Isolate*) : isolate_(nullptr) {}

Status V8NodeLabelSerializer::Serialize(Handle<Object>*, const NodeLabel&) {
  return Status::OK;
}

// TaintTracker stub implementations
TaintTracker::TaintTracker(bool, Isolate*) : impl_(nullptr) {}

TaintTracker::~TaintTracker() {}

void TaintTracker::Initialize(Isolate*) {}

bool TaintTracker::IsRewriteAstEnabled() {
  return false;
}

TaintTracker* TaintTracker::FromIsolate(Isolate*) {
  return nullptr;
}

TaintTracker* TaintTracker::New(bool, Isolate*) {
  return nullptr;
}

// Runtime stack frame functions - stub implementations
void RuntimePrepareSymbolicStackFrame(Isolate*, FrameType) {}

void RuntimeAddLiteralArgumentToStackFrame(Isolate*, DirectHandle<Object>) {}

void RuntimeEnterSymbolicStackFrame(Isolate*) {}

void RuntimeExitSymbolicStackFrame(Isolate*) {}

void RuntimeHook(Isolate*, Handle<Object>, Handle<Object>, int) {}

void RuntimeSetReceiver(Isolate*, DirectHandle<Object>, DirectHandle<Object>) {}

// Template function stubs for string taint operations
template <>
void InitTaintData<SeqOneByteString>(Tagged<SeqOneByteString>, TaintType) {}

template <>
void InitTaintData<SeqTwoByteString>(Tagged<SeqTwoByteString>, TaintType) {}

template <>
TaintData* GetWriteableStringTaintData<SeqOneByteString>(Tagged<SeqOneByteString>) {
  return nullptr;
}

template <>
TaintData* GetWriteableStringTaintData<SeqTwoByteString>(Tagged<SeqTwoByteString>) {
  return nullptr;
}

template <>
TaintData* GetWriteableStringTaintData<SeqString>(Tagged<SeqString>) {
  return nullptr;
}

// Provide stub implementations for template functions
template <class T>
void FlattenTaintData(Tagged<T>, TaintData*, int, int) {}

template <class T>
void CopyOut(Tagged<T>, TaintData*, int, int) {}

template <class T>
void CopyIn(Tagged<T>, TaintType, int, int) {}

template <class T>
void CopyIn(Tagged<T>, const TaintData*, int, int) {}

template <class T, class Array>
void OnJoinManyStrings(T*, Array*, Isolate*) {}

template <class T>
void OnGenericOperation(SymbolicType, Tagged<T>, Isolate*) {}

template <class T>
void OnNewReplaceRegexpWithString(String*, T*, JSRegExp*, String*, Isolate*) {}

// Explicit instantiations
template void FlattenTaintData<String>(Tagged<String>, TaintData*, int, int);

template void CopyOut<SeqString>(Tagged<SeqString>, TaintData*, int, int);

template void CopyIn<SeqString>(Tagged<SeqString>, TaintType, int, int);
template void CopyIn<SeqString>(Tagged<SeqString>, const TaintData*, int, int);

template void OnJoinManyStrings<SeqOneByteString, FixedArray>(
    SeqOneByteString*, FixedArray*, Isolate*);

template void OnJoinManyStrings<SeqTwoByteString, FixedArray>(
    SeqTwoByteString*, FixedArray*, Isolate*);

template void OnGenericOperation<String>(SymbolicType, Tagged<String>, Isolate*);

template void OnGenericOperation<SeqOneByteString>(SymbolicType, Tagged<SeqOneByteString>, Isolate*);

template void OnGenericOperation<SeqTwoByteString>(SymbolicType, Tagged<SeqTwoByteString>, Isolate*);

template void OnNewReplaceRegexpWithString<SeqOneByteString>(
    String*, SeqOneByteString*, JSRegExp*, String*, Isolate*);

template void OnNewReplaceRegexpWithString<SeqTwoByteString>(
    String*, SeqTwoByteString*, JSRegExp*, String*, Isolate*);

// LogIfTainted stub
int64_t LogIfTainted(DirectHandle<String>, TaintSinkLabel, int, Isolate*) {
  return NO_MESSAGE;
}

// Other stub functions
uint32_t LayoutVersionHash() { return 0; }

void InsertControlFlowHook(ParseInfo*) {}

}  // namespace tainttracking
