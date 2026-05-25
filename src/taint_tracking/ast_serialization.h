// Copyright 2026 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_TAINT_TRACKING_AST_SERIALIZATION_H_
#define V8_TAINT_TRACKING_AST_SERIALIZATION_H_

// Porting note:
// - This header was introduced by the original taint-tracking patch series.
// - Upstream V8 14.8 does not ship an equivalent header.
// - The late patch series expanded this file into the public surface for the
//   whole concolic-execution runtime, but those dependent files are not yet
//   forward-ported in this tree.
// - For the current forward port, keep only the serializer entry point that is
//   already implemented in ast_serialization.cc, and track the larger
//   concolic API gap in the porting ledger.

#include <vector>

#include "src/ast/ast.h"
#include "src/execution/isolate.h"
#include "src/objects/js-objects.h"
#include "v8/ast.capnp.h"

namespace tainttracking {

// TODO(taint_tracking): The old patch series later switched this interface to a
// ParseInfo-centric entry point. Revisit that shape only after the downstream
// symbolic-execution pipeline is forward-ported.
bool SerializeAst(v8::internal::FunctionLiteral* ast, ::Ast::Builder* message,
                  v8::internal::Isolate* isolate);

class ObjectOwnPropertiesVisitor {
 public:
  void Visit(v8::internal::Handle<v8::internal::JSReceiver> receiver,
             v8::internal::Isolate* isolate);

  // Returns true to visit value recursively
  virtual bool VisitKeyValue(
      v8::internal::Handle<v8::internal::String> key,
      v8::internal::Handle<v8::internal::Object> value) = 0;

 protected:
  ObjectOwnPropertiesVisitor() {}

 private:
  void ProcessReceiver(
      v8::internal::Handle<v8::internal::JSReceiver> receiver,
      v8::internal::Isolate* isolate);

  std::vector<v8::internal::Handle<v8::internal::JSReceiver>> value_stack_;
  v8::internal::Isolate* isolate_;
};

}  // namespace tainttracking

#endif  // V8_TAINT_TRACKING_AST_SERIALIZATION_H_
