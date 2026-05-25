// Copyright 2026 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/taint_tracking/ast_serialization.h"

#include <cstdint>
#include <forward_list>
#include <optional>
#include <variant>

#include "src/ast/scopes.h"
#include "src/common/globals.h"
#include "src/objects/fixed-array-inl.h"
#include "src/objects/function-kind.h"
#include "src/objects/function-syntax-kind.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/objects-inl.h"
#include "src/parsing/token.h"

namespace tainttracking {

namespace i = v8::internal;
using v8::internal::Tagged;
using v8::internal::Isolate;

// NodeLabel implementation
NodeLabel::NodeLabel(uint64_t rand, uint32_t counter) :
  rand_(rand), counter_(counter) {}

NodeLabel::NodeLabel() : rand_(0), counter_(0) {}

NodeLabel::NodeLabel(const NodeLabel& other) {
  CopyFrom(other);
}

NodeLabel& NodeLabel::operator=(const NodeLabel& other) {
  if (this != &other) {
    CopyFrom(other);
  }
  return *this;
}

bool NodeLabel::Equals(const NodeLabel& other) const {
  return rand_ == other.rand_ && counter_ == other.counter_;
}

void NodeLabel::CopyFrom(const NodeLabel& other) {
  rand_ = other.GetRand();
  counter_ = other.GetCounter();
}

NodeLabel::Labeler::Labeler(Isolate* isolate) :
  counter_(0),
  rng_(isolate->random_number_generator()) {}

NodeLabel NodeLabel::Labeler::New() {
  uint64_t next_value;
  rng_->NextBytes(&next_value, sizeof(next_value));
  return NodeLabel(next_value, counter_++);
}

NodeLabel::Rand NodeLabel::GetRand() const {
  return rand_;
}

NodeLabel::Counter NodeLabel::GetCounter() const {
  return counter_;
}

bool NodeLabel::IsValid() const {
  return rand_ != 0 || counter_ != 0;
}

std::size_t NodeLabel::Hash::operator()(NodeLabel const& val) const {
  return underlying_(val.GetRand());
}

bool NodeLabel::EqualTo::operator()(
    const NodeLabel& one, const NodeLabel& two) const {
  return one.Equals(two);
}

// ObjectOwnPropertiesVisitor implementation
void ObjectOwnPropertiesVisitor::Visit(
    v8::internal::Handle<v8::internal::JSReceiver> receiver,
    v8::internal::Isolate* isolate) {
  isolate_ = isolate;
  ProcessReceiver(receiver, isolate);
  while (!value_stack_.empty()) {
    v8::internal::Handle<v8::internal::JSReceiver> curr = value_stack_.back();
    value_stack_.pop_back();
    ProcessReceiver(curr, isolate);
  }
}

void ObjectOwnPropertiesVisitor::ProcessReceiver(
    v8::internal::Handle<v8::internal::JSReceiver> receiver,
    v8::internal::Isolate* isolate) {
  using v8::internal::Cast;
  using v8::internal::DirectHandle;
  using v8::internal::FixedArray;
  using v8::internal::Handle;
  using v8::internal::IsFixedArray;
  using v8::internal::IsJSReceiver;
  using v8::internal::JSArray;
  using v8::internal::JSReceiver;
  using v8::internal::MaybeDirectHandle;
  using v8::internal::MaybeHandle;
  using v8::internal::Object;
  using v8::internal::PropertyFilter;
  using v8::internal::String;

  MaybeDirectHandle<FixedArray> maybe_entries =
      JSReceiver::GetOwnEntries(isolate, receiver, PropertyFilter::ENUMERABLE_STRINGS);
  if (maybe_entries.is_null()) {
    return;
  }

  DirectHandle<FixedArray> entries;
  if (!maybe_entries.ToHandle(&entries)) {
    return;
  }

  for (unsigned int i = 0; i < entries->length().value(); ++i) {
    // Get the key value entries as a jsarray
    Tagged<Object> entry_pair_obj = entries->get(i);
    if (!IsJSArray(entry_pair_obj)) {
      continue;
    }
    DirectHandle<JSArray> entry_pair_js_array = handle(Cast<JSArray>(entry_pair_obj), isolate);

    // Get the backing storage for the key value
    Handle<Object> entry_pair_elements =
        handle(entry_pair_js_array->elements(), isolate);
    if (!IsFixedArray(*entry_pair_elements)) {
      continue;
    }
    Handle<FixedArray> entry_pair_as_array = Cast<FixedArray>(entry_pair_elements);
    if (entry_pair_as_array->length().value() != 2) {
      continue;
    }

    // Get the key and make sure its a string
    Tagged<Object> key_obj = entry_pair_as_array->get(0);
    if (!IsString(key_obj)) {
      continue;
    }
    Handle<String> key = handle(Cast<String>(key_obj), isolate);

    // Get the value. Its ok if its not defined.
    Tagged<Object> value_obj = entry_pair_as_array->get(1);
    Handle<Object> value;
    if (IsUndefined(value_obj, isolate)) {
      value = isolate->factory()->undefined_value();
    } else {
      value = handle(value_obj, isolate);
    }

    if (VisitKeyValue(key, value) && IsJSReceiver(*value)) {
      value_stack_.push_back(Cast<JSReceiver>(value));
    }
  }
}
using i::AstNode;
using i::Isolate;

// Create aliases for Cap'n Proto types to avoid conflicts with V8 AST types in macro expansions
// Only include types that don't conflict with V8 AST node types
namespace capnp {
  using Builder = ::Ast::Builder;
  using Statement = ::Ast::Statement;
  using Expression = ::Ast::Expression;
  using Declaration = ::Ast::Declaration;
  using JsString = ::Ast::JsString;
  using ScopePointer = ::Ast::ScopePointer;
  using FunctionKind = ::Ast::FunctionKind;
  using VariableMode = ::Ast::VariableMode;
  using Token = ::Ast::Token;
  using KeyedAccessStoreMode = ::Ast::KeyedAccessStoreMode;
  using InitializationFlag = ::Ast::InitializationFlag;
  using LiteralProperty = ::Ast::LiteralProperty;
}  // namespace capnp

class AstSerializer final : public i::AstVisitor<AstSerializer> {
 public:
  AstSerializer(capnp::Builder* builder, i::Isolate* isolate)
      : root_builder_(builder) {
    this->InitializeAstVisitor(isolate);
  }

  void SerializeRoot(i::FunctionLiteral* ast) {
    auto root = root_builder_->initRoot();
    auto func = root.initFunc();
    HandleFunctionLiteral(ast, &func);
  }

  bool success() const { return success_ && !HasStackOverflow(); }

 private:
  // Manual implementation to avoid type name conflicts with Cap'n Proto types
  void VisitNoStackOverflowCheck(i::AstNode* node) {
    switch (node->node_type()) {
#define GENERATE_VISIT_CASE(NodeType)                                   \
  case i::AstNode::k##NodeType:                                         \
    return this->Visit##NodeType(static_cast<i::NodeType*>(node));
      AST_NODE_LIST(GENERATE_VISIT_CASE)
#undef GENERATE_VISIT_CASE
#define GENERATE_FAILURE_CASE(NodeType) \
  case i::AstNode::k##NodeType:         \
    UNREACHABLE();
      FAILURE_NODE_LIST(GENERATE_FAILURE_CASE)
#undef GENERATE_FAILURE_CASE
    }
  }

  void Visit(i::AstNode* node) {
    if (CheckStackOverflow()) return;
    VisitNoStackOverflowCheck(node);
  }

  void SetStackOverflow() { stack_overflow_ = true; }
  void ClearStackOverflow() { stack_overflow_ = false; }
  bool HasStackOverflow() const { return stack_overflow_; }

  bool CheckStackOverflow() {
    if (stack_overflow_) return true;
    if (i::GetCurrentStackPosition() < stack_limit_) {
      stack_overflow_ = true;
      return true;
    }
    return false;
  }

 protected:
  uintptr_t stack_limit() const { return stack_limit_; }

 private:
  void InitializeAstVisitor(i::Isolate* isolate) {
    stack_limit_ = isolate->stack_guard()->real_climit();
    stack_overflow_ = false;
  }

  void InitializeAstVisitor(uintptr_t stack_limit) {
    stack_limit_ = stack_limit;
    stack_overflow_ = false;
  }

  uintptr_t stack_limit_ = 0;
  bool stack_overflow_ = false;

  template <typename T, typename BuilderType>
  void SerializeChild(T* node, BuilderType builder) {
    if (node == nullptr) return;
    SetCurrent(builder);
    Visit(node);
    ClearCurrent();
  }

  void SetCurrent(capnp::Statement::Builder builder) {
    current_stmt_ = builder;
  }

  void SetCurrent(capnp::Expression::Builder builder) {
    current_expr_ = builder;
  }

  void SetCurrent(capnp::Declaration::Builder builder) {
    current_decl_ = builder;
  }

  void ClearCurrent() {
    current_stmt_ = nullptr;
    current_expr_ = nullptr;
    current_decl_ = nullptr;
  }

  // Helper to get NodeVal from current builder - overloaded versions
  ::Ast::Statement::NodeVal::Builder GetCurrentStmtNodeVal() {
    if (current_stmt_.has_value()) return current_stmt_->getNodeVal();
    __builtin_trap();
  }

  ::Ast::Expression::NodeVal::Builder GetCurrentExprNodeVal() {
    if (current_expr_.has_value()) return current_expr_->getNodeVal();
    __builtin_trap();
  }

  ::Ast::Declaration::NodeVal::Builder GetCurrentDeclNodeVal() {
    if (current_decl_.has_value()) return current_decl_->getNodeVal();
    __builtin_trap();
  }

  void MarkTodo(const char* reason) {
    if (first_todo_ == nullptr) first_todo_ = reason;
    success_ = false;
  }

  size_t CountDeclarations(i::Declaration::List* declarations) const {
    size_t count = 0;
    for (i::Declaration* declaration : *declarations) {
      (void)declaration;
      ++count;
    }
    return count;
  }

  void HandleAstRawString(const i::AstRawString* str,
                          capnp::JsString::Builder* builder) {
    if (str == nullptr) return;
    auto segments = builder->initSegments(1);
    auto segment = segments[0];
    segment.setContent(::capnp::Data::Reader(
        str->raw_data(), static_cast<size_t>(str->byte_length())));
    segment.setIsOneByte(str->is_one_byte());
  }

  void HandleAstConsString(const i::AstConsString* str,
                           capnp::JsString::Builder* builder) {
    if (str == nullptr || str->IsEmpty()) return;
    std::forward_list<const i::AstRawString*> parts = str->ToRawStrings();
    size_t count = 0;
    for (const i::AstRawString* part : parts) {
      if (part == nullptr) continue;
      ++count;
    }
    if (count == 0) return;

    auto segments = builder->initSegments(static_cast<unsigned int>(count));
    size_t index = 0;
    for (const i::AstRawString* part : parts) {
      if (part == nullptr) continue;
      auto segment = segments[static_cast<uint>(index++)];
      segment.setContent(::capnp::Data::Reader(
          part->raw_data(), static_cast<size_t>(part->byte_length())));
      segment.setIsOneByte(part->is_one_byte());
    }
  }

  void HandleScope(i::Scope* scope, capnp::ScopePointer::Builder* builder) {
    builder->setParentExprId(
        static_cast<uint64_t>(reinterpret_cast<uintptr_t>(scope)));
  }

  ::Ast::FunctionLiteral::FunctionType ToAstFunctionType(
      i::FunctionSyntaxKind syntax_kind) {
    switch (syntax_kind) {
      case i::FunctionSyntaxKind::kAnonymousExpression:
        return ::Ast::FunctionLiteral::FunctionType::ANONYMOUS_EXPRESSION;
      case i::FunctionSyntaxKind::kNamedExpression:
        return ::Ast::FunctionLiteral::FunctionType::NAMED_EXPRESSION;
      case i::FunctionSyntaxKind::kDeclaration:
        return ::Ast::FunctionLiteral::FunctionType::DECLARATION;
      case i::FunctionSyntaxKind::kAccessorOrMethod:
        return ::Ast::FunctionLiteral::FunctionType::ACCESSOR_OR_METHOD;
      case i::FunctionSyntaxKind::kWrapped:
        // TODO(taint_tracking): Need modern API for: FunctionSyntaxKind::kWrapped.
        MarkTodo("Need modern API for: FunctionSyntaxKind::kWrapped");
        return ::Ast::FunctionLiteral::FunctionType::ANONYMOUS_EXPRESSION;
    }
    UNREACHABLE();
  }

  capnp::FunctionKind ToAstFunctionKind(i::FunctionKind kind) {
    switch (kind) {
      case i::FunctionKind::kNormalFunction:
        return capnp::FunctionKind::NORMAL_FUNCTION;
      case i::FunctionKind::kArrowFunction:
        return capnp::FunctionKind::ARROW_FUNCTION;
      case i::FunctionKind::kGeneratorFunction:
        return capnp::FunctionKind::GENERATOR_FUNCTION;
      case i::FunctionKind::kConciseMethod:
      case i::FunctionKind::kStaticConciseMethod:
        if (kind == i::FunctionKind::kStaticConciseMethod) {
          // TODO(taint_tracking): Need modern API for: preserving static method
          // information in FunctionKind serialization.
          MarkTodo("Need modern API for: static FunctionKind metadata");
        }
        return capnp::FunctionKind::CONCISE_METHOD;
      case i::FunctionKind::kConciseGeneratorMethod:
      case i::FunctionKind::kStaticConciseGeneratorMethod:
        if (kind == i::FunctionKind::kStaticConciseGeneratorMethod) {
          // TODO(taint_tracking): Need modern API for: preserving static
          // generator method information in FunctionKind serialization.
          MarkTodo("Need modern API for: static generator FunctionKind metadata");
        }
        return capnp::FunctionKind::CONCISE_GENERATOR_METHOD;
      case i::FunctionKind::kGetterFunction:
      case i::FunctionKind::kStaticGetterFunction:
        if (kind == i::FunctionKind::kStaticGetterFunction) {
          // TODO(taint_tracking): Need modern API for: preserving static getter
          // information in FunctionKind serialization.
          MarkTodo("Need modern API for: static getter FunctionKind metadata");
        }
        return capnp::FunctionKind::GETTER_FUNCTION;
      case i::FunctionKind::kSetterFunction:
      case i::FunctionKind::kStaticSetterFunction:
        if (kind == i::FunctionKind::kStaticSetterFunction) {
          // TODO(taint_tracking): Need modern API for: preserving static setter
          // information in FunctionKind serialization.
          MarkTodo("Need modern API for: static setter FunctionKind metadata");
        }
        return capnp::FunctionKind::SETTER_FUNCTION;
      case i::FunctionKind::kDefaultBaseConstructor:
        return capnp::FunctionKind::DEFAULT_BASE_CONSTRUCTOR;
      case i::FunctionKind::kDefaultDerivedConstructor:
        return capnp::FunctionKind::DEFAULT_SUBCLASS_CONSTRUCTOR;
      case i::FunctionKind::kBaseConstructor:
        return capnp::FunctionKind::BASE_CONSTRUCTOR;
      case i::FunctionKind::kDerivedConstructor:
        return capnp::FunctionKind::SUB_CLASS_CONSTRUCTOR;
      case i::FunctionKind::kAsyncFunction:
        return capnp::FunctionKind::ASYNC_FUNCTION;
      case i::FunctionKind::kAsyncArrowFunction:
        return capnp::FunctionKind::ASYNC_ARROW_FUNCTION;
      case i::FunctionKind::kAsyncConciseMethod:
      case i::FunctionKind::kStaticAsyncConciseMethod:
        if (kind == i::FunctionKind::kStaticAsyncConciseMethod) {
          // TODO(taint_tracking): Need modern API for: preserving static async
          // concise method information in FunctionKind serialization.
          MarkTodo(
              "Need modern API for: static async concise FunctionKind metadata");
        }
        return capnp::FunctionKind::ASYNC_CONCISE_METHOD;
      case i::FunctionKind::kModule:
      case i::FunctionKind::kModuleWithTopLevelAwait:
      case i::FunctionKind::kAsyncConciseGeneratorMethod:
      case i::FunctionKind::kStaticAsyncConciseGeneratorMethod:
      case i::FunctionKind::kAsyncGeneratorFunction:
      case i::FunctionKind::kClassMembersInitializerFunction:
      case i::FunctionKind::kClassMembersInitializerFunctionPrecededByStatic:
      case i::FunctionKind::kClassStaticInitializerFunction:
      case i::FunctionKind::kClassStaticInitializerFunctionPrecededByMember:
      case i::FunctionKind::kInvalid:
        // TODO(taint_tracking): Need modern API for: new FunctionKind members
        // that do not have a lossless legacy Cap'n Proto equivalent.
        MarkTodo("Need modern API for: unmapped modern FunctionKind");
        return capnp::FunctionKind::NORMAL_FUNCTION;
    }
    UNREACHABLE();
  }

  ::Ast::VariableMode ToAstVariableMode(i::VariableMode mode) {
    switch (mode) {
      case i::VariableMode::kVar:
        return ::Ast::VariableMode::VAR;
      case i::VariableMode::kLet:
        return ::Ast::VariableMode::LET;
      case i::VariableMode::kConst:
        return ::Ast::VariableMode::CONST;
      case i::VariableMode::kTemporary:
        return ::Ast::VariableMode::TEMPORARY;
      case i::VariableMode::kDynamic:
        return ::Ast::VariableMode::DYNAMIC;
      case i::VariableMode::kDynamicGlobal:
        return ::Ast::VariableMode::DYNAMIC_GLOBAL;
      case i::VariableMode::kDynamicLocal:
        return ::Ast::VariableMode::DYNAMIC_LOCAL;
      case i::VariableMode::kUsing:
      case i::VariableMode::kAwaitUsing:
      case i::VariableMode::kPrivateMethod:
      case i::VariableMode::kPrivateSetterOnly:
      case i::VariableMode::kPrivateGetterOnly:
      case i::VariableMode::kPrivateGetterAndSetter:
        MarkTodo("Need modern API for: unsupported VariableMode in ast.capnp");
        return ::Ast::VariableMode::LET;
    }
    UNREACHABLE();
  }

  ::Ast::Variable::Location ToAstVariableLocation(i::VariableLocation location) {
    switch (location) {
      case i::VariableLocation::UNALLOCATED:
        return ::Ast::Variable::Location::UNALLOCATED;
      case i::VariableLocation::PARAMETER:
        return ::Ast::Variable::Location::PARAMETER;
      case i::VariableLocation::LOCAL:
        return ::Ast::Variable::Location::LOCAL;
      case i::VariableLocation::CONTEXT:
        return ::Ast::Variable::Location::CONTEXT;
      case i::VariableLocation::LOOKUP:
        return ::Ast::Variable::Location::LOOKUP_SLOT;
      case i::VariableLocation::MODULE:
        MarkTodo("Need modern API for: MODULE VariableLocation absent in ast.capnp");
        return ::Ast::Variable::Location::CONTEXT;
      case i::VariableLocation::REPL_GLOBAL:
        MarkTodo("Need modern API for: REPL_GLOBAL VariableLocation");
        return ::Ast::Variable::Location::GLOBAL;
    }
    UNREACHABLE();
  }

  ::Ast::Call::CallType ToAstCallType(i::Call::CallType call_type) {
    switch (call_type) {
      case i::Call::GLOBAL_CALL:
        return ::Ast::Call::CallType::GLOBAL_CALL;
      case i::Call::WITH_CALL:
        MarkTodo("Need modern API for: WITH_CALL absent in ast.capnp");
        return ::Ast::Call::CallType::UNKNOWN;
      case i::Call::NAMED_PROPERTY_CALL:
      case i::Call::NAMED_OPTIONAL_CHAIN_PROPERTY_CALL:
        return ::Ast::Call::CallType::NAMED_PROPERTY_CALL;
      case i::Call::KEYED_PROPERTY_CALL:
      case i::Call::KEYED_OPTIONAL_CHAIN_PROPERTY_CALL:
        return ::Ast::Call::CallType::KEYED_PROPERTY_CALL;
      case i::Call::NAMED_SUPER_PROPERTY_CALL:
        return ::Ast::Call::CallType::NAMED_SUPER_PROPERTY_CALL;
      case i::Call::KEYED_SUPER_PROPERTY_CALL:
        return ::Ast::Call::CallType::KEYED_SUPER_PROPERTY_CALL;
      case i::Call::PRIVATE_CALL:
      case i::Call::PRIVATE_OPTIONAL_CHAIN_CALL:
      case i::Call::OTHER_CALL:
        return ::Ast::Call::CallType::OTHER_CALL;
      case i::Call::SUPER_CALL:
        return ::Ast::Call::CallType::SUPER_CALL;
    }
    UNREACHABLE();
  }

  capnp::Token ToAstToken(i::Token::Value token) {
    switch (token) {
      case i::Token::kComma:
        return capnp::Token::COMMA;
      case i::Token::kOr:
        return capnp::Token::OR;
      case i::Token::kAnd:
        return capnp::Token::AND;
      case i::Token::kBitOr:
        return capnp::Token::BIT_OR;
      case i::Token::kBitXor:
        return capnp::Token::BIT_XOR;
      case i::Token::kBitAnd:
        return capnp::Token::BIT_AND;
      case i::Token::kShl:
        return capnp::Token::SHL;
      case i::Token::kSar:
        return capnp::Token::SAR;
      case i::Token::kShr:
        return capnp::Token::SHR;
      case i::Token::kAdd:
        return capnp::Token::ADD;
      case i::Token::kSub:
        return capnp::Token::SUB;
      case i::Token::kMul:
        return capnp::Token::MUL;
      case i::Token::kDiv:
        return capnp::Token::DIV;
      case i::Token::kMod:
        return capnp::Token::MOD;
      case i::Token::kExp:
        return capnp::Token::EXP;
      case i::Token::kAssign:
        return capnp::Token::ASSIGN;
      case i::Token::kInit:
        return capnp::Token::INIT;
      case i::Token::kInc:
        return capnp::Token::INC;
      case i::Token::kDec:
        return capnp::Token::DEC;
      case i::Token::kEq:
        return capnp::Token::EQ;
      case i::Token::kNotEq:
        return capnp::Token::NE;
      case i::Token::kEqStrict:
        return capnp::Token::EQ_STRICT;
      case i::Token::kNotEqStrict:
        return capnp::Token::NE_STRICT;
      case i::Token::kLessThan:
        return capnp::Token::LT;
      case i::Token::kGreaterThan:
        return capnp::Token::GT;
      case i::Token::kLessThanEq:
        return capnp::Token::LTE;
      case i::Token::kGreaterThanEq:
        return capnp::Token::GTE;
      case i::Token::kInstanceOf:
        return capnp::Token::INSTANCEOF;
      case i::Token::kIn:
        return capnp::Token::IN;
      case i::Token::kAssignBitOr:
        return capnp::Token::ASSIGN_BIT_OR;
      case i::Token::kAssignBitXor:
        return capnp::Token::ASSIGN_BIT_XOR;
      case i::Token::kAssignBitAnd:
        return capnp::Token::ASSIGN_BIT_AND;
      case i::Token::kAssignShl:
        return capnp::Token::ASSIGN_SHL;
      case i::Token::kAssignSar:
        return capnp::Token::ASSIGN_SAR;
      case i::Token::kAssignShr:
        return capnp::Token::ASSIGN_SHR;
      case i::Token::kAssignAdd:
        return capnp::Token::ASSIGN_ADD;
      case i::Token::kAssignSub:
        return capnp::Token::ASSIGN_SUB;
      case i::Token::kAssignMul:
        return capnp::Token::ASSIGN_MUL;
      case i::Token::kAssignDiv:
        return capnp::Token::ASSIGN_DIV;
      case i::Token::kAssignMod:
        return capnp::Token::ASSIGN_MOD;
      case i::Token::kAssignExp:
        return capnp::Token::ASSIGN_EXP;
      case i::Token::kNot:
        return capnp::Token::NOT;
      case i::Token::kBitNot:
        return capnp::Token::BIT_NOT;
      case i::Token::kDelete:
        return capnp::Token::DELETE;
      case i::Token::kTypeOf:
        return capnp::Token::TYPEOF;
      case i::Token::kVoid:
        return capnp::Token::VOID;
      case i::Token::kNullish:
      case i::Token::kAssignNullish:
      case i::Token::kAssignOr:
      case i::Token::kAssignAnd:
        // TODO(taint_tracking): Need modern API for: nullish/logical assignment
        // operators absent from the legacy Cap'n Proto token enum.
        MarkTodo("Need modern API for: unmapped modern Token::Value");
        return capnp::Token::ASSIGN;
      default:
        MarkTodo("Need modern API for: unexpected Token::Value");
        return capnp::Token::ASSIGN;
    }
  }

  capnp::KeyedAccessStoreMode LegacyFallbackStoreMode(const char* reason) {
    // TODO(taint_tracking): Need modern API for: Assignment/CountOperation
    // store mode accessors removed from the modern AST API.
    MarkTodo(reason);
    return capnp::KeyedAccessStoreMode::STANDARD_STORE;
  }

  void EmitUnsupportedExpressionPlaceholder(const char* reason) {
    MarkTodo(reason);
    auto literal = GetCurrentExprNodeVal().initLiteral();
    literal.initObjectValue().getValue().setUndefined();
  }

  void EmitUnsupportedStatementPlaceholder(const char* reason) {
    MarkTodo(reason);
    GetCurrentStmtNodeVal().initEmptyStatement();
  }

  void HandleVariable(i::Variable* variable, ::Ast::Variable::Builder* builder) {
    if (variable == nullptr) {
      return;
    }
    DCHECK_NOT_NULL(variable);

    auto scope = builder->initScope();
    HandleScope(variable->scope(), &scope);

    auto name = builder->initName();
    HandleAstRawString(variable->raw_name(), &name);

    switch (variable->kind()) {
      case i::THIS_VARIABLE:
        builder->setKind(::Ast::Variable::Kind::THIS);
        break;
      case i::NORMAL_VARIABLE:
      case i::PARAMETER_VARIABLE:
        builder->setKind(::Ast::Variable::Kind::NORMAL);
        break;
      case i::SLOPPY_BLOCK_FUNCTION_VARIABLE:
      case i::SLOPPY_FUNCTION_NAME_VARIABLE:
        // TODO(taint_tracking): Need modern API for: VariableKind values with
        // no exact legacy Cap'n Proto enum.
        MarkTodo("Need modern API for: unmapped modern VariableKind");
        builder->setKind(::Ast::Variable::Kind::NORMAL);
        break;
    }

    builder->setMode(ToAstVariableMode(variable->mode()));
    switch (variable->initialization_flag()) {
      case i::kNeedsInitialization:
        builder->setInitializationFlag(
            capnp::InitializationFlag::NEEDS_INITIALIZATION);
        break;
      case i::kCreatedInitialized:
        builder->setInitializationFlag(
            capnp::InitializationFlag::CREATED_INITIALIZED);
        break;
    }
    builder->setLocation(ToAstVariableLocation(variable->location()));
  }

  void HandleResolvedVariableProxy(i::Variable* variable,
                                   ::Ast::VariableProxy::Builder* builder) {
    builder->setIsResolved(true);
    builder->setIsThis(variable != nullptr && variable->is_this());
    builder->setIsAssigned(false);
    builder->setIsNewTarget(false);
    auto var = builder->getValue().initVar();
    HandleVariable(variable, &var);
  }

  void HandleVariableProxy(i::VariableProxy* node,
                           ::Ast::VariableProxy::Builder* builder) {
    const bool is_resolved = node->is_resolved();
    builder->setIsResolved(is_resolved);
    builder->setIsThis(node->is_resolved() && node->var()->is_this());
    builder->setIsAssigned(node->is_assigned());
    builder->setIsNewTarget(node->is_new_target());
    if (is_resolved) {
      auto var = builder->getValue().initVar();
      HandleVariable(node->var(), &var);
    } else {
      auto name = builder->getValue().initName();
      HandleAstRawString(node->raw_name(), &name);
    }
  }

  void HandleDeclaration(i::Declaration* node,
                         ::Ast::DeclarationInterface::Builder* builder) {
    i::Variable* variable = node->var();
    auto proxy_node = builder->initProxy();
    auto proxy = proxy_node.initProxy();
    HandleResolvedVariableProxy(variable, &proxy);
    if (variable == nullptr) return;
    DCHECK_NOT_NULL(variable);

    builder->setMode(ToAstVariableMode(variable->mode()));

    auto scope = builder->initScope();
    if (node->IsVariableDeclaration()) {
      i::NestedVariableDeclaration* nested =
          node->AsVariableDeclaration()->AsNested();
      HandleScope(nested != nullptr ? nested->scope() : variable->scope(),
                  &scope);
    } else {
      HandleScope(variable->scope(), &scope);
    }
  }

  void HandleVariableDeclaration(
      i::VariableDeclaration* node,
      ::Ast::DeclarationInterface::Builder* builder) {
    HandleDeclaration(node, builder);
  }

  void HandleFunctionDeclaration(
      i::FunctionDeclaration* node,
      ::Ast::FunctionDeclaration::Builder* builder) {
    auto decl = builder->initDeclaration();
    HandleDeclaration(node, &decl);
    auto fn_node = builder->initFunctionLiteral();
    auto fn = fn_node.initFunc();
    HandleFunctionLiteral(node->fun(), &fn);
  }

  void HandleStatementList(
      const i::ZonePtrList<i::Statement>* statements,
      ::capnp::List<capnp::Statement>::Builder* builder) {
    for (int i = 0; i < statements->length(); ++i) {
      SerializeChild(statements->at(i), (*builder)[i]);
    }
  }

  void HandleExpressionList(
      const i::ZonePtrList<i::Expression>* expressions,
      ::capnp::List<capnp::Expression>::Builder* builder) {
    for (int i = 0; i < expressions->length(); ++i) {
      SerializeChild(expressions->at(i), (*builder)[i]);
    }
  }

  void HandleCaseClause(i::CaseClause* node,
                        ::Ast::CaseClause::Builder* builder) {
    builder->setIsDefault(node->is_default());
    if (!node->is_default()) {
      SerializeChild(node->label(), builder->initLabel());
    }
    auto* statements = node->statements();
    auto out_statements = builder->initStatements(statements->length());
    HandleStatementList(statements, &out_statements);
  }

  void HandleBlock(i::Block* node, ::Ast::Block::Builder* builder) {
    auto scope = builder->initScope();
    HandleScope(node->scope(), &scope);
    auto* statements = node->statements();
    auto out_statements = builder->initStatements(statements->length());
    HandleStatementList(statements, &out_statements);
  }

  void HandleFunctionLiteral(i::FunctionLiteral* node,
                             ::Ast::FunctionLiteral::Builder* builder) {
    if (node->has_shared_name()) {
      auto name = builder->initName();
      HandleAstConsString(node->raw_name(), &name);
    }

    builder->setFunctionType(ToAstFunctionType(node->syntax_kind()));
    builder->setFunctionKind(ToAstFunctionKind(node->kind()));

    auto decl_scope = builder->initScope();
    auto scope_ptr = decl_scope.initScope();
    HandleScope(node->scope(), &scope_ptr);

    i::Declaration::List* declarations = node->scope()->declarations();
    auto out_declarations =
        decl_scope.initDeclarations(static_cast<unsigned int>(CountDeclarations(declarations)));
    size_t index = 0;
    for (i::Declaration* declaration : *declarations) {
      auto out_declaration = out_declarations[static_cast<unsigned int>(index)].getNodeVal();
      if (declaration->IsVariableDeclaration()) {
        auto out_var = out_declaration.initVariableDeclaration();
        HandleVariableDeclaration(declaration->AsVariableDeclaration(),
                                  &out_var);
      } else {
        DCHECK(declaration->IsFunctionDeclaration());
        auto out_fn = out_declaration.initFunctionDeclaration();
        HandleFunctionDeclaration(declaration->AsFunctionDeclaration(), &out_fn);
      }
      ++index;
    }

    if (node->scope()->was_lazily_parsed()) {
      builder->initBody(0);
      return;
    }

    auto* body = node->body();
    auto out_body = builder->initBody(body->length());
    HandleStatementList(body, &out_body);
  }

  void VisitVariableDeclaration(i::VariableDeclaration* node) {
    auto out = GetCurrentDeclNodeVal().initVariableDeclaration();
    HandleVariableDeclaration(node, &out);
  }

  void VisitFunctionDeclaration(i::FunctionDeclaration* node) {
    auto out = GetCurrentDeclNodeVal().initFunctionDeclaration();
    HandleFunctionDeclaration(node, &out);
  }

  void VisitDoWhileStatement(i::DoWhileStatement* node) {
    auto out = GetCurrentStmtNodeVal().initDoWhileStatement();
    SerializeChild(node->cond(), out.initCond());
    SerializeChild(node->body(), out.initBody());
  }

  void VisitWhileStatement(i::WhileStatement* node) {
    auto out = GetCurrentStmtNodeVal().initWhileStatement();
    SerializeChild(node->cond(), out.initCond());
    SerializeChild(node->body(), out.initBody());
  }

  void VisitForStatement(i::ForStatement* node) {
    auto out = GetCurrentStmtNodeVal().initForStatement();
    if (node->init() != nullptr) SerializeChild(node->init(), out.initInit());
    if (node->cond() != nullptr) SerializeChild(node->cond(), out.initCond());
    if (node->next() != nullptr) SerializeChild(node->next(), out.initNext());
    SerializeChild(node->body(), out.initBody());
  }

  void VisitForInStatement(i::ForInStatement* node) {
    auto out = GetCurrentStmtNodeVal().initForInStatement();
    SerializeChild(node->body(), out.initBody());
    SerializeChild(node->each(), out.initEach());
    SerializeChild(node->subject(), out.initSubject());
  }

  void VisitForOfStatement(i::ForOfStatement* node) {
    (void)node;
    auto out = GetCurrentStmtNodeVal().initForOfStatement();
    (void)out;
    MarkTodo("Need modern API for: ForOfStatement");
  }

  void VisitExpressionStatement(i::ExpressionStatement* node) {
    SerializeChild(node->expression(), *current_expr_);
  }

  void VisitEmptyStatement(i::EmptyStatement* node) {
    (void)node;
    GetCurrentStmtNodeVal().initEmptyStatement();
  }

  void VisitSloppyBlockFunctionStatement(
      i::SloppyBlockFunctionStatement* node) {
    SerializeChild(node->statement(), *current_stmt_);
  }

  void VisitIfStatement(i::IfStatement* node) {
    auto out = GetCurrentStmtNodeVal().initIfStatement();
    SerializeChild(node->condition(), out.initCond());
    SerializeChild(node->then_statement(), out.initThen());
    SerializeChild(node->else_statement(), out.initElse());
  }

  void VisitContinueStatement(i::ContinueStatement* node) {
    (void)node;
    GetCurrentStmtNodeVal().initContinueStatement();
  }

  void VisitBreakStatement(i::BreakStatement* node) {
    (void)node;
    GetCurrentStmtNodeVal().initBreakStatement();
  }

  void VisitReturnStatement(i::ReturnStatement* node) {
    auto out = GetCurrentStmtNodeVal().initReturnStatement();
    SerializeChild(node->expression(), out.initValue());
  }

  void VisitWithStatement(i::WithStatement* node) {
    auto out = GetCurrentStmtNodeVal().initWithStatement();
    auto scope = out.initScope();
    HandleScope(node->scope(), &scope);
    SerializeChild(node->expression(), out.initExpression());
    SerializeChild(node->statement(), out.initStatement());
  }

  void VisitSwitchStatement(i::SwitchStatement* node) {
    auto out = GetCurrentStmtNodeVal().initSwitchStatement();
    SerializeChild(node->tag(), out.initTag());
    auto* cases = node->cases();
    auto out_cases = out.initCaseClauses(cases->length());
    for (int i = 0; i < cases->length(); ++i) {
      auto case_builder = out_cases[i];
      HandleCaseClause(cases->at(i), &case_builder);
    }
  }

  void VisitBlock(i::Block* node) {
    auto out = GetCurrentStmtNodeVal().initBlock();
    HandleBlock(node, &out);
  }

  void VisitTryCatchStatement(i::TryCatchStatement* node) {
    auto out = GetCurrentStmtNodeVal().initTryCatchStatement();
    auto scope = out.initScope();
    HandleScope(node->scope(), &scope);
    if (node->scope() != nullptr && node->scope()->catch_variable() != nullptr) {
      auto variable = out.initVariable();
      HandleVariable(node->scope()->catch_variable(), &variable);
    }
    auto catch_block_node = out.initCatchBlock();
    auto catch_block = catch_block_node.initBlock();
    HandleBlock(node->catch_block(), &catch_block);
    auto try_block_node = out.initTryBlock();
    auto try_block = try_block_node.initBlock();
    HandleBlock(node->try_block(), &try_block);
  }

  void VisitTryFinallyStatement(i::TryFinallyStatement* node) {
    auto out = GetCurrentStmtNodeVal().initTryFinallyStatement();
    auto finally_block_node = out.initFinallyBlock();
    auto finally_block = finally_block_node.initBlock();
    HandleBlock(node->finally_block(), &finally_block);
    auto try_block_node = out.initTryBlock();
    auto try_block = try_block_node.initBlock();
    HandleBlock(node->try_block(), &try_block);
  }

  void VisitDebuggerStatement(i::DebuggerStatement* node) {
    (void)node;
    // initDebuggerStatement may not exist in newer capnproto schema
    // Using a placeholder or skipping this statement type
    // TODO: Check if there's an alternative method in the schema
  }

  void VisitInitializeClassMembersStatement(
      i::InitializeClassMembersStatement* node) {
    (void)node;
    EmitUnsupportedStatementPlaceholder(
        "Need modern API for: InitializeClassMembersStatement");
  }

  void VisitInitializeClassStaticElementsStatement(
      i::InitializeClassStaticElementsStatement* node) {
    (void)node;
    EmitUnsupportedStatementPlaceholder(
        "Need modern API for: InitializeClassStaticElementsStatement");
  }

  void VisitAutoAccessorGetterBody(i::AutoAccessorGetterBody* node) {
    (void)node;
    EmitUnsupportedStatementPlaceholder(
        "Need modern API for: AutoAccessorGetterBody");
  }

  void VisitAutoAccessorSetterBody(i::AutoAccessorSetterBody* node) {
    (void)node;
    EmitUnsupportedStatementPlaceholder(
        "Need modern API for: AutoAccessorSetterBody");
  }

  void VisitRegExpLiteral(i::RegExpLiteral* node) {
    auto out = GetCurrentExprNodeVal().initRegExpLiteral();
    auto pattern = out.initPattern();
    HandleAstRawString(node->raw_pattern(), &pattern);
    out.setFlags(node->flags());
  }

  void VisitObjectLiteral(i::ObjectLiteral* node) {
    auto out = GetCurrentExprNodeVal().initObjectLiteral();
    auto* properties = node->properties();
    auto out_properties = out.initProperties(properties->length());
    for (int i = 0; i < properties->length(); ++i) {
      i::ObjectLiteralProperty* property = properties->at(i);
      auto out_property = out_properties[i];
      switch (property->kind()) {
        case i::ObjectLiteralProperty::CONSTANT:
          out_property.setKind(capnp::LiteralProperty::Kind::CONSTANT);
          break;
        case i::ObjectLiteralProperty::COMPUTED:
          out_property.setKind(capnp::LiteralProperty::Kind::COMPUTED);
          break;
        case i::ObjectLiteralProperty::MATERIALIZED_LITERAL:
          out_property.setKind(
              capnp::LiteralProperty::Kind::MATERIALIZED_LITERAL);
          break;
        case i::ObjectLiteralProperty::GETTER:
          out_property.setKind(capnp::LiteralProperty::Kind::GETTER);
          break;
        case i::ObjectLiteralProperty::SETTER:
          out_property.setKind(capnp::LiteralProperty::Kind::SETTER);
          break;
        case i::ObjectLiteralProperty::PROTOTYPE:
          out_property.setKind(capnp::LiteralProperty::Kind::PROTOTYPE);
          break;
        case i::ObjectLiteralProperty::SPREAD:
          // TODO(taint_tracking): Need modern API for: object spread properties
          // absent from the legacy Cap'n Proto schema.
          MarkTodo("Need modern API for: ObjectLiteralProperty::SPREAD");
          out_property.setKind(capnp::LiteralProperty::Kind::COMPUTED);
          break;
      }

      SerializeChild(property->key(), out_property.initKey());
      SerializeChild(property->value(), out_property.initValue());
      out_property.setIsComputedName(property->is_computed_name());
      out_property.setIsStatic(false);
    }
  }

  void VisitArrayLiteral(i::ArrayLiteral* node) {
    auto out = GetCurrentExprNodeVal().initArrayLiteral();
    auto* values = node->values();
    auto out_values = out.initValues(values->length());
    HandleExpressionList(values, &out_values);
  }

  void VisitAssignment(i::Assignment* node) {
    auto out = GetCurrentExprNodeVal().initAssignment();
    out.setOperation(ToAstToken(node->op()));
    out.setStoreMode(
        LegacyFallbackStoreMode("Need modern API for: Assignment store mode"));
    out.setIsSimple(true);
    // TODO(taint_tracking): Need modern API for: Assignment::IsUninitialized(),
    // which no longer exists on the modern AST API.
    MarkTodo("Need modern API for: Assignment uninitialized-field flag");
    out.setIsUninitializedField(false);
    SerializeChild(node->target(), out.initTarget());
    SerializeChild(node->value(), out.initValue());
  }

  void VisitCompoundAssignment(i::CompoundAssignment* node) {
    auto out = GetCurrentExprNodeVal().initAssignment();
    out.setOperation(ToAstToken(node->op()));
    out.setStoreMode(LegacyFallbackStoreMode(
        "Need modern API for: CompoundAssignment store mode"));
    out.setIsSimple(false);
    out.setIsUninitializedField(false);
    SerializeChild(node->target(), out.initTarget());
    SerializeChild(node->value(), out.initValue());
  }

  void VisitAwait(i::Await* node) {
    (void)node;
    EmitUnsupportedExpressionPlaceholder("Need modern API for: Await");
  }

  void VisitBinaryOperation(i::BinaryOperation* node) {
    auto out = GetCurrentExprNodeVal().initBinaryOperation();
    out.setToken(ToAstToken(node->op()));
    SerializeChild(node->left(), out.initLeft());
    SerializeChild(node->right(), out.initRight());
  }

  void VisitNaryOperation(i::NaryOperation* node) {
    (void)node;
    EmitUnsupportedExpressionPlaceholder("Need modern API for: NaryOperation");
  }

  void VisitCall(i::Call* node) {
    auto out = GetCurrentExprNodeVal().initCall();
    SerializeChild(node->expression(), out.initExpression());
    out.setCallType(ToAstCallType(node->GetCallType()));
    auto arguments = out.initArguments(node->arguments()->length());
    HandleExpressionList(node->arguments(), &arguments);
  }

  void VisitSuperCallForwardArgs(i::SuperCallForwardArgs* node) {
    (void)node;
    EmitUnsupportedExpressionPlaceholder(
        "Need modern API for: SuperCallForwardArgs");
  }

  void VisitCallNew(i::CallNew* node) {
    auto out = GetCurrentExprNodeVal().initCallNew();
    SerializeChild(node->expression(), out.initExpression());
    auto arguments = out.initArguments(node->arguments()->length());
    HandleExpressionList(node->arguments(), &arguments);
  }

  void VisitCallRuntime(i::CallRuntime* node) {
    auto out = GetCurrentExprNodeVal().initCallRuntime();
    auto arguments = out.initArguments(node->arguments()->length());
    HandleExpressionList(node->arguments(), &arguments);

    auto info = out.initInfo();
    auto fn = info.getFn();
    // TODO(taint_tracking): Need modern API for: CallRuntime no longer has
    // is_jsruntime() and context_index() methods in modern V8.
    // Always treating as regular runtime function.
    auto runtime_function = fn.initRuntimeFunction();
    runtime_function.setId(node->function()->function_id);
    runtime_function.setName(node->function()->name);
  }

  void VisitClassLiteral(i::ClassLiteral* node) {
    (void)node;
    GetCurrentExprNodeVal().initClassLiteral();
    MarkTodo("Need modern API for: ClassLiteral payload absent in ast.capnp");
  }

  void VisitCompareOperation(i::CompareOperation* node) {
    auto out = GetCurrentExprNodeVal().initCompareOperation();
    out.setToken(ToAstToken(node->op()));
    SerializeChild(node->left(), out.initLeft());
    SerializeChild(node->right(), out.initRight());
  }

  void VisitConditionalChain(i::ConditionalChain* node) {
    (void)node;
    EmitUnsupportedExpressionPlaceholder(
        "Need modern API for: ConditionalChain");
  }

  void VisitConditional(i::Conditional* node) {
    auto out = GetCurrentExprNodeVal().initConditional();
    SerializeChild(node->condition(), out.initCond());
    SerializeChild(node->then_expression(), out.initThen());
    SerializeChild(node->else_expression(), out.initElse());
  }

  void VisitCountOperation(i::CountOperation* node) {
    auto out = GetCurrentExprNodeVal().initCountOperation();
    out.setOperation(ToAstToken(node->op()));
    out.setIsPrefix(node->is_prefix());
    out.setIsPostfix(node->is_postfix());
    out.setStoreMode(LegacyFallbackStoreMode(
        "Need modern API for: CountOperation store mode"));
    SerializeChild(node->expression(), out.initExpression());
  }

  void VisitEmptyParentheses(i::EmptyParentheses* node) {
    (void)node;
    GetCurrentExprNodeVal().initEmptyParentheses();
  }

  void VisitFunctionLiteral(i::FunctionLiteral* node) {
    auto out = GetCurrentExprNodeVal().initFunctionLiteral();
    HandleFunctionLiteral(node, &out);
  }

  void VisitGetTemplateObject(i::GetTemplateObject* node) {
    (void)node;
    EmitUnsupportedExpressionPlaceholder(
        "Need modern API for: GetTemplateObject");
  }

  void VisitImportCallExpression(i::ImportCallExpression* node) {
    (void)node;
    EmitUnsupportedExpressionPlaceholder(
        "Need modern API for: ImportCallExpression absent in ast.capnp");
  }

  void VisitLiteral(i::Literal* node) {
    auto literal = GetCurrentExprNodeVal().initLiteral();
    auto object_value = literal.initObjectValue();

    switch (node->type()) {
      case i::Literal::kSmi:
        object_value.getValue().setSmi(node->AsSmiLiteral().value());
        return;
      case i::Literal::kHeapNumber:
        object_value.getValue().setNumber(node->AsNumber());
        return;
      case i::Literal::kString: {
        if (node->IsPropertyName()) {
          auto symbol = object_value.getValue().initSymbol();
          HandleAstRawString(node->AsRawString(), &symbol);
        } else {
          auto string = object_value.getValue().initString();
          HandleAstRawString(node->AsRawString(), &string);
        }
        return;
      }
      case i::Literal::kConsString:
        if (node->IsPropertyName()) {
          auto symbol = object_value.getValue().initSymbol();
          HandleAstConsString(node->AsConsString(), &symbol);
        } else {
          auto string = object_value.getValue().initString();
          HandleAstConsString(node->AsConsString(), &string);
        }
        return;
      case i::Literal::kBoolean:
        object_value.getValue().setBoolean(node->AsBooleanLiteral());
        return;
      case i::Literal::kUndefined:
        object_value.getValue().setUndefined();
        return;
      case i::Literal::kNull:
        object_value.getValue().setNullObject();
        return;
      case i::Literal::kTheHole:
        object_value.getValue().setTheHole();
        return;
      case i::Literal::kBigInt:
        // TODO(taint_tracking): Need modern API for: BigInt literal payloads
        // absent from the legacy literal value schema.
        MarkTodo("Need modern API for: Literal::kBigInt");
        object_value.getValue().setUndefined();
        return;
    }
    UNREACHABLE();
  }

  void VisitNativeFunctionLiteral(i::NativeFunctionLiteral* node) {
    auto out = GetCurrentExprNodeVal().initNativeFunctionLiteral();
    out.setName(node->name()->ToCString().get());
    out.setExtensionName(node->extension() != nullptr ? node->extension()->name()
                                                      : "");
  }

  void VisitOptionalChain(i::OptionalChain* node) {
    (void)node;
    EmitUnsupportedExpressionPlaceholder(
        "Need modern API for: OptionalChain");
  }

  void VisitProperty(i::Property* node) {
    auto out = GetCurrentExprNodeVal().initProperty();
    // TODO(taint_tracking): Need modern API for: Property::is_for_call() and
    // Property::IsStringAccess(), which no longer exist in the modern AST API.
    MarkTodo("Need modern API for: Property call/string-access flags");
    out.setIsForCall(false);
    out.setIsStringAccess(false);
    SerializeChild(node->key(), out.initKey());
    SerializeChild(node->obj(), out.initObj());
  }

  void VisitSpread(i::Spread* node) {
    (void)node;
    GetCurrentExprNodeVal().initSpread();
    MarkTodo("Need modern API for: Spread payload absent in ast.capnp");
  }

  void VisitSuperCallReference(i::SuperCallReference* node) {
    auto out = GetCurrentExprNodeVal().initSuperCallReference();
    if (node->new_target_var() != nullptr) {
      auto new_target_node = out.initNewTargetVar();
      auto new_target = new_target_node.initProxy();
      HandleVariableProxy(node->new_target_var(), &new_target);
    }
    if (node->this_function_var() != nullptr) {
      auto this_function_node = out.initThisFunctionVar();
      auto this_function = this_function_node.initProxy();
      HandleVariableProxy(node->this_function_var(), &this_function);
    }
  }

  void VisitSuperPropertyReference(i::SuperPropertyReference* node) {
    auto out = GetCurrentExprNodeVal().initSuperPropertyReference();
    SerializeChild(node->home_object(), out.initHomeObject());
  }

  void VisitTemplateLiteral(i::TemplateLiteral* node) {
    (void)node;
    EmitUnsupportedExpressionPlaceholder(
        "Need modern API for: TemplateLiteral");
  }

  void VisitThisExpression(i::ThisExpression* node) {
    (void)node;
    GetCurrentExprNodeVal().initThisFunction();
  }

  void VisitThrow(i::Throw* node) {
    auto out = GetCurrentExprNodeVal().initThrow();
    SerializeChild(node->exception(), out.initException());
  }

  void VisitUnaryOperation(i::UnaryOperation* node) {
    auto out = GetCurrentExprNodeVal().initUnaryOperation();
    out.setToken(ToAstToken(node->op()));
    SerializeChild(node->expression(), out.initExpression());
  }

  void VisitVariableProxy(i::VariableProxy* node) {
    auto out = GetCurrentExprNodeVal().initVariableProxy();
    HandleVariableProxy(node, &out);
  }

  void VisitYield(i::Yield* node) {
    (void)node;
    auto out = GetCurrentExprNodeVal().initYield();
    (void)out;
    MarkTodo("Need modern API for: Yield");
  }

  void VisitYieldStar(i::YieldStar* node) {
    (void)node;
    EmitUnsupportedExpressionPlaceholder("Need modern API for: YieldStar");
  }

  using BuilderVariant = std::variant<capnp::Statement::Builder, capnp::Expression::Builder, capnp::Declaration::Builder>;

  std::optional<capnp::Statement::Builder> current_stmt_;
  std::optional<capnp::Expression::Builder> current_expr_;
  std::optional<capnp::Declaration::Builder> current_decl_;
  capnp::Builder* root_builder_;
  bool success_ = true;
  const char* first_todo_ = nullptr;
};

bool SerializeAst(i::FunctionLiteral* ast, capnp::Builder* message,
                  i::Isolate* isolate) {
  if (ast == nullptr || message == nullptr || isolate == nullptr) return false;
  AstSerializer serializer(message, isolate);
  serializer.SerializeRoot(ast);
  return serializer.success();
}

}  // namespace tainttracking
