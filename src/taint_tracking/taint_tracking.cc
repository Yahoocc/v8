// This file has the main logic for taint tracking

// Taint tracking imports
#include "src/taint_tracking.h"

#include "src/taint_tracking-inl.h"
#include "src/taint_tracking/ast_serialization.h"
#include "src/taint_tracking/log_listener.h"
#include "src/taint_tracking/object_versioner.h"
#include "src/taint_tracking/picosha2.h"
#include "v8/logrecord.capnp.h"

// Other V8 imports
#include <stdio.h>
#include <string.h>

#include <array>
#include <limits>
#include <memory>
#include <random>
#include <tuple>
#include <unordered_map>

#include "src/ast/ast.h"
#include "src/base/bits.h"
#include "src/base/platform/platform.h"
#include "src/tasks/cancelable-task.h"
#include "src/heap/factory.h"
#include "src/heap/heap.h"
#include "src/execution/isolate.h"
#include "src/objects/objects-inl.h"
#include "src/parsing/parser.h"
#include "src/strings/string-stream.h"
#include "src/utils/utils.h"
#include "src/init/v8.h"

// For the capnp library
#include <capnp/message.h>
#include <capnp/serialize-packed.h>
#include <capnp/serialize.h>
#include <kj/std/iostream.h>

namespace v8 {
namespace internal {
// Note: DEFAULT_TAINT_INFO removed in new V8 version
// const int64_t Name::DEFAULT_TAINT_INFO;
}
}  // namespace v8

using namespace v8::internal;

namespace tainttracking {

// Increment this when changing memory layout for the effect to propagate to
// deserialized code
const int kTaintTrackingVersion = 15;

// const int kPointerStrSize = 64;  // Unused
// const int kBitsPerByte = 8;  // Unused
// const int kStackTraceInfoSize = 4000;  // Unused
const char kEnableHeaderLoggingName[] = "enableHeaderLogging";
const char kEnableBodyLoggingName[] = "enableBodyLogging";
const char kLoggingFilenamePrefix[] = "loggingFilenamePrefix";
const char kJobIdName[] = "jobId";
// const char kJsTaintProperty[] = "taintStatus";  // Unused
// const char kJsIdProperty[] = "id";  // Unused
const InstanceCounter kMaxCounterSnapshot = 1 << 16;

const v8::base::TimeDelta kMaxTimeBetweenFlushes =
    v8::base::TimeDelta::FromSeconds(10);

// Number of messages to queue before flushing the log stream.
const int kFlushMessageMax = 1000;
const int kLogBufferSize = 64 * MB;

int TaintTracker::Impl::isolate_counter_ = 0;
std::mutex TaintTracker::Impl::isolate_counter_mutex_;

// Use a raw pointer to avoid exit-time destructor warning
LogListener* global_log_listener = nullptr;

std::unordered_map<Address, std::unique_ptr<TaintData[]>>* seq_string_taint_data =
    nullptr;

TaintData* GetSeqStringTaintData(Tagged<SeqString> str) {
  if (seq_string_taint_data == nullptr) {
    seq_string_taint_data = new std::unordered_map<Address, std::unique_ptr<TaintData[]>>();
  }
  auto& data = (*seq_string_taint_data)[str.ptr()];
  if (!data) {
    data.reset(new TaintData[str->length()]);
    memset(data.get(), static_cast<int>(TaintType::UNTAINTED), str->length());
  }
  return data.get();
}

class IsTaintedVisitor;
void InitTaintInfo(const std::vector<std::tuple<TaintType, int>>&,
                   TaintLogRecord::TaintInformation::Builder*);

void RegisterLogListener(std::unique_ptr<LogListener> listener) {
  global_log_listener = listener.release();
}

inline bool IsValidTaintType(TaintType type) {
  return (static_cast<uint8_t>(type) & TAINT_TYPE_MASK) <=
         static_cast<uint8_t>(MAX_TAINT_TYPE);
}

inline void CheckTaintError(TaintType type, Tagged<String> object, Isolate* isolate) {
#ifdef DEBUG
  if (!IsValidTaintType(type)) {
    std::unique_ptr<char[]> strval = object->ToCString();
    char stack_trace[kStackTraceInfoSize];
    FixedStringAllocator alloc(stack_trace, sizeof(stack_trace));
    StringStream stream(&alloc,
                        StringStream::ObjectPrintMode::kPrintObjectConcise);
    isolate->PrintStack(&stream);

    std::cerr << "Taint tracking memory error: "
              << std::to_string(static_cast<uint8_t>(type)).c_str()
              << std::endl;
    std::cerr << "String length: " << object->length() << std::endl;
    std::cerr << "String type: " << object->map()->instance_type() << std::endl;
    std::cerr << "String value: " << strval.get() << std::endl;
    std::cerr << "JS Stack trace: " << stack_trace << std::endl;
    std::cerr << "String address: " << ((void*)object.ptr()) << std::endl;
    FATAL("Taint Tracking Memory Error");
  }
#endif
}

class TaintVisitor {
 public:
  TaintVisitor() : visitee_(nullptr), writeable_(false), isolate_(nullptr) {}
  TaintVisitor(Isolate* isolate) : visitee_(nullptr), writeable_(false), isolate_(isolate) {}
  TaintVisitor(bool writeable, Isolate* isolate) : visitee_(nullptr), writeable_(writeable), isolate_(isolate) {}

  virtual void Visit(const uint8_t* visitee, TaintData* taint_info, int offset,
                     int size) = 0;
  virtual void Visit(const uint16_t* visitee, TaintData* taint_info, int offset,
                     int size) = 0;

  template <class T>
  void run(Tagged<T> source, int start, int len) {
    visitee_ = source;
    VisitIntoStringTemplate(source, start, len);
    // We don't want to recurse because the stack could overflow if there are
    // many ConsString's
    while (!visitee_stack_.empty()) {
      std::tuple<Tagged<String>, int, int> back = visitee_stack_.back();
      visitee_stack_.pop_back();
      VisitIntoStringTemplate(std::get<0>(back), std::get<1>(back),
                              std::get<2>(back));
    }
  }

 protected:
  Tagged<String> GetVisitee() { return visitee_; }

 private:
  template <typename Char>
  void DoVisit(Char* visitee, TaintData* taint_info, int offset, int size) {
#ifdef DEBUG
    if (taint_info != nullptr && !writeable_) {
      for (int i = 0; i < size; i++) {
        CheckTaintError(static_cast<TaintType>(*(taint_info + offset + i)),
                        GetVisitee(), isolate_);
      }
    }
#endif
    Visit(visitee, taint_info, offset, size);
  }

  template <class T>
  void VisitIntoStringTemplate(Tagged<T> source, int from, int len);

  std::vector<std::tuple<Tagged<String>, int, int>> visitee_stack_;
  Tagged<String> visitee_;
  bool writeable_;
  Isolate* isolate_;
};

MessageHolder::MessageHolder() : builder_(), depth_(0) {}
MessageHolder::~MessageHolder() {}
::TaintLogRecord::Builder MessageHolder::GetRoot() {
  return builder_.getRoot<TaintLogRecord>();
}
::TaintLogRecord::Builder MessageHolder::InitRoot() {
  return builder_.initRoot<TaintLogRecord>();
}

void MessageHolder::DoSynchronousWrite(::kj::OutputStream& stream) {
  if (v8_flags.taint_tracking_write_packed_logs) {
    capnp::writePackedMessage(stream, builder_);
  } else {
    capnp::writeMessage(stream, builder_);
  }
}

template <typename Char>
void MessageHolder::CopyBuffer(::Ast::JsString::Builder builder,
                               const Char* str, int length) {
  if (v8_flags.taint_tracking_enable_concolic_no_marshalling) {
    return;
  }

  auto segments = builder.initSegments(1);
  auto flat = segments[0];
  flat.setContent(::capnp::Data::Reader(reinterpret_cast<const uint8_t*>(str),
                                        sizeof(Char) * length));
  flat.setIsOneByte(sizeof(Char) == 1);
}

template void MessageHolder::CopyBuffer<uint8_t>(
    ::Ast::JsString::Builder builder, const uint8_t* str, int length);
template void MessageHolder::CopyBuffer<uint16_t>(
    ::Ast::JsString::Builder builder, const uint16_t* str, int length);

class StringCopier : public TaintVisitor {
 public:
  StringCopier(Isolate* isolate) : TaintVisitor(isolate) {}

  void Visit(const uint8_t* visitee, TaintData* taint_info, int offset,
             int size) override {
    segments_.push_back(std::make_tuple(visitee + offset, true, size));
  }
  void Visit(const uint16_t* visitee, TaintData* taint_info, int offset,
             int size) override {
    segments_.push_back(
        std::make_tuple(reinterpret_cast<const uint8_t*>(visitee + offset),
                        false, size * sizeof(uint16_t)));
  }

  void Build(::Ast::JsString::Builder builder) {
    auto contents = builder.initSegments(static_cast<unsigned int>(segments_.size()));
    for (uint i = 0; i < static_cast<uint>(segments_.size()); i++) {
      auto& segment = segments_[i];
      auto out_content = contents[i];
      out_content.setContent(
          ::capnp::Data::Reader(std::get<0>(segment), std::get<2>(segment)));
      out_content.setIsOneByte(std::get<1>(segment));
    }
  }

 private:
  std::vector<std::tuple<const uint8_t*, bool, int>> segments_;
};

void MessageHolder::CopyJsStringSlow(
    ::Ast::JsString::Builder builder,
    v8::internal::Handle<v8::internal::String> str,
    v8::internal::Isolate* isolate) {
  if (v8_flags.taint_tracking_enable_concolic_no_marshalling) {
    return;
  }

  StringCopier copier(isolate);
  {
    DisallowHeapAllocation no_gc;
    copier.run(*str, 0, str->length());
  }
  copier.Build(builder);
}

void MessageHolder::CopyJsStringSlow(::Ast::JsString::Builder builder,
                                     v8::internal::String* str,
                                     v8::internal::Isolate* isolate) {
  if (v8_flags.taint_tracking_enable_concolic_no_marshalling) {
    return;
  }

  // Convert to Tagged<String>
  Tagged<String> tagged_str = Tagged<String>(str);
  StringCopier copier(isolate);
  copier.run(tagged_str, 0, str->length());
  copier.Build(builder);
}

void MessageHolder::CopyJsStringSlow(
    ::Ast::JsString::Builder builder,
    v8::internal::DirectHandle<v8::internal::String> str,
    v8::internal::Isolate* isolate) {
  if (v8_flags.taint_tracking_enable_concolic_no_marshalling) {
    return;
  }

  StringCopier copier(isolate);
  {
    DisallowHeapAllocation no_gc;
    copier.run(*str, 0, str->length());
  }
  copier.Build(builder);
}

void MessageHolder::CopyJsObjectToStringSlow(
    ::Ast::JsString::Builder obj_builder,
    v8::internal::Handle<v8::internal::Object> obj,
    v8::internal::Isolate* isolate) {
  if (v8_flags.taint_tracking_enable_concolic_no_marshalling) {
    return;
  }

  if (IsHeapObject(*obj)) {
    CopyJsStringSlow(
        obj_builder,
        Object::ToString(isolate, obj)
            .ToHandleChecked(),
        isolate);
  } else {
    DCHECK(IsSmi(*obj));
    auto out_content = obj_builder.initSegments(1)[0];
    std::string as_str = std::to_string(Cast<Smi>(*obj).value());
    out_content.setContent(::capnp::Data::Reader(
        reinterpret_cast<const uint8_t*>(as_str.c_str()), as_str.size()));
    out_content.setIsOneByte(true);
  }
}

int MessageHolder::GetDepth() { return depth_; }

template <typename T>
typename T::Builder MessageHolder::InitRootAs() {
  return builder_.initRoot<T>();
}

template <typename T>
typename T::Builder MessageHolder::GetRootAs() {
  return builder_.getRoot<T>();
}

template ::TaintLogRecord::SymbolicValue::Builder
MessageHolder::InitRootAs<::TaintLogRecord::SymbolicValue>();
template ::TaintLogRecord::SymbolicValue::Builder
MessageHolder::GetRootAs<::TaintLogRecord::SymbolicValue>();

class LogTaintTask : public v8::Task {
 public:
  LogTaintTask(Isolate* isolate) : isolate_(isolate) {}

  void Run() override {
    TaintTracker::FromIsolate(isolate_)->Get()->DoFlushLog();
  }

 private:
  Isolate* isolate_;
};

class JsObjectSerializer : public ObjectOwnPropertiesVisitor {
 public:
  JsObjectSerializer(::Ast::JsReceiver::Builder builder, MessageHolder& holder)
      : builder_(builder), holder_(holder), isolate_(nullptr) {}

  virtual bool VisitKeyValue(Handle<String> key, Handle<Object> value) {
    keys_ = ArrayList::Add(isolate_, keys_, key);
    values_ = ArrayList::Add(isolate_, values_, value);
    return false;
  }

  void Run(Handle<JSReceiver> value, Isolate* isolate) {
    isolate_ = isolate;
    keys_ = Cast<ArrayList>(isolate->factory()->NewFixedArray(0));
    values_ = Cast<ArrayList>(isolate->factory()->NewFixedArray(0));
    builder_.setType(IsJSArray(*value) ? Ast::JsReceiver::Type::ARRAY
                                        : Ast::JsReceiver::Type::OBJECT);
    Visit(value, isolate);
    PostProcess();
  }

  void PostProcess() {
    static const int MAX_RECURSION_DEPTH = 0;

    int size = keys_->length();
    DCHECK_EQ(keys_->length(), values_->length());
    auto keyvals_list = builder_.initKeyValues(size);

    for (int i = 0; i < size; i++) {
      auto kv_builder = keyvals_list[i];
      Tagged<String> key = Cast<String>(keys_->get(i));
      DCHECK(IsString(key));
      Handle<String> key_handle(key, isolate_);
      holder_.WriteConcreteObject(kv_builder.initKey(),
                                  ObjectSnapshot(key_handle), isolate_);

      auto value_builder = kv_builder.initValue();
      Tagged<Object> value_tagged = values_->get(i);
      Handle<Object> value = handle(value_tagged, isolate_);
      if (holder_.GetDepth() > MAX_RECURSION_DEPTH && IsJSReceiver(*value)) {
        value_builder.getValue().setUnserializedObject();
      } else {
        if (!holder_.WriteConcreteObject(value_builder, value, isolate_)) {
          value_builder.getValue().setUnknown();
        }
      }
    }
  }

 private:
  ::Ast::JsReceiver::Builder builder_;
  MessageHolder& holder_;
  Isolate* isolate_;
  DirectHandle<ArrayList> keys_;    // Array of keys of type String
  DirectHandle<ArrayList> values_;  // Array of values of type Object
};

Status MessageHolder::WriteReceiverSlow(::Ast::JsObjectValue::Builder builder,
                                        TaggedRevisedObject value,
                                        Isolate* isolate) {
  // Removed unused variable INITIAL_OBJECT_PROPERTY_MAP_SIZE

  Handle<JSReceiver> as_receiver = value.GetTarget();
  auto which_value = builder.getValue();

  depth_ += 1;
  JsObjectSerializer serializer(which_value.initReceiver(), *this);
  serializer.Run(as_receiver, isolate);
  builder.setUniqueId(value.GetId());
  depth_ -= 1;

  return Status::OK;
}

Status MessageHolder::WriteConcreteObject(::Ast::JsObjectValue::Builder builder,
                                          ObjectSnapshot snapshot,
                                          Isolate* isolate) {
  if (v8_flags.taint_tracking_enable_concolic_no_marshalling) {
    return Status::OK;
  }

  auto obj = snapshot.GetObj();
  if (IsHeapObject(*obj)) {
    return ObjectVersioner::FromIsolate(isolate)
        .MaybeSerialize(snapshot, builder, *this);
  } else {
    return WriteConcreteSmi(builder, Cast<Smi>(*obj).value());
  }
}

Status MessageHolder::WriteConcreteReceiverSlow(
    ::Ast::JsObjectValue::Builder builder, TaggedRevisedObject snapshot,
    Isolate* isolate) {
  auto obj = snapshot.GetTarget();

  InstanceType type = obj->map()->instance_type();
  switch (type) {
    case JS_REG_EXP_TYPE: {
      builder.setUniqueId(snapshot.GetId());

      Handle<JSRegExp> as_regex = Cast<JSRegExp>(obj);
      auto out_reg = builder.getValue().initRegexp();
      {
        Tagged<String> source = as_regex->source(isolate);
        if (IsString(source)) {
          Handle<String> source_handle = handle(source, isolate);
          CopyJsStringSlow(out_reg.initSource(), source_handle, isolate);
        }
      }
      if (IsFixedArray(as_regex->data(isolate))) {
        std::vector<::Ast::RegExp::Flag> cp_flags;
        JSRegExp::Flags flags = as_regex->flags();
        if (flags & JSRegExp::Flag::kGlobal) {
          cp_flags.push_back(::Ast::RegExp::Flag::GLOBAL);
        }
        if (flags & JSRegExp::Flag::kIgnoreCase) {
          cp_flags.push_back(::Ast::RegExp::Flag::IGNORE_CASE);
        }
        if (flags & JSRegExp::Flag::kMultiline) {
          cp_flags.push_back(::Ast::RegExp::Flag::MULTILINE);
        }
        if (flags & JSRegExp::Flag::kSticky) {
          cp_flags.push_back(::Ast::RegExp::Flag::STICKY);
        }
        if (flags & JSRegExp::Flag::kUnicode) {
          cp_flags.push_back(::Ast::RegExp::Flag::UNICODE);
        }

        auto out_flags = out_reg.initFlags(static_cast<unsigned int>(cp_flags.size()));
        for (size_t i = 0; i < cp_flags.size(); i++) {
          out_flags.set(static_cast<unsigned int>(i), cp_flags[i]);
        }
      }

      return WriteReceiverSlow(out_reg.initReceiver(), snapshot, isolate);
    }

    case JS_FUNCTION_TYPE: {
      Handle<JSFunction> as_function = Cast<JSFunction>(obj);
      builder.setUniqueId(snapshot.GetId());
      auto fn = builder.getValue().initFunction();
      Handle<SharedFunctionInfo> shared =
          handle(as_function->shared(), isolate);
      DirectHandle<String> debug_name = SharedFunctionInfo::DebugName(isolate, shared);
      CopyJsStringSlow(fn.initName(), debug_name, isolate);
      fn.setStartPosition(shared->StartPosition());
      fn.setEndPosition(shared->EndPosition());
      Handle<Object> maybe_script(shared->script(), isolate);
      if (IsScript(*maybe_script)) {
        Handle<Script> script = Cast<Script>(maybe_script);
        if (!WriteConcreteObject(fn.initScriptName(),
                                 handle(script->name(), isolate), isolate)) {
          return Status::FAILURE;
        }
        fn.setScriptId(script->id());
      }

      // Note: SharedFunctionInfo::code() was removed in newer V8 versions
      // Using abstract_code() as a replacement, but this may need further adjustment
      // Tagged<AbstractCode> abstract_code = shared->abstract_code(isolate);

      // TODO: taint_node_label field needs to be added to SharedFunctionInfo in the new V8
      // Commenting out for now to allow compilation
      /*
      if (shared->has_taint_node_label() && !IsUndefined(shared->taint_node_label(), isolate)) {
        V8NodeLabelSerializer dser(isolate);
        NodeLabel label;
        DCHECK(dser.Deserialize(shared->taint_node_label(), &label));
        BuilderSerializer ser;
        DCHECK(ser.Serialize(fn.initFnLabel(), label));
      }
      */

      // TODO: The code below needs to be updated for the new V8 API
      // AbstractCode doesn't have the same interface as Code
      // Commenting out for now to allow compilation
      /*
      if (code->kind() == Code::Kind::BUILTIN) {
        int builtin_idx = code->builtin_index();
        DCHECK(builtin_idx < Builtins::Name::builtin_count &&
               builtin_idx >= 0 &&
               (Code::cast(isolate->builtins()->builtin(
                    static_cast<Builtins::Name>(builtin_idx))) == *code) &&
               code->kind() == Code::Kind::BUILTIN);
        auto builtin_builder = fn_type.initBuiltinFunction();
        builtin_builder.setId(code->builtin_index());
        builtin_builder.setName(isolate->builtins()->name(builtin_idx));
      } else
      */

      // TODO: get_api_func_data() needs to be verified in the new V8 API
      // Commenting out for now to allow compilation
      /*
      if (shared->IsApiFunction()) {
        auto api_builder = fn_type.initApiFunction();
        Handle<Object> serial_num =
            handle(shared->get_api_func_data()->serial_number(), isolate);
        DCHECK(serial_num->IsSmi());
        api_builder.setSerialNumber(Smi::cast(*serial_num)->value());
        // TODO: init via api?
      }
      */

      return WriteReceiverSlow(fn.initReceiver(), snapshot, isolate);
    }

    default:
      return WriteReceiverSlow(builder, snapshot, isolate);
  }
}

Status MessageHolder::WriteConcreteImmutableObjectSlow(
    ::Ast::JsObjectValue::Builder builder, TaggedObject snapshot,
    Isolate* isolate) {
  Handle<Object> value = snapshot.GetObj();
  DCHECK(IsHeapObject(*value) && !IsJSReceiver(*value));

  auto out_val = builder.getValue();
  Handle<HeapObject> as_heap_obj = Cast<HeapObject>(value);
  InstanceType type = as_heap_obj->map()->instance_type();
  builder.setUniqueId(snapshot.GetUniqueId());
  if (type < FIRST_NONSTRING_TYPE) {
    CopyJsStringSlow(out_val.initString(), Cast<String>(value), isolate);
  } else {
    switch (type) {
      case HEAP_NUMBER_TYPE:
        out_val.setNumber(Cast<HeapNumber>(value)->value());
        break;

      case ODDBALL_TYPE: {
        if (IsFalse(*value, isolate)) {
          out_val.setBoolean(false);
        } else if (IsTrue(*value, isolate)) {
          out_val.setBoolean(true);
        } else if (IsUndefined(*value, isolate)) {
          out_val.setUndefined();
        } else if (IsNull(*value, isolate)) {
          out_val.setNullObject();
        } else {
          out_val.setUnknown();
          return Status::FAILURE;
        }
      } break;

      case SYMBOL_TYPE: {
        Tagged<PrimitiveHeapObject> desc = Cast<Symbol>(value)->description();
        if (IsString(desc)) {
          Handle<String> to_str = handle(Cast<String>(desc), isolate);
          CopyJsStringSlow(out_val.initSymbol(), to_str, isolate);
        }
      } break;

      default:
        out_val.setUnknown();
        return Status::FAILURE;
    }
  }
  return Status::OK;
}

Status MessageHolder::WriteConcreteSmi(Ast::JsObjectValue::Builder builder,
                                       int value) {
  builder.getValue().setSmi(value);
  builder.setUniqueId(NO_UNIQUE_ID);
  return Status::OK;
}

// static
int64_t TaintTracker::Impl::LogToFile(Isolate* isolate, MessageHolder& builder,
                                      FlushConfig conf) {
  TaintTracker::Impl* impl = TaintTracker::FromIsolate(isolate)->Get();
  auto log_message = builder.GetRoot();
  if (global_log_listener) {
    global_log_listener->OnLog(log_message.asReader());
  }
  log_message.setIsolate(reinterpret_cast<uint64_t>(isolate));

  // TODO: Context::taint_tracking_context_id() needs to be added in the new V8
  // Commenting out for now to allow compilation
  /*
  Tagged<Context> context = isolate->context();
  if (!context.is_null()) {
    Tagged<NativeContext> native_context = context->native_context();
    if (!native_context.is_null()) {
      builder.WriteConcreteObject(
          log_message.initContextId(),
          ObjectSnapshot(
              handle(native_context->taint_tracking_context_id(), isolate)),
          isolate);
    }
  }
  */

  return impl->LogToFileImpl(isolate, builder, conf);
}

int64_t TaintTracker::Impl::LogToFileImpl(Isolate* isolate,
                                          MessageHolder& builder,
                                          FlushConfig conf) {
  if (!IsLogging()) {
    return NO_MESSAGE;
  }
  auto log_message = builder.GetRoot();
  uint64_t msg_id = message_counter_++;
  log_message.setMessageId(msg_id);

  if (buffered_log_) {
    std::lock_guard<std::mutex> guard(log_mutex_);
    builder.DoSynchronousWrite(*buffered_log_);
  }

  if (unsent_messages_ > kFlushMessageMax || conf == FORCE_FLUSH ||
      last_message_flushed_.HasExpired(kMaxTimeBetweenFlushes)) {
    ScheduleFlushLog(isolate);
    last_message_flushed_.Restart();
  } else {
    unsent_messages_ += 1;
  }

  return msg_id;
}

void TaintTracker::Impl::ScheduleFlushLog(v8::internal::Isolate* isolate) {
  std::lock_guard<std::mutex> guard(log_mutex_);
  if (!log_flush_scheduled_) {
    auto task_runner = V8::GetCurrentPlatform()->GetForegroundTaskRunner(
        reinterpret_cast<v8::Isolate*>(isolate));
    task_runner->PostTask(
        std::unique_ptr<v8::Task>(new LogTaintTask(isolate)));
    log_flush_scheduled_ = true;
  }
}

void TaintTracker::Impl::DoFlushLog() {
  std::lock_guard<std::mutex> guard(log_mutex_);
  DCHECK(IsLogging());
  if (buffered_log_) {
    buffered_log_->flush();
  }
  log_->flush();
  log_flush_scheduled_ = false;
}

bool AllowDeserializingCode() {
  DCHECK(v8_flags.taint_tracking_disable_code_caching ||
         !v8_flags.taint_tracking_enable_ast_modification);
  return !v8_flags.taint_tracking_disable_code_caching;
}

uint32_t LayoutVersionHash() { return (kTaintTrackingVersion); }

inline TaintFlag MaskForType(TaintType type) {
  return (static_cast<uint8_t>(type) & TAINT_TYPE_MASK) == static_cast<uint8_t>(TaintType::UNTAINTED)
             ? kTaintFlagUntainted
             : static_cast<TaintFlag>(1 << (static_cast<uint8_t>(type) - 1));
}

TaintFlag AddFlag(TaintFlag current, TaintType new_value, Tagged<String> object) {
  // CheckTaintError requires isolate parameter - skip for now
  // CheckTaintError(new_value, object, isolate);
  return current | MaskForType(new_value);
}

bool TestFlag(TaintFlag flag, TaintType type) {
  return (MaskForType(type) & flag) != 0;
}

TaintType TaintFlagToType(TaintFlag flag) {
  if (flag == kTaintFlagUntainted) {
    return TaintType::UNTAINTED;
  }
  if (v8::base::bits::IsPowerOfTwo(flag)) {
    // Find which bit is set
    int bit_pos = 0;
    uint32_t temp = flag;
    while (temp > 1) {
      temp >>= 1;
      bit_pos++;
    }
    return static_cast<TaintType>(bit_pos + 1);
  }
  // Multiple taints - return TAINTED as a fallback
  return TaintType::TAINTED;
}

std::string TaintTypeToString(TaintType type) {
  switch (type) {
    case TaintType::UNTAINTED:
      return "Untainted";
    case TaintType::TAINTED:
      return "Tainted";
    case TaintType::COOKIE:
      return "Cookie";
    case TaintType::MESSAGE:
      return "Message";
    case TaintType::URL:
      return "Url";
    case TaintType::URL_HASH:
      return "UrlHash";
    case TaintType::URL_PROTOCOL:
      return "UrlProtocol";
    case TaintType::URL_HOST:
      return "UrlHost";
    case TaintType::URL_HOSTNAME:
      return "UrlHostname";
    case TaintType::URL_ORIGIN:
      return "UrlOrigin";
    case TaintType::URL_PORT:
      return "UrlPort";
    case TaintType::URL_PATHNAME:
      return "UrlPathname";
    case TaintType::URL_SEARCH:
      return "UrlSearch";
    case TaintType::DOM:
      return "Dom";
    case TaintType::REFERRER:
      return "Referrer";
    case TaintType::WINDOWNAME:
      return "WindowName";
    case TaintType::STORAGE:
      return "Storage";
    case TaintType::NETWORK:
      return "Network";
    case TaintType::MULTIPLE_TAINTS:
      return "MultipleTaints";
    case TaintType::MESSAGE_ORIGIN:
      return "MessageOrigin";
    case TaintType::URL_ENCODED:
      return "UrlEncoded";
    case TaintType::URL_COMPONENT_ENCODED:
      return "UrlComponentEncoded";
    case TaintType::ESCAPE_ENCODED:
      return "EscapeEncoded";
    case TaintType::MULTIPLE_ENCODINGS:
      return "MultipleEncodings";
    case TaintType::URL_DECODED:
      return "UrlDecoded";
    case TaintType::URL_COMPONENT_DECODED:
      return "UrlComponentDecoded";
    case TaintType::ESCAPE_DECODED:
      return "EscapeDecoded";
    default:
      return "UnknownTaintError:" + std::to_string(static_cast<uint8_t>(type));
  }
}

::TaintLogRecord::TaintEncoding TaintTypeToRecordEncoding(TaintType type) {
  // The encoding system has been removed from TaintType enum
  // Return NONE as default
  return TaintLogRecord::TaintEncoding::NONE;
}

::TaintLogRecord::TaintType TaintTypeToRecordEnum(TaintType type) {
  uint8_t type_val = static_cast<uint8_t>(type) & TAINT_TYPE_MASK;
  switch (static_cast<TaintType>(type_val)) {
    case TaintType::UNTAINTED:
      return TaintLogRecord::TaintType::UNTAINTED;
    case TaintType::TAINTED:
      return TaintLogRecord::TaintType::TAINTED;
    case TaintType::COOKIE:
      return TaintLogRecord::TaintType::COOKIE;
    case TaintType::MESSAGE:
      return TaintLogRecord::TaintType::MESSAGE;
    case TaintType::URL:
      return TaintLogRecord::TaintType::URL;
    case TaintType::URL_HASH:
      return TaintLogRecord::TaintType::URL_HASH;
    case TaintType::URL_PROTOCOL:
      return TaintLogRecord::TaintType::URL_PROTOCOL;
    case TaintType::URL_HOST:
      return TaintLogRecord::TaintType::URL_HOST;
    case TaintType::URL_HOSTNAME:
      return TaintLogRecord::TaintType::URL_HOSTNAME;
    case TaintType::URL_ORIGIN:
      return TaintLogRecord::TaintType::URL_ORIGIN;
    case TaintType::URL_PORT:
      return TaintLogRecord::TaintType::URL_PORT;
    case TaintType::URL_PATHNAME:
      return TaintLogRecord::TaintType::URL_PATHNAME;
    case TaintType::URL_SEARCH:
      return TaintLogRecord::TaintType::URL_SEARCH;
    case TaintType::DOM:
      return TaintLogRecord::TaintType::DOM;
    case TaintType::REFERRER:
      return TaintLogRecord::TaintType::REFERRER;
    case TaintType::WINDOWNAME:
      return TaintLogRecord::TaintType::WINDOWNAME;
    case TaintType::STORAGE:
      return TaintLogRecord::TaintType::STORAGE;
    case TaintType::NETWORK:
      return TaintLogRecord::TaintType::NETWORK;
    case TaintType::MULTIPLE_TAINTS:
      return TaintLogRecord::TaintType::MULTIPLE_TAINTS;
    case TaintType::MESSAGE_ORIGIN:
      return TaintLogRecord::TaintType::MESSAGE_ORIGIN;
    default:
      return TaintLogRecord::TaintType::TAINTED;
  }
}

TaintLogRecord::SymbolicOperation SymbolicTypeToEnum(SymbolicType type) {
  switch (type) {
    case CONCAT:
      return TaintLogRecord::SymbolicOperation::CONCAT;
    case SLICE:
      return TaintLogRecord::SymbolicOperation::SLICE;
    case LITERAL:
      return TaintLogRecord::SymbolicOperation::LITERAL;
    case EXTERNAL:
      return TaintLogRecord::SymbolicOperation::EXTERNAL;
    case PARSED_JSON:
      return TaintLogRecord::SymbolicOperation::PARSED_JSON;
    case STRINGIFIED_JSON:
      return TaintLogRecord::SymbolicOperation::STRINGIFIED_JSON;
    case REGEXP:
      return TaintLogRecord::SymbolicOperation::REGEXP;
    case JOIN:
      return TaintLogRecord::SymbolicOperation::JOIN;
    case CASE_CHANGE:
      return TaintLogRecord::SymbolicOperation::CASE_CHANGE;
    case URI_ENCODE:
      return TaintLogRecord::SymbolicOperation::URI_ENCODE;
    case URI_DECODE:
      return TaintLogRecord::SymbolicOperation::URI_DECODE;
    case URI_ESCAPE:
      return TaintLogRecord::SymbolicOperation::URI_ESCAPE;
    case URI_UNESCAPE:
      return TaintLogRecord::SymbolicOperation::URI_UNESCAPE;
    case INCREMENTAL_BUILD:
      return TaintLogRecord::SymbolicOperation::INCREMENTAL_BUILD;
    case URI_COMPONENT_DECODE:
      return TaintLogRecord::SymbolicOperation::URI_COMPONENT_DECODE;
    case URI_COMPONENT_ENCODE:
      return TaintLogRecord::SymbolicOperation::URI_COMPONENT_ENCODE;
  }
}

std::string TaintFlagToString(TaintFlag flag) {
  std::ostringstream output;
  bool started = false;
  int found = 0;
  for (int i = static_cast<int>(TaintType::TAINTED);
       i <= static_cast<int>(MAX_TAINT_TYPE); i++) {
    TaintType type = static_cast<TaintType>(i);
    if (TestFlag(flag, type)) {
      if (started) {
        output << "&";
      } else {
        started = true;
      }
      output << TaintTypeToString(type);
      found += 1;
    }
  }
  if (found == 0) {
    return TaintTypeToString(TaintType::UNTAINTED);
  }
  return output.str();
}

template <class T>
TaintData* StringTaintData(Tagged<T> str);
template <>
TaintData* StringTaintData<SeqOneByteString>(Tagged<SeqOneByteString> str) {
  return GetSeqStringTaintData(Cast<SeqString>(str));
}
template <>
TaintData* StringTaintData<SeqTwoByteString>(Tagged<SeqTwoByteString> str) {
  return GetSeqStringTaintData(Cast<SeqString>(str));
}
template <>
TaintData* StringTaintData<ExternalOneByteString>(Tagged<ExternalOneByteString> str) {
  // External strings store taint data in their resource object
  return str->resource()->GetTaintInfo();
}
template <>
TaintData* StringTaintData<ExternalTwoByteString>(Tagged<ExternalTwoByteString> str) {
  // External strings store taint data in their resource object
  return str->resource()->GetTaintInfo();
}

template <class T>
TaintData* StringTaintData_TryAllocate(Tagged<T> str) {
  TaintData* answer = StringTaintData(str);
  if (answer == nullptr) {
    int len = str->length();
    // const_cast needed because resource() returns const but InitTaintChars is not const
    auto* resource = const_cast<typename T::Resource*>(str->resource());
    answer = resource->InitTaintChars(len);
    memset(answer, static_cast<int>(TaintType::UNTAINTED), len);
  }
  return answer;
}

template <>
TaintData* GetWriteableStringTaintData<SeqOneByteString>(
    Tagged<SeqOneByteString> str) {
  return StringTaintData(str);
}
template <>
TaintData* GetWriteableStringTaintData<SeqTwoByteString>(
    Tagged<SeqTwoByteString> str) {
  return StringTaintData(str);
}
template <>
TaintData* GetWriteableStringTaintData<ExternalOneByteString>(
    Tagged<ExternalOneByteString> str) {
  return StringTaintData_TryAllocate(str);
}
template <>
TaintData* GetWriteableStringTaintData<ExternalTwoByteString>(
    Tagged<ExternalTwoByteString> str) {
  return StringTaintData_TryAllocate(str);
}
template <>
TaintData* GetWriteableStringTaintData<SeqString>(Tagged<SeqString> str) {
  if (IsSeqOneByteString(str)) {
    return GetWriteableStringTaintData(Cast<SeqOneByteString>(str));
  } else {
    return GetWriteableStringTaintData(Cast<SeqTwoByteString>(str));
  }
}

void MarkNewString(String* str) {
  // TODO: set_taint_info method may not exist in new V8 version
  // str->set_taint_info(0);
}

template <class T>
void InitTaintSeqByteString(Tagged<T> str, TaintType type) {
  TaintData* data = StringTaintData(str);
  memset(data, static_cast<int>(type), str->length());
  // TODO: MarkNewString may need to be updated
  // MarkNewString(str);
}

template <>
void InitTaintData<SeqOneByteString>(Tagged<SeqOneByteString> str, TaintType type) {
  InitTaintSeqByteString(str, type);
}
template <>
void InitTaintData<SeqTwoByteString>(Tagged<SeqTwoByteString> str, TaintType type) {
  InitTaintSeqByteString(str, type);
}
template <>
void InitTaintData<SeqString>(Tagged<SeqString> str, TaintType type) {
  if (IsSeqOneByteString(str)) {
    InitTaintData(Cast<SeqOneByteString>(str), type);
  } else {
    InitTaintData(Cast<SeqTwoByteString>(str), type);
  }
}

template <>
void TaintVisitor::VisitIntoStringTemplate<ConsString>(Tagged<ConsString> source,
                                                       int from_offset,
                                                       int from_len) {
  Tagged<String> first = source->first();
  int first_len = first->length();
  if (from_offset < first_len) {
    if (from_len + from_offset <= first_len) {
      visitee_stack_.push_back(std::make_tuple(first, from_offset, from_len));
    } else {
      int copy_first = first_len - from_offset;
      // Make sure that the second element is pushed first so that the
      // first element will be the first to execute.
      visitee_stack_.push_back(
          std::make_tuple(source->second(), 0, from_len - copy_first));
      visitee_stack_.push_back(std::make_tuple(first, from_offset, copy_first));
    }
  } else {
    visitee_stack_.push_back(
        std::make_tuple(source->second(), from_offset - first_len, from_len));
  }
}

template <>
void TaintVisitor::VisitIntoStringTemplate<SlicedString>(Tagged<SlicedString> source,
                                                         int from_offset,
                                                         int from_len) {
  visitee_stack_.push_back(std::make_tuple(
      source->parent(), from_offset + source->offset(), from_len));
}

template <>
void TaintVisitor::VisitIntoStringTemplate<SeqOneByteString>(
    Tagged<SeqOneByteString> source, int from, int len) {
  DCHECK_GE(from, 0);
  DCHECK_GE(len, 0);
  DCHECK_LE(from + len, source->length());
  // TODO: GetChars() may need to be updated for new V8 API
  // DoVisit(source->GetChars(), StringTaintData(source), from, len);
}

template <>
void TaintVisitor::VisitIntoStringTemplate<SeqTwoByteString>(
    Tagged<SeqTwoByteString> source, int from, int len) {
  DCHECK_GE(from, 0);
  DCHECK_GE(len, 0);
  DCHECK_LE(from + len, source->length());
  // TODO: GetChars() may need to be updated for new V8 API
  // DoVisit(source->GetChars(), StringTaintData(source), from, len);
}

template <>
void TaintVisitor::VisitIntoStringTemplate<ExternalOneByteString>(
    Tagged<ExternalOneByteString> source, int from, int len) {
  DCHECK_GE(from, 0);
  DCHECK_GE(len, 0);
  DCHECK_LE(from + len, source->length());
  // TaintData* data;
  // if (writeable_) {
  //   data = StringTaintData_TryAllocate(source);
  // } else {
  //   data = StringTaintData(source);
  // }
  // TODO: GetChars() may need to be updated for new V8 API
  // DoVisit(source->GetChars(), data, from, len);
}

template <>
void TaintVisitor::VisitIntoStringTemplate<ExternalTwoByteString>(
    Tagged<ExternalTwoByteString> source, int from, int len) {
  DCHECK_GE(from, 0);
  DCHECK_GE(len, 0);
  DCHECK_LE(from + len, source->length());
  // TaintData* data;
  // if (writeable_) {
  //   data = StringTaintData_TryAllocate(source);
  // } else {
  //   data = StringTaintData(source);
  // }
  // TODO: GetChars() may need to be updated for new V8 API
  // DoVisit(source->GetChars(), data, from, len);
}

template <>
void TaintVisitor::VisitIntoStringTemplate<ExternalString>(
    Tagged<ExternalString> source, int from, int len) {
  if (IsExternalOneByteString(source)) {
    return VisitIntoStringTemplate(Cast<ExternalOneByteString>(source), from,
                                   len);
  } else {
    DCHECK(IsExternalTwoByteString(source));
    return VisitIntoStringTemplate(Cast<ExternalTwoByteString>(source), from,
                                   len);
  }
}

template <>
void TaintVisitor::VisitIntoStringTemplate<SeqString>(Tagged<SeqString> source,
                                                      int from, int len) {
  if (IsSeqOneByteString(source)) {
    return VisitIntoStringTemplate(Cast<SeqOneByteString>(source), from, len);
  } else {
    DCHECK(IsSeqTwoByteString(source));
    return VisitIntoStringTemplate(Cast<SeqTwoByteString>(source), from, len);
  }
}

template <>
void TaintVisitor::VisitIntoStringTemplate<String>(Tagged<String> source,
                                                   int from_offset,
                                                   int from_len) {
  StringShape shape(source);
  if (shape.IsCons()) {
    VisitIntoStringTemplate(Cast<ConsString>(source), from_offset, from_len);
  } else if (shape.IsSliced()) {
    VisitIntoStringTemplate(Cast<SlicedString>(source), from_offset, from_len);
  } else if (shape.IsExternalOneByte()) {
    VisitIntoStringTemplate(Cast<ExternalOneByteString>(source), from_offset,
                            from_len);
  } else if (shape.IsExternalTwoByte()) {
    VisitIntoStringTemplate(Cast<ExternalTwoByteString>(source), from_offset,
                            from_len);
  } else if (shape.IsSequentialOneByte()) {
    VisitIntoStringTemplate(Cast<SeqOneByteString>(source), from_offset,
                            from_len);
  } else if (shape.IsSequentialTwoByte()) {
    VisitIntoStringTemplate(Cast<SeqTwoByteString>(source), from_offset,
                            from_len);
  } else {
    FATAL("Taint Tracking Unreachable");
  }
}

class Sha256Visitor : public TaintVisitor {
 public:
  Sha256Visitor() : TaintVisitor() {}

  void Visit(const uint8_t* visitee, TaintData* taint_info, int offset,
             int size) override {
    const uint8_t* start = visitee + offset;
    hasher_.process(start, start + size);
  }

  void Visit(const uint16_t* visitee, TaintData* taint_info, int offset,
             int size) override {
    const uint16_t* start = visitee + offset;
    hasher_.process(reinterpret_cast<const uint8_t*>(start),
                    reinterpret_cast<const uint8_t*>(start + size));
  }

  std::string GetResult() {
    hasher_.finish();
    return picosha2::get_hash_hex_string(hasher_);
  }

 private:
  picosha2::hash256_one_by_one hasher_;
};

std::string Sha256StringAsHex(Handle<String> value) {
  Sha256Visitor visitor;
  {
    DisallowHeapAllocation no_gc;
    visitor.run(*value, 0, value->length());
  }
  return visitor.GetResult();
}

class CopyVisitor : public TaintVisitor {
 public:
  CopyVisitor(TaintData* dest) : TaintVisitor(), already_copied_(0), dest_(dest) {}

  void Visit(const uint8_t* visitee, TaintData* taint_info, int offset,
             int size) override {
    VisitInline(taint_info, offset, size);
  }
  void Visit(const uint16_t* visitee, TaintData* taint_info, int offset,
             int size) override {
    VisitInline(taint_info, offset, size);
  }

 private:
  inline void VisitInline(TaintData* taint_info, int offset, int size) {
    if (taint_info) {
      MemCopy(dest_ + already_copied_, taint_info + offset, size);
    } else {
      memset(dest_ + already_copied_,
             static_cast<TaintData>(TaintType::UNTAINTED), size);
    }
    already_copied_ += size;
  }

  int already_copied_;
  TaintData* dest_;
};

class IsTaintedVisitor : public TaintVisitor {
 public:
  IsTaintedVisitor()
      : flag_(static_cast<TaintFlag>(TaintType::UNTAINTED)),
        prev_type_(TaintType::UNTAINTED),
        already_written_(0) {}

  void Visit(const uint8_t* visitee, TaintData* taint_info, int offset,
             int size) override {
    VisitInline(taint_info, offset, size);
  }
  void Visit(const uint16_t* visitee, TaintData* taint_info, int offset,
             int size) override {
    VisitInline(taint_info, offset, size);
  }

  int Size() const { return already_written_; }

  TaintFlag GetFlag() const { return flag_; }

  std::vector<std::tuple<TaintType, int>> GetRanges() { return taint_ranges_; }

 private:
  inline void VisitInline(TaintData* taint_info, int offset, int size) {
    if (taint_info == nullptr) {
      already_written_ += size;
      if (size != 0) {
        prev_type_ = TaintType::UNTAINTED;
      }
      return;
    }

    TaintData* start = taint_info + offset;
    for (TaintData* t = start; t < start + size; t++) {
      TaintType type = static_cast<TaintType>(*t);
      if (type != prev_type_) {
        taint_ranges_.push_back(std::make_tuple(type, already_written_));
      }
      prev_type_ = type;
      flag_ = AddFlag(flag_, type, GetVisitee());
      already_written_++;
    }
  }

  TaintFlag flag_;
  TaintType prev_type_;
  std::vector<std::tuple<TaintType, int>> taint_ranges_;
  int already_written_;
};

template <class T>
TaintFlag CheckTaint(T* object) {
  IsTaintedVisitor visitor;
  Tagged<T> tagged_object(object);
  visitor.run(tagged_object, 0, tagged_object->length());
  return visitor.GetFlag();
}

template TaintFlag CheckTaint<String>(String* object);

class WritingVisitor : public TaintVisitor {
 public:
  WritingVisitor(const TaintData* in_data)
      : TaintVisitor(true, nullptr), in_data_(in_data), already_written_(0) {}

  void Visit(const uint16_t* visitee, TaintData* taint_data, int offset,
             int size) override {
    VisitInline(taint_data, offset, size);
  }
  void Visit(const uint8_t* visitee, TaintData* taint_data, int offset,
             int size) override {
    VisitInline(taint_data, offset, size);
  }

 private:
  inline void VisitInline(TaintData* taint_data, int offset, int size) {
    MemCopy(taint_data + offset, in_data_ + already_written_, size);
    already_written_ += size;
  }

  const TaintData* in_data_;
  int already_written_;
};

void InitTaintInfo(const std::vector<std::tuple<TaintType, int>>& range_data,
                   TaintLogRecord::TaintInformation::Builder* builder) {
  auto ranges = builder->initRanges(static_cast<unsigned int>(range_data.size()));
  for (size_t i = 0; i < range_data.size(); i++) {
    ranges[static_cast<unsigned int>(i)].setStart(std::get<1>(range_data[i]));
    ranges[static_cast<unsigned int>(i)].setEnd(-1);  // TODO: unused

    TaintType t_type = std::get<0>(range_data[i]);
    ranges[static_cast<unsigned int>(i)].setType(TaintTypeToRecordEnum(t_type));
    ranges[static_cast<unsigned int>(i)].setEncoding(TaintTypeToRecordEncoding(t_type));
  }
}

class SingleWritingVisitor : public TaintVisitor {
 public:
  SingleWritingVisitor(TaintType type) : TaintVisitor(true, nullptr), type_(type) {}

  void Visit(const uint8_t* visitee, TaintData* taint_data, int offset,
             int size) override {
    VisitInline(taint_data, offset, size);
  }
  void Visit(const uint16_t* visitee, TaintData* taint_data, int offset,
             int size) override {
    VisitInline(taint_data, offset, size);
  }

 private:
  inline void VisitInline(TaintData* taint_data, int offset, int size) {
    memset(taint_data + offset, static_cast<int>(type_), size);
  }

  TaintType type_;
};

template <class T>
TaintType GetTaintStatus(T* object, size_t idx) {
  TaintData output;
  CopyVisitor visitor(&output);
  Tagged<T> tagged_object(object);
  visitor.run(tagged_object, static_cast<int>(idx), 1);
  return static_cast<TaintType>(output);
}

template <class T>
TaintType GetTaintStatusRange(T* source, size_t idx_start, size_t length) {
  IsTaintedVisitor visitor;
  Tagged<T> tagged_source(source);
  visitor.run(tagged_source, static_cast<int>(idx_start), static_cast<int>(length));
  TaintType answer = TaintFlagToType(visitor.GetFlag());
  // TODO: CheckTaintError requires isolate parameter, but not available here
  // CheckTaintError(answer, tagged_source, isolate);
  return answer;
}

template <class T>
void SetTaintStatus(T* object, size_t idx, TaintType type) {
  SingleWritingVisitor visitor(type);
  Tagged<T> tagged_object(object);
  visitor.run(tagged_object, static_cast<int>(idx), 1);
}

template <class T>
void FlattenTaintData(T* source, TaintData* dest, int from_offset,
                      int from_len) {
  CopyVisitor visitor(dest);
  Tagged<T> tagged_source(source);
  visitor.run(tagged_source, from_offset, from_len);
}

// Overload for Tagged<T>
template <class T>
void FlattenTaintData(Tagged<T> source, TaintData* dest, int from_offset,
                      int from_len) {
  CopyVisitor visitor(dest);
  visitor.run(source, from_offset, from_len);
}

template <class T, class S>
void FlattenTaint(S* source, T* dest, int from_offset, int from_len) {
  DCHECK_GE(from_offset, 0);
  DCHECK_GE(source->length(), from_offset + from_len);
  DCHECK_GE(dest->length(), from_len);
  FlattenTaintData(source, GetWriteableStringTaintData(dest), from_offset,
                   from_len);
}

template <class T, class One, class Two>
void ConcatTaint(T* result, One* first, Two* second) {
  CopyVisitor visitor(GetWriteableStringTaintData(result));
  Tagged<One> tagged_first(first);
  Tagged<Two> tagged_second(second);
  visitor.run(tagged_first, 0, first->length());
  visitor.run(tagged_second, 0, second->length());
}

template <class T>
void CopyOut(T* source, TaintData* dest, int offset, int len) {
  CopyVisitor visitor(dest);
  Tagged<T> tagged_source(source);
  visitor.run(tagged_source, offset, len);
}

// Overload for Tagged<T>
template <class T>
void CopyOut(Tagged<T> source, TaintData* dest, int offset, int len) {
  CopyVisitor visitor(dest);
  visitor.run(source, offset, len);
}

template <class T>
void CopyIn(T* dest, TaintType source, int offset, int len) {
  DCHECK_GE(dest->length(), len);
  SingleWritingVisitor visitor(source);
  Tagged<T> tagged_dest(dest);
  visitor.run(tagged_dest, offset, len);
}

// Overload for Tagged<T>
template <class T>
void CopyIn(Tagged<T> dest, TaintType source, int offset, int len) {
  DCHECK_GE(dest->length(), len);
  SingleWritingVisitor visitor(source);
  visitor.run(dest, offset, len);
}

template <class T>
void CopyIn(T* dest, const TaintData* source, int offset, int len) {
  WritingVisitor visitor(source);
  Tagged<T> tagged_dest(dest);
  visitor.run(tagged_dest, offset, len);
}

// Overload for Tagged<T>
template <class T>
void CopyIn(Tagged<T> dest, const TaintData* source, int offset, int len) {
  WritingVisitor visitor(source);
  visitor.run(dest, offset, len);
}

void LogSetTaintString(Handle<String> str, TaintType type) {
  if (v8_flags.taint_tracking_enable_symbolic) {
    MessageHolder message;
    auto log_message = message.InitRoot();
    auto set_taint = log_message.getMessage().initSetTaint();
    // set_taint.setTargetId(str->taint_info());  // TODO: taint_info() method doesn't exist in new V8
    set_taint.setTaintType(TaintTypeToRecordEnum(type));
    Isolate* isolate = nullptr;
    if (GetIsolateFromHeapObject(*str, &isolate)) {
      TaintTracker::Impl::LogToFile(isolate, message);
    }
  }
}

void SetTaintString(Handle<String> str, TaintType type) {
  {
    DisallowHeapAllocation no_gc;
    Isolate* isolate = nullptr;
    if (GetIsolateFromHeapObject(*str, &isolate)) {
      CheckTaintError(type, *str, isolate);
    }
    CopyIn(*str, type, 0, str->length());
  }
  LogSetTaintString(str, type);
}

void JSSetTaintBuffer(v8::internal::Handle<v8::internal::String> str,
                      v8::internal::Handle<v8::internal::JSArrayBuffer> data) {
  {
    DisallowHeapAllocation no_gc;
    CopyIn(*str, reinterpret_cast<TaintData*>(data->backing_store()), 0,
           str->length());
  }
  LogSetTaintString(str, TaintType::TAINTED);  // TODO: MULTIPLE_TAINTS doesn't exist, using TAINTED
}

std::vector<std::tuple<TaintType, int>> InitTaintRanges(Handle<String> target) {
  IsTaintedVisitor visitor;
  {
    DisallowHeapAllocation no_gc;
    visitor.run(*target, 0, target->length());
  }
  return visitor.GetRanges();
}

::TaintLogRecord::SinkType FromSinkType(TaintSinkLabel label) {
  switch (label) {
    case TaintSinkLabel::URL_SINK:
      return ::TaintLogRecord::SinkType::URL;
    // TODO: These sink types don't exist in new V8 TaintSinkLabel enum
    // case TaintSinkLabel::EMBED_SRC_SINK:
    //   return TaintLogRecord::SinkType::EMBED_SRC_SINK;
    // case TaintSinkLabel::IFRAME_SRC_SINK:
    //   return TaintLogRecord::SinkType::IFRAME_SRC_SINK;
    // case TaintSinkLabel::ANCHOR_SRC_SINK:
    //   return TaintLogRecord::SinkType::ANCHOR_SRC_SINK;
    // case TaintSinkLabel::IMG_SRC_SINK:
    //   return TaintLogRecord::SinkType::IMG_SRC_SINK;
    // case TaintSinkLabel::SCRIPT_SRC_URL_SINK:
    //   return TaintLogRecord::SinkType::SCRIPT_SRC_URL_SINK;
    // case TaintSinkLabel::JAVASCRIPT_EVENT_HANDLER_ATTRIBUTE:
    //   return TaintLogRecord::SinkType::JAVASCRIPT_EVENT_HANDLER_ATTRIBUTE;
    case TaintSinkLabel::JAVASCRIPT:
      return ::TaintLogRecord::SinkType::JAVASCRIPT;
    case TaintSinkLabel::HTML:
      return ::TaintLogRecord::SinkType::HTML;
    // TODO: These sink types don't exist in new V8 TaintSinkLabel enum
    // case TaintSinkLabel::MESSAGE_DATA:
    //   return ::TaintLogRecord::SinkType::MESSAGE_DATA;
    // case TaintSinkLabel::COOKIE_SINK:
    //   return ::TaintLogRecord::SinkType::COOKIE;
    // case TaintSinkLabel::STORAGE_SINK:
    //   return ::TaintLogRecord::SinkType::STORAGE;
    // case TaintSinkLabel::ORIGIN:
    //   return ::TaintLogRecord::SinkType::ORIGIN;
    // case TaintSinkLabel::DOM_URL:
    //   return ::TaintLogRecord::SinkType::DOM_URL;
    // case TaintSinkLabel::ELEMENT:
    //   return ::TaintLogRecord::SinkType::ELEMENT;
    // case TaintSinkLabel::JAVASCRIPT_URL:
    //   return ::TaintLogRecord::SinkType::JAVASCRIPT_URL;
    // case TaintSinkLabel::CSS:
    //   return ::TaintLogRecord::SinkType::CSS;
    // case TaintSinkLabel::CSS_STYLE_ATTRIBUTE:
    //   return ::TaintLogRecord::SinkType::CSS_STYLE_ATTRIBUTE;
    // case TaintSinkLabel::JAVASCRIPT_SET_TIMEOUT:
    //   return ::TaintLogRecord::SinkType::JAVASCRIPT_SET_TIMEOUT;
    // case TaintSinkLabel::JAVASCRIPT_SET_INTERVAL:
    //   return ::TaintLogRecord::SinkType::JAVASCRIPT_SET_INTERVAL;
    case TaintSinkLabel::LOCATION_ASSIGN:
      return ::TaintLogRecord::SinkType::LOCATION_ASSIGNMENT;
    default:
      UNREACHABLE();
  }
}

class HeartBeatTask : public v8::Task {
 public:
  HeartBeatTask(v8::internal::Isolate* isolate) : isolate_(isolate) {}

  void Run() override;

  static void StartTimer(v8::internal::Isolate* isolate) {
    // TODO: CallDelayedOnForegroundThread API changed in new V8
    // static const double _MILLIS_PER_SECOND = 1000;
    // V8::GetCurrentPlatform()->CallDelayedOnForegroundThread(
    //     reinterpret_cast<v8::Isolate*>(isolate), new HeartBeatTask(isolate),
    //     static_cast<double>(v8_flags.taint_tracking_heart_beat_millis) /
    //         _MILLIS_PER_SECOND);
  }

 private:
  v8::internal::Isolate* isolate_;
};

void LogInitializeNavigate(Handle<String> url, Isolate* isolate) {
  MessageHolder message;
  auto root = message.InitRoot();
  auto navigate = root.getMessage().initNavigate();
  message.CopyJsStringSlow(navigate.initUrl(), url, isolate);
  TaintTracker::Impl::LogToFile(isolate, message, FlushConfig::FORCE_FLUSH);

  if (!TaintTracker::FromIsolate(isolate)->Get()->HasHeartbeat()) {
    HeartBeatTask::StartTimer(isolate);
  }
}

void LogDispose(Isolate* isolate) {
  TaintTracker::Impl* impl = TaintTracker::FromIsolate(isolate)->Get();
  if (impl->IsLogging()) {
    impl->DoFlushLog();
  }
}

class JsStringInitializer {
 public:
  virtual void SetJsString(::Ast::JsString::Builder builder,
                           MessageHolder& holder) const = 0;

  virtual void InitMessageOriginCheck(
      TaintLogRecord::JsSinkTainted::Builder builder,
      MessageHolder& holder) const = 0;
};

template <typename Char>
class JsStringFromBuffer : public JsStringInitializer {
 public:
  JsStringFromBuffer(const Char* chardata, int length)
      : chardata_(chardata), length_(length) {}

  void SetJsString(::Ast::JsString::Builder builder,
                   MessageHolder& holder) const override {
    holder.CopyBuffer(builder, chardata_, length_);
  }

  void InitMessageOriginCheck(TaintLogRecord::JsSinkTainted::Builder builder,
                              MessageHolder& holder) const override {}

 private:
  const Char* chardata_;
  int length_;
};

class JsStringFromString : public JsStringInitializer {
 public:
  JsStringFromString(DirectHandle<String> str, Isolate* isolate)
      : str_(str), isolate_(isolate) {}

  void SetJsString(::Ast::JsString::Builder builder,
                   MessageHolder& holder) const override {
    holder.CopyJsStringSlow(builder, str_, isolate_);
  }

  void InitMessageOriginCheck(TaintLogRecord::JsSinkTainted::Builder builder,
                              MessageHolder& holder) const override {
    MaybeHandle<FixedArray> maybe_res =
        TaintTracker::FromIsolate(isolate_)
            ->Get()
            ->GetCrossOriginMessageTable(str_);

    Handle<FixedArray> res;
    if (maybe_res.ToHandle(&res)) {
      DCHECK_EQ(res->length().value(), 2);
      auto origin_check = builder.initMessageOriginCheck();
      Tagged<Object> origin_obj = res->get(0);
      Tagged<Object> compare_obj = res->get(1);
      DCHECK(IsString(origin_obj));
      DCHECK(IsString(compare_obj));
      Handle<String> origin_str = handle(Cast<String>(origin_obj), isolate_);
      Handle<String> compare_str = handle(Cast<String>(compare_obj), isolate_);
      holder.CopyJsStringSlow(origin_check.initOriginString(),
                              origin_str, isolate_);
      holder.CopyJsStringSlow(origin_check.initComparedString(),
                              compare_str, isolate_);
    }
  }

 private:
  DirectHandle<String> str_;
  Isolate* isolate_;
};

int64_t LogIfTainted(IsTaintedVisitor& visitor,
                     const JsStringInitializer& initer,
                     v8::internal::Isolate* isolate,
                     v8::String::TaintSinkLabel label,
                     std::shared_ptr<SymbolicState> symbolic_data) {
  // Temporarily disable taint logging to debug hang issue
  // return NO_MESSAGE;

  if ((visitor.GetFlag() & static_cast<TaintFlag>(TaintType::UNTAINTED)) &&
      !v8_flags.taint_tracking_sources_sinks_to_logs) {
    return NO_MESSAGE;
  }

  MessageHolder message;
  auto log_message = message.InitRoot();

  auto sink_message = log_message.getMessage().initJsSinkTainted();

  auto trace = sink_message.initStackTrace();

  std::vector<std::unique_ptr<char[]>> traceMessages;
  {
    DisallowHeapAllocation no_gc;
    HandleScope scope(isolate);
    StackFrameIterator counter(isolate);
    int count = 0;
    while (!counter.done()) {
      counter.Advance();
      count += 1;
    }
    traceMessages.reserve(count);
    auto frames = trace.initFrames(count);

    StackFrameIterator it(isolate);
    for (int i = 0; !it.done(); it.Advance(), ++i) {
      HeapStringAllocator alloc;
      StringStream stream(&alloc,
                          StringStream::ObjectPrintMode::kPrintObjectConcise);
      StackFrame* frame = it.frame();
      frame->Print(&stream, StackFrame::OVERVIEW, i);
      stream.Add("================details==============\n");
      frame->Print(&stream, StackFrame::DETAILS, i);
      stream.PrintMentionedObjectCache(isolate);

      std::unique_ptr<char[]> human_string = stream.ToCString();
      auto frame_location = frame->InfoForTaintLog();
      Handle<Script> script;
      Handle<SharedFunctionInfo> info;
      if (frame_location.script.ToHandle(&script) &&
          frame_location.shared_info.ToHandle(&info)) {
        auto frame_info_builder = frames[i].initFrameInfo();
        // TODO: IsScript and IsSharedFunctionInfo checks removed in new V8
        // DCHECK(script->IsScript());
        // DCHECK(info->IsSharedFunctionInfo());
        message.CopyJsObjectToStringSlow(
            frame_info_builder.initSourceUrl(),
            Handle<Object>(script->source_url(), isolate), isolate);
        message.CopyJsObjectToStringSlow(
            frame_info_builder.initScriptName(),
            Handle<Object>(script->name(), isolate), isolate);
        frame_info_builder.setLineNumber(frame_location.lineNumber);
        frame_info_builder.setPosition(frame_location.position);
        frame_info_builder.setSourceId(script->id());
        frame_info_builder.setAstIndex(frame_location.ast_taint_tracking_index);

        // TODO: start_position and end_position API changed in new V8
        // frame_info_builder.setFunctionStartPosition(info->start_position());
        // frame_info_builder.setFunctionEndPosition(info->end_position());
      }

      frames[i].setFrameHumanReadable(human_string.get());
      traceMessages.push_back(std::move(human_string));
    }
  }

  auto source = sink_message.initTaintSource();
  InitTaintInfo(visitor.GetRanges(), &source);
  sink_message.setSinkType(FromSinkType(label));
  initer.SetJsString(sink_message.initTargetString(), message);
  initer.InitMessageOriginCheck(sink_message, message);
  if (symbolic_data) {
    auto init_sym = sink_message.initSymbolicValue();
    symbolic_data->WriteSelf(init_sym, message);
  }
  return static_cast<int64_t>(TaintTracker::Impl::LogToFile(
      isolate, message, FlushConfig::FORCE_FLUSH));
}

inline bool EnableConcolic() {
  return v8_flags.taint_tracking_enable_concolic &&
         !v8_flags.taint_tracking_enable_concolic_hooks_only;
}

int64_t LogIfTainted(DirectHandle<String> str, TaintSinkLabel label,
                     int symbolic_data, Isolate* isolate) {
  IsTaintedVisitor visitor;
  {
    DisallowHeapAllocation no_gc;
    visitor.run(*str, 0, str->length());
  }
  JsStringFromString initer(str, isolate);
  // TODO: ConcolicExecutor API changed in new V8
  // std::shared_ptr<SymbolicState> symbolic_arg =
  //     EnableConcolic() ? TaintTracker::FromIsolate(isolate)
  //                            ->Get()
  //                            ->Exec()
  //                            .GetSymbolicArgumentState(symbolic_data)
  //                      : std::shared_ptr<SymbolicState>();
  std::shared_ptr<SymbolicState> symbolic_arg = std::shared_ptr<SymbolicState>();
  return LogIfTainted(visitor, initer, isolate, label, symbolic_arg);
}

template <typename Char>
int64_t LogIfBufferTainted(TaintData* buffer, const Char* stringdata,
                           size_t length, int symbolic_data,
                           v8::internal::Isolate* isolate,
                           v8::String::TaintSinkLabel label) {
  IsTaintedVisitor visitor;
  visitor.Visit(stringdata, buffer, 0, static_cast<int>(length));
  JsStringFromBuffer<Char> initer(stringdata, static_cast<int>(length));
  // TODO: ConcolicExecutor API changed in new V8
  // std::shared_ptr<SymbolicState> symbolic_arg =
  //     EnableConcolic() ? TaintTracker::FromIsolate(isolate)
  //                            ->Get()
  //                            ->Exec()
  //                            .GetSymbolicArgumentState(symbolic_data)
  //                      : std::shared_ptr<SymbolicState>();
  std::shared_ptr<SymbolicState> symbolic_arg = std::shared_ptr<SymbolicState>();
  return LogIfTainted(visitor, initer, isolate, label, symbolic_arg);
}

template int64_t LogIfBufferTainted<uint8_t>(TaintData* buffer,
                                             const uint8_t* stringdata,
                                             size_t length, int symbolic_data,
                                             v8::internal::Isolate* isolate,
                                             v8::String::TaintSinkLabel label);
template int64_t LogIfBufferTainted<uint16_t>(TaintData* buffer,
                                              const uint16_t* stringdata,
                                              size_t length, int symbolic_data,
                                              v8::internal::Isolate* isolate,
                                              v8::String::TaintSinkLabel label);

class SetTaintOnObjectKv : public ObjectOwnPropertiesVisitor {
 public:
  SetTaintOnObjectKv(TaintType type) : type_(type) {}

  bool VisitKeyValue(Handle<String> key, Handle<Object> value) override {
    DisallowHeapAllocation no_gc;
    CopyIn(*key, type_, 0, key->length());
    if (IsString(*value)) {
      Handle<String> value_as_string = Cast<String>(value);
      CopyIn(*value_as_string, type_, 0, value_as_string->length());
    }
    return true;
  }

 private:
  TaintType type_;
};

void SetTaintOnObjectRecursive(Handle<JSReceiver> obj, TaintType type, Isolate* isolate) {
  SetTaintOnObjectKv v(type);
  v.Visit(obj, isolate);
}

void SetTaint(v8::internal::Handle<v8::internal::Object> obj, TaintType type, Isolate* isolate) {
  if (IsString(*obj)) {
    SetTaintString(Cast<String>(obj), type);
  } else if (IsJSReceiver(*obj)) {
    SetTaintOnObjectRecursive(Cast<JSReceiver>(obj), type, isolate);
  }
}

class SetTaintInfoOnObjectKv : public ObjectOwnPropertiesVisitor {
 public:
  SetTaintInfoOnObjectKv(int64_t info) : info_(info) {}

  bool VisitKeyValue(Handle<String> key, Handle<Object> value) override {
    // TODO: set_taint_info API removed in new V8
    // key->set_taint_info(info_);
    if (IsString(*value)) {
      // Cast<String>(value)->set_taint_info(info_);
    }
    return true;
  }

 private:
  [[maybe_unused]] int64_t info_;  // TODO: unused because set_taint_info API removed
};

void SetTaintInfo(v8::internal::Handle<v8::internal::Object> obj,
                  int64_t info, Isolate* isolate) {
  // TODO: set_taint_info API removed in new V8
  if (IsString(*obj)) {
    // Cast<String>(obj)->set_taint_info(info);
  } else if (IsJSReceiver(*obj)) {
    Handle<JSReceiver> receiver = Cast<JSReceiver>(obj);
    SetTaintInfoOnObjectKv kv(info);
    kv.Visit(receiver, isolate);
  }
}

Handle<Object> JSCheckTaintMaybeLog(Handle<String> str, Handle<Object> sink,
                                    int symbolic_data, Isolate* isolate) {
  int64_t ret = LogIfTainted(str, TaintSinkLabel::JAVASCRIPT, symbolic_data, isolate);
  if (ret == -1) {
    return isolate->factory()->ToBoolean(false);
  } else {
    DirectHandle<Object> num = Cast<Object>(isolate->factory()->NewNumberFromInt64(ret));
    return Handle<Object>(*num, isolate);
  }
}

v8::internal::Handle<v8::internal::JSArrayBuffer>
JSGetTaintStatus(v8::internal::Handle<v8::internal::String> str,
                 v8::internal::Isolate* isolate) {
  // TODO: JSArrayBuffer API changed in new V8, need to update this function
  // Handle<JSArrayBuffer> answer = isolate->factory()->NewJSArrayBuffer();
  // DisallowHeapAllocation no_gc;
  // int len = str->length();
  // JSArrayBuffer::SetupAllocatingData(answer, isolate, len, false,
  //                                    SharedFlag::kNotShared);
  // FlattenTaintData(*str, reinterpret_cast<TaintData*>(answer->backing_store()),
  //                  0, len);
  // return answer;

  // Temporary workaround: return empty JSArrayBuffer
  return isolate->factory()->NewJSArrayBuffer(std::shared_ptr<BackingStore>());
}

void JSTaintLog(v8::internal::Handle<v8::internal::String> str,
                v8::internal::MaybeHandle<v8::internal::String> extra_ref,
                Isolate* isolate) {
  MessageHolder message;
  auto log_message = message.InitRoot();
  auto js_message = log_message.getMessage().initJsLog();
  message.CopyJsStringSlow(js_message.initLogMessage(), str, isolate);
  // TODO: taint_info() and kUndefinedInstanceCounter removed in new V8
  // js_message.setExtraRefTaint(!extra_ref.is_null()
  //                                 ? extra_ref.ToHandleChecked()->taint_info()
  //                                 : kUndefinedInstanceCounter);
  TaintTracker::Impl::LogToFile(isolate, message, FlushConfig::FORCE_FLUSH);
}

void TaintTracker::OnBeforeCompile(Handle<Script> script, Isolate* isolate) {
  DisallowHeapAllocation no_gc;
  Tagged<Object> source_obj = script->source();
  DCHECK(IsString(source_obj));
  Tagged<String> source = Cast<String>(source_obj);
  IsTaintedVisitor visitor;
  visitor.run(source, 0, source->length());
  if ((visitor.GetFlag() & static_cast<TaintFlag>(TaintType::UNTAINTED)) == 0) {
    TaintInstanceInfo instance;
    std::unique_ptr<char[]> name(
        Object::ToString(isolate, handle(script->name(), isolate))
            .ToHandleChecked()
            ->ToCString());
    std::unique_ptr<char[]> source_url(
        Object::ToString(isolate, handle(script->source_url(), isolate))
            .ToHandleChecked()
            ->ToCString());
    std::unique_ptr<char[]> source_code(source->ToCString());
    instance.taint_flag = visitor.GetFlag();
    instance.name = name.get();
    instance.source_url = source_url.get();
    instance.source_code = source_code.get();
    instance.ranges = visitor.GetRanges();
    FromIsolate(isolate)->Get()->Trigger(instance, isolate);
  }
}

TaintTracker* TaintTracker::New(bool enable_serializer,
                                v8::internal::Isolate* isolate) {
  return new TaintTracker(enable_serializer, isolate);
}

void TaintTracker::RegisterTaintListener(TaintListener* listener) {
  Get()->RegisterTaintListener(listener);
}

// static
TaintTracker* TaintTracker::FromIsolate(Isolate* isolate) {
  return isolate->taint_tracking_data();
}

TaintTracker::TaintTracker(bool enable_serializer,
                           v8::internal::Isolate* isolate)
    : impl_(std::unique_ptr<TaintTracker::Impl>(
          new TaintTracker::Impl(enable_serializer, isolate))) {}

TaintTracker::~TaintTracker() {}

TaintTracker::Impl* TaintTracker::Get() { return impl_.get(); }

TaintTracker::Impl::Impl(bool enable_serializer, v8::internal::Isolate* isolate)
    : message_counter_(0),
      log_(),
      listeners_(),
      is_logging_(false),
      log_flush_scheduled_(false),
      has_heartbeat_(false),
      unsent_messages_(0),
      log_mutex_(),
      // exec_(isolate),  // Commented out: ConcolicExecutor incomplete type
      versioner_(new ObjectVersioner(isolate)) {
  symbolic_elem_counter_ = enable_serializer ? 1 : kMaxCounterSnapshot;
  last_message_flushed_.Start();
}

void TaintTracker::Initialize(v8::internal::Isolate* isolate) {
  Get()->Initialize(isolate);
}

bool TaintTracker::IsRewriteAstEnabled() {
  return v8_flags.taint_tracking_enable_ast_modification;
}

void TaintTracker::Impl::Initialize(v8::internal::Isolate* isolate) {
  const char* taint_log_file = v8_flags.taint_log_file;
  if (taint_log_file != nullptr && taint_log_file[0] != '\0') {
    std::lock_guard<std::mutex> guard(log_mutex_);
    is_logging_ = true;

    std::unique_ptr<std::ofstream> oflog(new std::ofstream());
    oflog->open(LogFileName());
    std::swap(log_, oflog);
    buffer_log_storage_ = kj::heapArray<uint8_t>(kLogBufferSize);
    kj_log_.reset(new ::kj::std::StdOutputStream(*log_));
    buffered_log_.reset(
        new ::kj::BufferedOutputStreamWrapper(*kj_log_, buffer_log_storage_));
  }

  HandleScope scope(isolate);
  if (EnableConcolic()) {
    // TODO: ConcolicExecutor API changed in new V8
    // Exec().Initialize();
  }

  static const int INITIAL_SIZE = 10;
  Handle<Object> tmp = ObjectHashTable::New(isolate, INITIAL_SIZE);
  cross_origin_message_table_ = Cast<ObjectHashTable>(
      isolate->global_handles()->Create(*tmp.location()));
}

TaintTracker::Impl::~Impl() {
  if (is_logging_) {
    std::lock_guard<std::mutex> guard(log_mutex_);
    log_->close();
  }

  GlobalHandles::Destroy(
      reinterpret_cast<Address*>(cross_origin_message_table_.location()));
}

void TaintTracker::Impl::RegisterTaintListener(TaintListener* listener) {
  listeners_.push_back(std::unique_ptr<TaintListener>(listener));
}

void TaintTracker::Impl::Trigger(const TaintInstanceInfo& info,
                                 Isolate* isolate) {
  for (auto& listener : listeners_) {
    listener->OnTaintedCompilation(info, isolate);
  }
}

bool TaintTracker::Impl::IsLogging() const { return is_logging_; }

bool TaintTracker::Impl::HasHeartbeat() const { return is_logging_; }

void MakeUniqueLogFileName(std::ostringstream& base) {
  base << v8_flags.taint_log_file << "_" << v8::base::OS::GetCurrentProcessId()
       << "_" << static_cast<int64_t>(v8::base::OS::TimeCurrentMillis());
}

std::string TaintTracker::Impl::LogFileName() {
  std::lock_guard<std::mutex> lock(isolate_counter_mutex_);
  std::ostringstream log_fname;
  MakeUniqueLogFileName(log_fname);
  log_fname << "_" << (isolate_counter_++);
  return log_fname.str();
}

InstanceCounter* TaintTracker::symbolic_elem_counter() {
  return &(Get()->symbolic_elem_counter_);
}

InstanceCounter TaintTracker::Impl::NewInstance() {
  return symbolic_elem_counter_++;
}

v8::internal::Handle<v8::internal::HeapObject> JSTaintConstants(
    v8::internal::Isolate* isolate) {
  Factory* factory = isolate->factory();
  Handle<JSObject> ret = factory->NewJSObjectWithNullProto();
  MaybeHandle<Object> ignore;
  for (int i = static_cast<int>(TaintType::UNTAINTED); i < static_cast<int>(MAX_TAINT_TYPE); i++) {
    std::string taint_string = TaintTypeToString(static_cast<TaintType>(i));
    v8::base::Vector<const char> js_string(taint_string.data(), taint_string.size());
    ignore = Object::SetProperty(
        isolate,
        ret,
        Cast<Name>(
            factory->NewStringFromUtf8(js_string).ToHandleChecked()),
        Cast<Object>(factory->NewHeapNumber(i)), StoreOrigin::kMaybeKeyed);
  }
  ignore = Object::SetProperty(
      isolate,
      ret,
      Cast<Name>(
          factory->NewStringFromAsciiChecked(kEnableHeaderLoggingName)),
      Cast<Object>(factory->NewHeapNumber(
          v8_flags.taint_tracking_enable_header_logging ? 1 : 0)),
      StoreOrigin::kMaybeKeyed);
  ignore = Object::SetProperty(
      isolate,
      ret,
      Cast<Name>(
          factory->NewStringFromAsciiChecked(kEnableBodyLoggingName)),
      Cast<Object>(factory->NewHeapNumber(
          v8_flags.taint_tracking_enable_page_logging ? 1 : 0)),
      StoreOrigin::kMaybeKeyed);
  std::ostringstream log_name_base;
  MakeUniqueLogFileName(log_name_base);
  log_name_base << "_full_page_" << isolate;
  ignore = Object::SetProperty(
      isolate,
      ret,
      Cast<Name>(
          factory->NewStringFromAsciiChecked(kLoggingFilenamePrefix)),
      Cast<Object>(
          factory->NewStringFromAsciiChecked(log_name_base.str().c_str())),
      StoreOrigin::kMaybeKeyed);
  ignore = Object::SetProperty(
      isolate,
      ret, Cast<Name>(factory->NewStringFromAsciiChecked(kJobIdName)),
      Cast<Object>(
          factory->NewStringFromAsciiChecked(v8_flags.taint_tracking_job_id)),
      StoreOrigin::kMaybeKeyed);
  return ret;
}

template void OnNewConcatStringCopy<SeqOneByteString, String, String>(
    SeqOneByteString*, String*, String*, Isolate*);
template void OnNewConcatStringCopy<SeqTwoByteString, String, String>(
    SeqTwoByteString*, String*, String*, Isolate*);

template void OnNewSubStringCopy<String, SeqOneByteString>(String*,
                                                           SeqOneByteString*,
                                                           int, int, Isolate*);
template void OnNewSubStringCopy<SeqOneByteString, SeqOneByteString>(
    SeqOneByteString*, SeqOneByteString*, int, int, Isolate*);
template void OnNewSubStringCopy<String, SeqTwoByteString>(String*,
                                                           SeqTwoByteString*,
                                                           int, int, Isolate*);
template void OnNewSubStringCopy<ConsString, SeqString>(ConsString*, SeqString*,
                                                        int, int, Isolate*);
template void OnNewSubStringCopy<SeqOneByteString, SeqString>(SeqOneByteString*,
                                                              SeqString*, int,
                                                              int, Isolate*);
template void OnNewSubStringCopy<String, SeqString>(String*, SeqString*, int,
                                                    int, Isolate*);

template void FlattenTaintData<ExternalString>(ExternalString*, TaintData*, int,
                                               int);
template void FlattenTaintData<String>(String*, TaintData*, int, int);

// Tagged versions
template void FlattenTaintData<String>(Tagged<String>, TaintData*, int, int);
template void FlattenTaintData<ExternalString>(Tagged<ExternalString>, TaintData*, int, int);

template TaintType GetTaintStatusRange<String>(String*, size_t, size_t);

template TaintType GetTaintStatus<String>(String*, size_t);

template void SetTaintStatus<SeqOneByteString>(SeqOneByteString*, size_t,
                                               TaintType);
template void SetTaintStatus<SeqTwoByteString>(SeqTwoByteString*, size_t,
                                               TaintType);
template void SetTaintStatus<String>(String*, size_t, TaintType);

template void CopyIn<SeqOneByteString>(SeqOneByteString*, TaintType, int, int);

template void CopyIn<SeqOneByteString>(SeqOneByteString*, const TaintData*, int,
                                       int);
template void CopyIn<SeqTwoByteString>(SeqTwoByteString*, const TaintData*, int,
                                       int);
template void CopyIn<SeqString>(SeqString*, const TaintData*, int, int);

// Tagged versions with TaintData
template void CopyIn<SeqString>(Tagged<SeqString>, const TaintData*, int, int);
template void CopyIn<SeqOneByteString>(Tagged<SeqOneByteString>, const TaintData*, int, int);
template void CopyIn<SeqTwoByteString>(Tagged<SeqTwoByteString>, const TaintData*, int, int);

// Tagged versions with TaintType
template void CopyIn<SeqString>(Tagged<SeqString>, TaintType, int, int);
template void CopyIn<SeqOneByteString>(Tagged<SeqOneByteString>, TaintType, int, int);
template void CopyIn<SeqTwoByteString>(Tagged<SeqTwoByteString>, TaintType, int, int);

template void CopyOut<SeqString>(SeqString*, TaintData*, int, int);
template void CopyOut<SeqOneByteString>(SeqOneByteString*, TaintData*, int,
                                        int);
template void CopyOut<SeqTwoByteString>(SeqTwoByteString*, TaintData*, int,
                                        int);

// Tagged versions
template void CopyOut<SeqString>(Tagged<SeqString>, TaintData*, int, int);
template void CopyOut<SeqOneByteString>(Tagged<SeqOneByteString>, TaintData*, int, int);
template void CopyOut<SeqTwoByteString>(Tagged<SeqTwoByteString>, TaintData*, int, int);

template void OnNewReplaceRegexpWithString<SeqOneByteString>(
    String* subject, SeqOneByteString* result, JSRegExp* pattern,
    String* replacement, Isolate* isolate);
template void OnNewReplaceRegexpWithString<SeqTwoByteString>(
    String* subject, SeqTwoByteString* result, JSRegExp* pattern,
    String* replacement, Isolate* isolate);

template void OnJoinManyStrings<SeqOneByteString, JSArray>(SeqOneByteString*,
                                                           JSArray*, Isolate*);
template void OnJoinManyStrings<SeqTwoByteString, JSArray>(SeqTwoByteString*,
                                                           JSArray*, Isolate*);
template void OnJoinManyStrings<SeqOneByteString, FixedArray>(SeqOneByteString*,
                                                              FixedArray*, Isolate*);
template void OnJoinManyStrings<SeqTwoByteString, FixedArray>(SeqTwoByteString*,
                                                              FixedArray*, Isolate*);

template void FlattenTaint<SeqOneByteString, String>(String*, SeqOneByteString*,
                                                     int, int);
template void FlattenTaint<SeqTwoByteString, String>(String*, SeqTwoByteString*,
                                                     int, int);

template <size_t N>
void LogSymbolic(Tagged<String> first, const std::array<Tagged<String>, N>& refs,
                 std::string extra, SymbolicType type, Isolate* isolate) {
  DCHECK(v8_flags.taint_tracking_enable_symbolic);
  DCHECK_NOT_NULL(first);

  MessageHolder message;
  auto log_message = message.InitRoot();
  auto symbolic_log = log_message.getMessage().initSymbolicLog();
  // TODO: taint_info() method no longer exists
  // symbolic_log.setTargetId(first->taint_info());
  // auto arg_list = symbolic_log.initArgRefs(refs.size());
  for (size_t i = 0; i < refs.size(); i++) {
    // TODO: taint_info() method no longer exists
    // arg_list.set(i, refs[i]->taint_info());
  }
  message.CopyJsStringSlow(symbolic_log.initTargetValue(), handle(first, isolate), isolate);
  IsTaintedVisitor visitor;
  visitor.run(first, 0, first->length());
  auto info_ranges = visitor.GetRanges();
  auto value = symbolic_log.initTaintValue();
  InitTaintInfo(info_ranges, &value);
  symbolic_log.setSymbolicOperation(SymbolicTypeToEnum(type));

  TaintTracker::Impl::LogToFile(isolate, message);
}

template <class T>
void OnNewStringLiteral(T* source, Isolate* isolate) {
  if (v8_flags.taint_tracking_enable_symbolic) {
    LogSymbolic<0>(source, {{}}, "", LITERAL, isolate);
  }
}
template void OnNewStringLiteral(String* source, Isolate* isolate);
template void OnNewStringLiteral(SeqOneByteString* source, Isolate* isolate);
template void OnNewStringLiteral(SeqTwoByteString* source, Isolate* isolate);

void OnNewDeserializedString(String* source, Isolate* isolate) {
  MarkNewString(source);
  OnNewStringLiteral(source, isolate);
}

template <class T, class S>
void OnNewSubStringCopy(T* source, S* dest, int offset, int length, Isolate* isolate) {
  FlattenTaint(source, dest, offset, length);
  if (v8_flags.taint_tracking_enable_symbolic) {
    LogSymbolic<1>(dest, {{source}}, std::to_string(offset), SLICE, isolate);
  }
}

void OnNewSlicedString(SlicedString* target, String* first, int offset,
                       int length, Isolate* isolate) {
  MarkNewString(target);
  if (v8_flags.taint_tracking_enable_symbolic) {
    LogSymbolic<1>(target, {{first}}, std::to_string(offset), SLICE, isolate);
  }
}

template <class T, class S, class R>
void OnNewConcatStringCopy(T* dest, S* first, R* second, Isolate* isolate) {
  ConcatTaint(dest, first, second);
  if (v8_flags.taint_tracking_enable_symbolic) {
    LogSymbolic<2>(dest, {{first, second}}, "", CONCAT, isolate);
  }
}

void OnNewConsString(ConsString* target, String* first, String* second, Isolate* isolate) {
  MarkNewString(target);
  if (v8_flags.taint_tracking_enable_symbolic) {
    LogSymbolic<2>(target, {{first, second}}, "", CONCAT, isolate);
  }
}

void OnNewFromJsonString(SeqString* target, String* source, Isolate* isolate) {
  if (v8_flags.taint_tracking_enable_symbolic) {
    LogSymbolic<1>(target, {{source}}, "", PARSED_JSON, isolate);
  }
}

template <class T>
void OnNewExternalString(T* str, Isolate* isolate) {
  MarkNewString(str);
  OnNewStringLiteral(str, isolate);
}
template void OnNewExternalString<ExternalOneByteString>(
    ExternalOneByteString*, Isolate*);
template void OnNewExternalString<ExternalTwoByteString>(
    ExternalTwoByteString*, Isolate*);

template <class T>
void OnNewReplaceRegexpWithString(String* subject, T* result, JSRegExp* pattern,
                                  String* replacement, Isolate* isolate) {
  if (v8_flags.taint_tracking_enable_symbolic) {
    LogSymbolic<2>(result, {{subject, Cast<String>(pattern->source(isolate))}},
                   replacement->ToCString().get(), REGEXP, isolate);
  }
}

template <class T, class Array>
void OnJoinManyStrings(T* target, Array* array, Isolate* isolate) {
  if (v8_flags.taint_tracking_enable_symbolic) {
    LogSymbolic<0>(target, {{}}, "TODO: print array value", JOIN, isolate);
  }
}

template <class T>
void OnConvertCase(String* source, T* answer, Isolate* isolate) {
  FlattenTaint(source, answer, 0, source->length());
  if (v8_flags.taint_tracking_enable_symbolic) {
    LogSymbolic<1>(answer, {{source}}, "", CASE_CHANGE, isolate);
  }
}
template void OnConvertCase<SeqOneByteString>(String* source,
                                              SeqOneByteString* answer, Isolate* isolate);
template void OnConvertCase<SeqTwoByteString>(String* source,
                                              SeqTwoByteString* answer, Isolate* isolate);
template void OnConvertCase<SeqString>(String* source, SeqString* answer, Isolate* isolate);

template void OnGenericOperation<String>(SymbolicType, Tagged<String>, Isolate*);
template void OnGenericOperation<SeqOneByteString>(SymbolicType,
                                                   Tagged<SeqOneByteString>, Isolate*);
template void OnGenericOperation<SeqTwoByteString>(SymbolicType,
                                                   Tagged<SeqTwoByteString>, Isolate*);
template <class T>
void OnGenericOperation(SymbolicType type, Tagged<T> source, Isolate* isolate) {
  if (v8_flags.taint_tracking_enable_symbolic) {
    LogSymbolic<0>(source, {{}}, "", type, isolate);
  }

  // TODO: These variables are unused after commenting out the encoding logic
  // uint8_t anti_mask;
  // uint8_t mask;
  switch (type) {
    // TODO: These TaintType enum values don't exist in the current version
    // case SymbolicType::URI_DECODE:
    //   anti_mask = TaintType::URL_ENCODED;
    //   mask = TaintType::URL_DECODED;
    //   break;

    // case SymbolicType::URI_COMPONENT_DECODE:
    //   anti_mask = TaintType::URL_COMPONENT_ENCODED;
    //   mask = TaintType::URL_COMPONENT_DECODED;
    //   break;

    // case SymbolicType::URI_UNESCAPE:
    //   anti_mask = TaintType::ESCAPE_ENCODED;
    //   mask = TaintType::ESCAPE_DECODED;
    //   break;

    // case SymbolicType::URI_ENCODE:
    //   mask = TaintType::URL_ENCODED;
    //   anti_mask = TaintType::URL_DECODED;
    //   break;

    // case SymbolicType::URI_COMPONENT_ENCODE:
    //   mask = TaintType::URL_COMPONENT_ENCODED;
    //   anti_mask = TaintType::URL_COMPONENT_DECODED;
    //   break;

    // case SymbolicType::URI_ESCAPE:
    //   mask = TaintType::ESCAPE_ENCODED;
    //   anti_mask = TaintType::ESCAPE_DECODED;
    //   break;

    default:
      return;
  }

  // The encoding operations are required to return a flat string.
  // DCHECK(source->IsSeqString());  // TODO: IsSeqString() method removed in new V8

  {
    DisallowHeapAllocation no_gc;
    Tagged<SeqString> as_seq_tagged = Cast<SeqString>(source);
    SeqString* as_seq_ptr = as_seq_tagged.operator->();

    int length = as_seq_ptr->length();
    std::vector<TaintData> type_arr(length);
    CopyOut(as_seq_ptr, type_arr.data(), 0, length);

    for (int i = 0; i < length; i++) {
      // TODO: type_i is unused after commenting out the encoding logic
      // uint8_t type_i = static_cast<uint8_t>(type_arr[i]);
      // TODO: ENCODING_TYPE_MASK, NO_ENCODING, MULTIPLE_ENCODINGS don't exist
      // uint8_t old_encoding = type_i & TaintType::ENCODING_TYPE_MASK;

      // If the old encoding is nothing, then we move to the mask encoding. If
      // the old encoding was the inverse operation, then we move to no
      // encoding. If it is neither, then we move to the multiple encoding
      // state.
      // TODO: NO_ENCODING and MULTIPLE_ENCODINGS don't exist, commenting out
      // uint8_t new_encoding =
      //     old_encoding == TaintType::NO_ENCODING
      //         ? mask
      //         : (old_encoding == anti_mask ? TaintType::NO_ENCODING
      //                                      : TaintType::MULTIPLE_ENCODINGS);

      // type_arr[i] = static_cast<TaintType>(
      //     (static_cast<uint8_t>(type_i) & TAINT_TYPE_MASK) | static_cast<uint8_t>(new_encoding));
    }

    // TODO: Perform this operation in-place without the copy in and copy out
    // calls.
    CopyIn(as_seq_ptr, type_arr.data(), 0, length);
  }
}

void InsertControlFlowHook(ParseInfo* info) {
  DCHECK_NOT_NULL(info->literal());
  if (v8_flags.taint_tracking_enable_export_ast ||
      v8_flags.taint_tracking_enable_ast_modification ||
      v8_flags.taint_tracking_enable_source_export ||
      v8_flags.taint_tracking_enable_source_hash_export) {
    // CHECK(SerializeAst(info));  // TODO: SerializeAst API changed
  }
}

// ConcolicExecutor& TaintTracker::Impl::Exec() { return exec_; }  // TODO: exec_ member not found

ObjectVersioner& TaintTracker::Impl::Versioner() { return *versioner_; }

void LogRuntimeSymbolic(Isolate* isolate, Handle<Object> target_object,
                        Handle<Object> label, CheckType check) {
  MessageHolder message;
  auto log_message = message.InitRoot();
  auto cntrl_flow = log_message.getMessage().initRuntimeLog();
  // BuilderSerializer serializer_out;  // TODO: BuilderSerializer not found
  V8NodeLabelSerializer serializer_in(isolate);
  NodeLabel out;
  // CHECK_EQ(Status::OK, serializer_in.Deserialize(label, &out));
  // CHECK_EQ(Status::OK, serializer_out.Serialize(cntrl_flow.initLabel(), out));
  bool isstring = IsString(*target_object);
  if (isstring) {
    // cntrl_flow.setObjectLabel(
    //     Cast<String>(target_object)->taint_info());  // TODO: taint_info() not available
  }
  switch (check) {
    case CheckType::STATEMENT_BEFORE:
      cntrl_flow.setCheckType(::Ast::RuntimeLog::CheckType::STATEMENT_BEFORE);
      break;
    case CheckType::STATEMENT_AFTER:
      cntrl_flow.setCheckType(::Ast::RuntimeLog::CheckType::STATEMENT_AFTER);
      break;
    case CheckType::EXPRESSION_BEFORE:
      cntrl_flow.setCheckType(::Ast::RuntimeLog::CheckType::EXPRESSION_BEFORE);
      break;
    case CheckType::EXPRESSION_AFTER:
    case CheckType::STATIC_VALUE_CHECK:
      cntrl_flow.setCheckType(::Ast::RuntimeLog::CheckType::EXPRESSION_AFTER);
      break;
    default:
      UNREACHABLE();
  }

  TaintTracker::Impl::LogToFile(isolate, message);
}

uint64_t MAGIC_NUMBER = 0xbaededfeed;

V8NodeLabelSerializer::V8NodeLabelSerializer(Isolate* isolate)
    : local_isolate_(isolate->main_thread_local_isolate()) {}

V8NodeLabelSerializer::V8NodeLabelSerializer(LocalIsolate* local_isolate)
    : local_isolate_(local_isolate) {}

Status V8NodeLabelSerializer::Serialize(Object** output,
                                        const NodeLabel& label) {
  if (!label.IsValid()) {
    return Status::FAILURE;
  }
  // TODO: Fix pointer assignment - API changed
  // *output = *Make(label);
  return Status::OK;
}

v8::internal::Handle<v8::internal::Object> V8NodeLabelSerializer::Make(
    const NodeLabel& label) {
  auto* factory = local_isolate_->factory();
  Handle<SeqOneByteString> str =
      factory
          ->NewRawOneByteString(sizeof(NodeLabel::Rand) +
                                sizeof(NodeLabel::Counter) + sizeof(uint64_t))
          .ToHandleChecked();
  NodeLabel::Rand rand_val = label.GetRand();
  NodeLabel::Counter counter_val = label.GetCounter();
  DisallowGarbageCollection no_gc;
  uint8_t* data = str->GetChars(no_gc);
  MemCopy(data, reinterpret_cast<const uint8_t*>(&rand_val),
          sizeof(NodeLabel::Rand));
  MemCopy(data + sizeof(NodeLabel::Rand),
          reinterpret_cast<const uint8_t*>(&counter_val),
          sizeof(NodeLabel::Counter));
  MemCopy(
      data + sizeof(NodeLabel::Rand) + sizeof(NodeLabel::Counter),
      reinterpret_cast<const uint8_t*>(&MAGIC_NUMBER), sizeof(uint64_t));
  return str;
}

Status V8NodeLabelSerializer::Serialize(Handle<Object>* output,
                                        const NodeLabel& label) {
  if (!label.IsValid()) {
    return Status::FAILURE;
  }

  *output = Make(label);
  return Status::OK;
}

Status V8NodeLabelSerializer::Deserialize(Handle<Object> arr,
                                          NodeLabel* label) {
  DisallowHeapAllocation no_gc;
  // return Deserialize(*arr, label);  // TODO: Deserialize signature changed
  return Status::FAILURE;
}

Status V8NodeLabelSerializer::Deserialize(Object* arr, NodeLabel* label) {
  DisallowGarbageCollection no_gc;
  Tagged<Object> tagged_arr = *reinterpret_cast<Tagged<Object>*>(&arr);
  if (!IsSeqOneByteString(tagged_arr)) {
    return Status::FAILURE;
  }
  Tagged<SeqOneByteString> seqstr = Cast<SeqOneByteString>(tagged_arr);

  if (sizeof(NodeLabel::Rand) + sizeof(NodeLabel::Counter) + sizeof(uint64_t) !=
      static_cast<size_t>(seqstr->length())) {
    return Status::FAILURE;
  }

  NodeLabel::Rand rand_val;
  NodeLabel::Counter counter_val;
  const uint8_t* data = seqstr->GetChars(no_gc);
  MemCopy(reinterpret_cast<uint8_t*>(&rand_val), data,
          sizeof(NodeLabel::Rand));
  MemCopy(reinterpret_cast<uint8_t*>(&counter_val),
          data + sizeof(NodeLabel::Rand),
          sizeof(NodeLabel::Counter));

  uint64_t magic_number_check;
  MemCopy(
      reinterpret_cast<uint8_t*>(&magic_number_check),
      data + sizeof(NodeLabel::Counter) + sizeof(NodeLabel::Rand),
      sizeof(uint64_t));
  if (magic_number_check != MAGIC_NUMBER) {
    return Status::FAILURE;
  }
  label->CopyFrom(NodeLabel(rand_val, counter_val));
  return label->IsValid() ? Status::OK : Status::FAILURE;
}

void RuntimeHook(Isolate* isolate, Handle<Object> target_object,
                 Handle<Object> label, int checktype) {
  DCHECK(v8_flags.taint_tracking_enable_ast_modification);
  CheckType check = static_cast<CheckType>(checktype);

  if (v8_flags.taint_tracking_enable_symbolic) {
    LogRuntimeSymbolic(isolate, target_object, label, check);
  }
  if (EnableConcolic()) {
    // TaintTracker::FromIsolate(isolate)->Get()->Exec().OnRuntimeHook(
    //     target_object, label, check);  // TODO: Exec() not available
  }
}

void RuntimeHookVariableLoad(Isolate* isolate, Handle<Object> target_object,
                             Handle<Object> proxy_label,
                             Handle<Object> past_assignment_label,
                             int checktype) {
  DCHECK(v8_flags.taint_tracking_enable_ast_modification);
  CheckType check = static_cast<CheckType>(checktype);

  if (v8_flags.taint_tracking_enable_symbolic) {
    LogRuntimeSymbolic(isolate, target_object, proxy_label, check);
  }
  if (EnableConcolic()) {
    // TaintTracker::FromIsolate(isolate)->Get()->Exec().OnRuntimeHookVariableLoad(
    //     target_object, proxy_label, past_assignment_label, check);  // TODO: Exec() not available
  }
}

Handle<Object> RuntimeHookVariableStore(Isolate* isolate,
                                        Handle<Object> concrete,
                                        Handle<Object> label,
                                        CheckType checktype,
                                        Handle<Object> var_idx) {
  if (EnableConcolic()) {
    // TaintTracker::FromIsolate(isolate)->Get()->Exec().OnRuntimeHookVariableStore(
    //     concrete, label, checktype, var_idx);  // TODO: Exec() not available
    return isolate->factory()->undefined_value();
  } else {
    return isolate->factory()->undefined_value();
  }
}

void RuntimeHookVariableContextStore(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::Object> concrete,
    v8::internal::Handle<v8::internal::Object> label,
    v8::internal::Handle<v8::internal::Context> context,
    v8::internal::Handle<v8::internal::Smi> smi) {
  if (EnableConcolic()) {
    // return TaintTracker::FromIsolate(isolate)
    //     ->Get()
    //     ->Exec()
    //     .OnRuntimeHookVariableContextStore(concrete, label, context, smi);  // TODO: Exec() not available
  }
}

void RuntimeExitSymbolicStackFrame(v8::internal::Isolate* isolate) {
  if (EnableConcolic()) {
    // return TaintTracker::FromIsolate(isolate)
    //     ->Get()
    //     ->Exec()
    //     .ExitSymbolicStackFrame();  // TODO: Exec() not available
  }
}

void RuntimePrepareSymbolicStackFrame(v8::internal::Isolate* isolate,
                                      FrameType type) {
  if (EnableConcolic()) {
    // return TaintTracker::FromIsolate(isolate)
    //     ->Get()
    //     ->Exec()
    //     .PrepareSymbolicStackFrame(type);  // TODO: Exec() not available
  }
}

void RuntimeEnterSymbolicStackFrame(v8::internal::Isolate* isolate) {
  if (EnableConcolic()) {
    // return TaintTracker::FromIsolate(isolate)
    //     ->Get()
    //     ->Exec()
    //     .EnterSymbolicStackFrame();  // TODO: Exec() not available
  }
}

void RuntimeAddArgumentToStackFrame(
    v8::internal::Isolate* isolate,
    v8::internal::MaybeHandle<v8::internal::Object> label) {
  if (EnableConcolic()) {
    // TaintTracker::FromIsolate(isolate)->Get()->Exec().AddArgumentToFrame(label);  // TODO: Exec() not available
  }
}

void RuntimeAddLiteralArgumentToStackFrame(
    v8::internal::Isolate* isolate,
    v8::internal::DirectHandle<v8::internal::Object> value) {
  if (EnableConcolic()) {
    // TaintTracker::FromIsolate(isolate)->Get()->Exec().AddLiteralArgumentToFrame(
    //     value);  // TODO: Exec() not available
  }
}

v8::internal::Handle<v8::internal::Object> GetSymbolicArgument(
    v8::internal::Isolate* isolate, uint32_t i) {
  if (EnableConcolic()) {
    // return TaintTracker::FromIsolate(isolate)
    //     ->Get()
    //     ->Exec()
    //     .GetSymbolicArgumentObject(i);  // TODO: Exec() not available
    return isolate->factory()->undefined_value();
  } else {
    return isolate->factory()->undefined_value();
  }
}

void LogHeartBeat(v8::internal::Isolate* isolate) {
  MessageHolder holder;
  auto builder = holder.InitRoot();
  auto message = builder.getMessage();
  auto job_id_message = message.initJobId();
  job_id_message.setJobId(v8_flags.taint_tracking_job_id.value());
  job_id_message.setTimestampMillisSinceEpoch(
      static_cast<int64_t>(v8::base::OS::TimeCurrentMillis()));
  TaintTracker::Impl::LogToFile(isolate, holder, FlushConfig::FORCE_FLUSH);
}

void HeartBeatTask::Run() {
  LogHeartBeat(isolate_);
  StartTimer(isolate_);
}

bool HasLabel(v8::internal::Isolate* isolate, const NodeLabel& label) {
  if (EnableConcolic()) {
    // return TaintTracker::FromIsolate(isolate)->Get()->Exec().HasLabel(label);  // TODO: Exec() not available
    return false;
  } else {
    return false;
  }
}

bool SymbolicMatchesFunctionArgs(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  if (EnableConcolic()) {
    // return TaintTracker::FromIsolate(
    //            reinterpret_cast<v8::internal::Isolate*>(info.GetIsolate()))
    //     ->Get()
    //     ->Exec()
    //     .MatchesArgs(info);  // TODO: Exec() not available
    return true;
  } else {
    return true;
  }
}

void RuntimeSetReturnValue(
    v8::internal::Isolate* isolate,
    v8::internal::DirectHandle<v8::internal::Object> value,
    v8::internal::MaybeDirectHandle<v8::internal::Object> label) {
  if (EnableConcolic()) {
    // TaintTracker::FromIsolate(isolate)->Get()->Exec().OnRuntimeSetReturnValue(
    //     value, label);  // TODO: Exec() not available
  }
}

void RuntimeEnterTry(v8::internal::Isolate* isolate,
                     v8::internal::DirectHandle<v8::internal::Object> label) {
  if (EnableConcolic()) {
    // TaintTracker::FromIsolate(isolate)->Get()->Exec().OnRuntimeEnterTry(label);  // TODO: Exec() not available
  }
}

void RuntimeExitTry(v8::internal::Isolate* isolate,
                    v8::internal::DirectHandle<v8::internal::Object> label) {
  if (EnableConcolic()) {
    // TaintTracker::FromIsolate(isolate)->Get()->Exec().OnRuntimeExitTry(label);  // TODO: Exec() not available
  }
}

void RuntimeOnThrow(v8::internal::Isolate* isolate,
                    v8::internal::DirectHandle<v8::internal::Object> exception,
                    bool is_rethrow) {
  if (EnableConcolic()) {
    // TaintTracker::FromIsolate(isolate)->Get()->Exec().OnRuntimeThrow(
    //     exception, is_rethrow);  // TODO: Exec() not available
  }
}

void RuntimeOnCatch(v8::internal::Isolate* isolate,
                    v8::internal::DirectHandle<v8::internal::Object> thrown_object,
                    v8::internal::DirectHandle<v8::internal::Context> context) {
  if (EnableConcolic()) {
    // TaintTracker::FromIsolate(isolate)->Get()->Exec().OnRuntimeCatch(
    //     thrown_object, context);  // TODO: Exec() not available
  }
}

void RuntimeOnExitFinally(v8::internal::Isolate* isolate) {
  if (EnableConcolic()) {
    // TaintTracker::FromIsolate(isolate)->Get()->Exec().OnRuntimeExitFinally();  // TODO: Exec() not available
  }
}

void RuntimeSetReceiver(v8::internal::Isolate* isolate,
                        v8::internal::DirectHandle<v8::internal::Object> value,
                        v8::internal::DirectHandle<v8::internal::Object> label) {
  if (EnableConcolic()) {
    // TaintTracker::FromIsolate(isolate)->Get()->Exec().SetReceiverOnFrame(value,
    //                                                                      label);  // TODO: Exec() not available
  }
}

v8::internal::Tagged<v8::internal::Object> RuntimePrepareApplyFrame(
    v8::internal::Isolate* isolate,
    v8::internal::DirectHandle<v8::internal::Object> argument_list,
    v8::internal::DirectHandle<v8::internal::Object> target_fn,
    v8::internal::DirectHandle<v8::internal::Object> new_target,
    v8::internal::DirectHandle<v8::internal::Object> this_argument,
    FrameType frame_type) {
  if (EnableConcolic()) {
    // TaintTracker::FromIsolate(isolate)->Get()->Exec().RuntimePrepareApplyFrame(
    //     argument_list, target_fn, new_target, this_argument, frame_type);  // TODO: Exec() not available
  }
  return Cast<Object>(ReadOnlyRoots(isolate).undefined_value());
}

v8::internal::Tagged<v8::internal::Object> RuntimePrepareCallFrame(
    v8::internal::Isolate* isolate,
    v8::internal::DirectHandle<v8::internal::Object> target_fn,
    FrameType caller_frame_type,
    v8::internal::DirectHandle<v8::internal::FixedArray> args) {
  if (EnableConcolic()) {
    // TaintTracker::FromIsolate(isolate)->Get()->Exec().RuntimePrepareCallFrame(
    //     target_fn, caller_frame_type, args);  // TODO: Exec() not available
  }
  return Cast<Object>(ReadOnlyRoots(isolate).undefined_value());
}

v8::internal::Tagged<v8::internal::Object> RuntimePrepareCallOrConstructFrame(
    v8::internal::Isolate* isolate,
    v8::internal::DirectHandle<v8::internal::Object> target_fn,
    v8::internal::DirectHandle<v8::internal::Object> new_target,
    v8::internal::DirectHandle<v8::internal::FixedArray> args) {
  if (EnableConcolic()) {
    // TaintTracker::FromIsolate(isolate)
    //     ->Get()
    //     ->Exec()
    //     .RuntimePrepareCallOrConstructFrame(target_fn, new_target, args);  // TODO: Exec() not available
  }
  return Cast<Object>(ReadOnlyRoots(isolate).undefined_value());
}

void RuntimeSetLiteralReceiver(
    v8::internal::Isolate* isolate,
    v8::internal::DirectHandle<v8::internal::Object> target_fn) {
  if (EnableConcolic()) {
    // TaintTracker::FromIsolate(isolate)
    //     ->Get()
    //     ->Exec()
    //     .SetLiteralReceiverOnCurrentFrame(target_fn);  // TODO: Exec() not available
  }
}

void RuntimeCheckMessageOrigin(v8::internal::Isolate* isolate,
                               v8::internal::DirectHandle<v8::internal::Object> left,
                               v8::internal::DirectHandle<v8::internal::Object> right,
                               v8::internal::Token::Value token) {
  if (!IsString(*left) || !IsString(*right)) {
    return;
  }

  DirectHandle<String> left_as_str = Cast<String>(left);
  DirectHandle<String> right_as_str = Cast<String>(right);

  IsTaintedVisitor left_visitor;
  {
    DisallowHeapAllocation no_gc;
    left_visitor.run(*left_as_str, 0, left_as_str->length());
  }

  IsTaintedVisitor right_visitor;
  {
    DisallowHeapAllocation no_gc;
    right_visitor.run(*right_as_str, 0, right_as_str->length());
  }

  bool left_has_key = false;

  TaintFlag origin_flag =
      AddFlag(kTaintFlagUntainted, TaintType::MESSAGE);  // TODO: MESSAGE_ORIGIN not available, using MESSAGE
  if (left_visitor.GetFlag() == origin_flag) {
    left_has_key = true;
  } else if (right_visitor.GetFlag() != origin_flag) {
    return;
  }

  if (left_has_key) {
    TaintTracker::FromIsolate(isolate)->Get()->PutCrossOriginMessageTable(
        isolate, Handle<String>(*left_as_str, isolate), Handle<String>(*right_as_str, isolate));
  } else {
    TaintTracker::FromIsolate(isolate)->Get()->PutCrossOriginMessageTable(
        isolate, Handle<String>(*right_as_str, isolate), Handle<String>(*left_as_str, isolate));
  }
}

v8::internal::MaybeHandle<FixedArray>
TaintTracker::Impl::GetCrossOriginMessageTable(
    v8::internal::DirectHandle<v8::internal::String> ref) {
  // TODO: taint_info() method doesn't exist in new V8, commenting out this function
  // Isolate* isolate = nullptr;
  // if (!GetIsolateFromHeapObject(*ref, &isolate)) {
  //   return MaybeDirectHandle<FixedArray>();
  // }
  // Tagged<Object> val = cross_origin_message_table_->Lookup(
  //     isolate->factory()->NewNumberFromInt64(ref->taint_info()));
  // if (!IsUndefined(val)) {
  //   if (IsFixedArray(val)) {
  //     return DirectHandle<FixedArray>(Cast<FixedArray>(val), isolate);
  //   }
  // }
  return MaybeHandle<FixedArray>();
}

void TaintTracker::Impl::PutCrossOriginMessageTable(
    v8::internal::Isolate* isolate,
    v8::internal::Handle<v8::internal::String> origin_taint,
    v8::internal::Handle<v8::internal::String> compare) {
  // TODO: taint_info() method doesn't exist in new V8, commenting out this function
  // DirectHandle<FixedArray> value = isolate->factory()->NewFixedArray(2);
  // value->set(0, *origin_taint);
  // value->set(1, *compare);
  // int64_t key = origin_taint->taint_info();
  // if (key == 0) {  // TODO: kUndefinedInstanceCounter removed in new V8
  //   // This means the key was not initialized, but there is a check.
  //   return;
  // }
  //
  // // DCHECK_NE(key, kUndefinedInstanceCounter);  // TODO: kUndefinedInstanceCounter removed
  // DCHECK_NE(key, 0);
  //
  // DirectHandle<ObjectHashTable> new_table =
  //     ObjectHashTable::Put(isolate, cross_origin_message_table_,
  //                          isolate->factory()->NewNumberFromInt64(key), value);
  //
  // if (new_table.location() != cross_origin_message_table_.location()) {
  //   cross_origin_message_table_ = DirectHandle<ObjectHashTable>::cast(
  //       isolate->global_handles()->Create(*new_table));
  // }
}

void RuntimeParameterToContextStorage(
    v8::internal::Isolate* isolate, int parameter_index, int context_slot_index,
    v8::internal::DirectHandle<v8::internal::Context> context) {
  if (EnableConcolic()) {
    // TaintTracker::FromIsolate(isolate)
    //     ->Get()
    //     ->Exec()
    //     .OnRuntimeParameterToContextStorage(parameter_index, context_slot_index,
    //                                         context);  // TODO: Exec() not available
  }
}

}  // namespace tainttracking

static_assert(static_cast<uint8_t>(::tainttracking::TaintType::UNTAINTED) == 0);
static_assert(sizeof(::tainttracking::TaintFlag) * kBitsPerByte >=
              static_cast<uint8_t>(::tainttracking::MAX_TAINT_TYPE));
