#ifndef OBJECT_VERSIONER_H
#define OBJECT_VERSIONER_H

#include <memory>

#include "src/objects.h"
#include "src/taint_tracking/symbolic_state.h"

namespace tainttracking {

class MessageHolder;
class ObjectSnapshot;
class RevisionDictionary;
class TaggedObject;
class TaggedRevisedObject;

class RevisionInfo {
 public:
  enum Type { APPEND, DELETE, REPLACE };
};

class ImmutableRevisionList {
 public:
  static const int NO_REVISION = -1;
};

class ObjectVersioner {
 public:
  ObjectVersioner() = delete;
  explicit ObjectVersioner(v8::internal::Isolate* isolate);

  void Init();

  void OnSet(v8::internal::Handle<v8::internal::JSReceiver> target,
             v8::internal::Handle<v8::internal::String> key,
             v8::internal::Handle<v8::internal::Object> prev_value);
  void OnRemove(v8::internal::Handle<v8::internal::JSReceiver> target,
                v8::internal::Handle<v8::internal::String> key,
                v8::internal::Handle<v8::internal::Object> prev_value);
  void OnAppend(v8::internal::Handle<v8::internal::JSReceiver> target,
                v8::internal::Handle<v8::internal::String> key);

  ObjectSnapshot TakeSnapshot(v8::internal::Handle<v8::internal::Object> target);

  Status MaybeSerialize(ObjectSnapshot snapshot,
                        Ast::JsObjectValue::Builder builder,
                        MessageHolder& holder);

  static ObjectVersioner& FromIsolate(v8::internal::Isolate* isolate);

 private:
  void PutInMap(v8::internal::Handle<v8::internal::HeapObject> target,
                int unique_id);
  v8::internal::Handle<v8::internal::WeakHashTable> GetTable();

  std::unique_ptr<LiteralValueHolder> weak_object_map_;
  int current_version_;
  int unique_immutable_id_;
  v8::internal::Isolate* isolate_;
};

}  // namespace tainttracking

#endif
