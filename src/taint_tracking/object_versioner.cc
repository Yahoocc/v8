#include "src/taint_tracking/object_versioner.h"

#include "src/taint_tracking-inl.h"

using namespace v8::internal;

namespace tainttracking {

ObjectSnapshot::ObjectSnapshot(Handle<Object> obj)
    : current_revision_(NO_SNAPSHOT), obj_(obj) {}

ObjectSnapshot::ObjectSnapshot(int revision, Handle<Object> obj)
    : current_revision_(revision), obj_(obj) {}

int ObjectSnapshot::GetCurrentRevision() const { return current_revision_; }

Handle<Object> ObjectSnapshot::GetObj() const { return obj_; }

TaggedObject::TaggedObject(Handle<Object> obj, int unique_id)
    : obj_(obj), unique_id_(unique_id) {}

int TaggedObject::GetUniqueId() const { return unique_id_; }

Handle<Object> TaggedObject::GetObj() const { return obj_; }

RevisionDictionary::RevisionDictionary() : dict_() {}

RevisionDictionary::RevisionDictionary(Handle<NameDictionary> dict)
    : dict_(dict) {}

RevisionDictionary::RevisionDictionary(Isolate* isolate, int size)
    : dict_(NameDictionary::New(isolate, size)) {}

MaybeHandle<Object> RevisionDictionary::Lookup(Handle<Name> key) {
  if (dict_.is_null()) return MaybeHandle<Object>();

  Isolate* isolate = key->GetIsolate();
  InternalIndex entry = dict_->FindEntry(isolate, key);
  if (entry.is_not_found()) return MaybeHandle<Object>();
  return handle(dict_->ValueAt(entry), isolate);
}

void RevisionDictionary::Put(Handle<Name> key, Handle<Object> value) {
  if (dict_.is_null()) return;
  Isolate* isolate = key->GetIsolate();
  PropertyDetails details(PropertyKind::kData, NONE,
                          PropertyConstness::kMutable);
  dict_ = NameDictionary::Add(isolate, dict_, key, value, details)
              .ToHandleChecked();
}

bool RevisionDictionary::IsValid() { return !dict_.is_null(); }

TaggedRevisedObject::TaggedRevisedObject(Handle<JSReceiver> rec, int unique_id,
                                         int revision,
                                         RevisionDictionary revisions)
    : obj_(rec),
      unique_id_(unique_id),
      revision_(revision),
      revisions_(revisions) {}

Handle<JSReceiver> TaggedRevisedObject::GetTarget() const { return obj_; }

int TaggedRevisedObject::GetId() const { return unique_id_; }

int TaggedRevisedObject::GetVersion() const { return revision_; }

const RevisionDictionary& TaggedRevisedObject::GetRevisions() const {
  return revisions_;
}

ObjectVersioner::ObjectVersioner(Isolate* isolate)
    : weak_object_map_(),
      current_version_(1),
      unique_immutable_id_(1),
      isolate_(isolate) {}

void ObjectVersioner::Init() {
  static const int kInitialObjectMapSize = 16;
  weak_object_map_.reset(new LiteralValueHolder(
      WeakHashTable::New(isolate_, kInitialObjectMapSize), isolate_));
}

void ObjectVersioner::OnSet(Handle<JSReceiver>, Handle<String>, Handle<Object>) {
  ++current_version_;
}

void ObjectVersioner::OnRemove(Handle<JSReceiver>, Handle<String>,
                               Handle<Object>) {
  ++current_version_;
}

void ObjectVersioner::OnAppend(Handle<JSReceiver>, Handle<String>) {
  ++current_version_;
}

ObjectSnapshot ObjectVersioner::TakeSnapshot(Handle<Object> target) {
  return ObjectSnapshot(current_version_, target);
}

void ObjectVersioner::PutInMap(Handle<HeapObject> target, int unique_id) {
  Handle<WeakHashTable> old_table = GetTable();
  Handle<WeakHashTable> new_table = WeakHashTable::Put(
      old_table, target, handle(Smi::FromInt(unique_id), isolate_));

  if (*new_table != *old_table) {
    weak_object_map_.reset(new LiteralValueHolder(new_table, isolate_));
  }
}

Handle<WeakHashTable> ObjectVersioner::GetTable() {
  if (!weak_object_map_) Init();
  return Handle<WeakHashTable>::cast(weak_object_map_->Get());
}

Status ObjectVersioner::MaybeSerialize(ObjectSnapshot target_snap,
                                       Ast::JsObjectValue::Builder builder,
                                       MessageHolder& holder) {
  Handle<Object> target = target_snap.GetObj();
  DCHECK(target->IsHeapObject());

  Handle<HeapObject> heap_target = Handle<HeapObject>::cast(target);
  Handle<Object> lookup_val(handle(GetTable()->Lookup(heap_target), isolate_));

  if (!lookup_val->IsTheHole(isolate_)) {
    DCHECK(lookup_val->IsSmi());
    builder.setUniqueId(Smi::ToInt(*lookup_val));
    builder.getValue().setPreviouslySerialized();
    return Status::OK;
  }

  int new_id = ++unique_immutable_id_;
  if (target->IsJSReceiver()) {
    Status status = holder.WriteConcreteReceiverSlow(
        builder, TaggedRevisedObject(Handle<JSReceiver>::cast(target), new_id,
                                     target_snap.GetCurrentRevision(),
                                     RevisionDictionary()));
    if (status == Status::OK) {
      PutInMap(heap_target, new_id);
    }
    return status;
  }

  Status status =
      holder.WriteConcreteImmutableObjectSlow(builder,
                                              TaggedObject(target, new_id));
  if (status == Status::OK) {
    PutInMap(heap_target, new_id);
  }
  return status;
}

ObjectVersioner& ObjectVersioner::FromIsolate(Isolate* isolate) {
  return TaintTracker::FromIsolate(isolate)->Get()->Versioner();
}

}  // namespace tainttracking
