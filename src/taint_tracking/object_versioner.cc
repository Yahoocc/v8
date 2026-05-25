#include "src/taint_tracking/object_versioner.h"

#include "src/taint_tracking-inl.h"
#include "src/objects/dictionary-inl.h"
#include "src/objects/hash-table-inl.h"
#include "src/handles/maybe-handles-inl.h"

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

RevisionDictionary::RevisionDictionary() : dict_(), isolate_(nullptr) {}

RevisionDictionary::RevisionDictionary(Handle<NameDictionary> dict)
    : dict_(dict), isolate_(nullptr) {}

RevisionDictionary::RevisionDictionary(Isolate* isolate, int size)
    : dict_(NameDictionary::New(isolate, size)), isolate_(isolate) {}

MaybeHandle<Object> RevisionDictionary::Lookup(Handle<Name> key) {
  if (dict_.is_null() || !isolate_) return MaybeHandle<Object>();

  InternalIndex entry = dict_->FindEntry(isolate_, key);
  if (entry.is_not_found()) return MaybeHandle<Object>();
  return MaybeHandle<Object>(dict_->ValueAt(entry), isolate_);
}

void RevisionDictionary::Put(Handle<Name> key, Handle<Object> value) {
  if (dict_.is_null() || !isolate_) return;
  PropertyDetails details(PropertyKind::kData, PropertyAttributes::NONE,
                          PropertyConstness::kMutable);
  dict_ = NameDictionary::Add(isolate_, dict_, key, value, details)
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
      EphemeronHashTable::New(isolate_, kInitialObjectMapSize), isolate_));
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
  Handle<EphemeronHashTable> old_table = GetTable();
  DirectHandle<Smi> smi_value(Smi::FromInt(unique_id), isolate_);
  Handle<EphemeronHashTable> new_table = EphemeronHashTable::Put(
      isolate_, old_table, target, smi_value);

  if (*new_table != *old_table) {
    weak_object_map_.reset(new LiteralValueHolder(new_table, isolate_));
  }
}

Handle<EphemeronHashTable> ObjectVersioner::GetTable() {
  if (!weak_object_map_) Init();
  return Cast<EphemeronHashTable>(weak_object_map_->Get());
}

Status ObjectVersioner::MaybeSerialize(ObjectSnapshot target_snap,
                                       Ast::JsObjectValue::Builder builder,
                                       MessageHolder& holder) {
  Handle<Object> target = target_snap.GetObj();
  DCHECK((*target).IsHeapObject());

  Handle<HeapObject> heap_target = Cast<HeapObject>(target);
  Tagged<Object> lookup_result = GetTable()->Lookup(heap_target);

  if (!IsTheHole(lookup_result, isolate_)) {
    DCHECK(IsSmi(lookup_result));
    builder.setUniqueId(Smi::ToInt(lookup_result));
    builder.getValue().setPreviouslySerialized();
    return Status::OK;
  }

  int new_id = ++unique_immutable_id_;
  if (IsJSReceiver(*target)) {
    Status status = holder.WriteConcreteReceiverSlow(
        builder, TaggedRevisedObject(Cast<JSReceiver>(target), new_id,
                                     target_snap.GetCurrentRevision(),
                                     RevisionDictionary()),
        isolate_);
    if (status == Status::OK) {
      PutInMap(heap_target, new_id);
    }
    return status;
  }

  Status status =
      holder.WriteConcreteImmutableObjectSlow(builder,
                                              TaggedObject(target, new_id),
                                              isolate_);
  if (status == Status::OK) {
    PutInMap(heap_target, new_id);
  }
  return status;
}

ObjectVersioner& ObjectVersioner::FromIsolate(Isolate* isolate) {
  return TaintTracker::FromIsolate(isolate)->Get()->Versioner();
}

}  // namespace tainttracking
