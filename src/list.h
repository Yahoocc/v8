// Copyright 2026 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_LIST_H_
#define V8_LIST_H_

#include <vector>

namespace v8 {
namespace internal {

// Minimal compatibility wrapper for legacy List<T> call sites that were not
// migrated alongside newer V8 container changes.
template <typename T>
class List {
 public:
  List() = default;
  explicit List(int capacity) { Initialize(capacity); }

  void Initialize(int capacity) {
    data_.clear();
    if (capacity > 0) data_.reserve(capacity);
  }

  void Free() {
    data_.clear();
    data_.shrink_to_fit();
  }

  int length() const { return static_cast<int>(data_.size()); }
  bool is_empty() const { return data_.empty(); }

  void Add(const T& value) { data_.push_back(value); }

  T RemoveLast() {
    T value = data_.back();
    data_.pop_back();
    return value;
  }

  T& last() { return data_.back(); }
  const T& last() const { return data_.back(); }

  T& operator[](int index) { return data_[index]; }
  const T& operator[](int index) const { return data_[index]; }

 private:
  std::vector<T> data_;
};

}  // namespace internal
}  // namespace v8

#endif  // V8_LIST_H_
