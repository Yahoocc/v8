// Copyright 2026 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDE_V8_TESTING_H_
#define INCLUDE_V8_TESTING_H_

#include "v8config.h"  // NOLINT(build/include_directory)

namespace v8 {

// Compatibility shim for older internal API code that still references
// v8::Testing::StressType.
class V8_EXPORT Testing {
 public:
  enum class StressType {
    kNoStress
  };
};

}  // namespace v8

#endif  // INCLUDE_V8_TESTING_H_
