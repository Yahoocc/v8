# AST Serialization Porting Ledger

This ledger records the current forward-port state of the AST serialization
slice and its adjacent taint-tracking schema files.

The implementation was updated by merging ideas from:

- `ast_serialization.patch`, which contains the original patch-series history.
- The provided `ast.capnp`, which is the current schema snapshot used by the
  forward-ported serializer implementation.
- The late-file reconstructions recovered from `v8_patch.txt` for
  `logrecord.capnp` and the old `ast_serialization.h` history.
- The local V8 14.8 AST headers, which determine the modern visitor API and the
  currently available node accessors.

## Related File Status

- Path: `src/taint_tracking/ast_serialization.h`
  Status: old patch series created this file; upstream V8 14.8 still has no
  native equivalent.
  Current port action: kept as a small modern header that only exposes the
  already-forward-ported serializer entry point.
  Uncertain area: the late patch-series concolic runtime API from this header
  was not restored because its dependent files are still absent in the modern
  tree.

- Path: `src/taint_tracking/protos/ast.capnp`
  Status: old patch series created this file; upstream V8 14.8 has no native
  equivalent.
  Current port action: created this file in the modern tree from the provided
  schema snapshot, because the current `ast_serialization.cc` was already
  aligned against that snapshot.
  Uncertain area: later patch-series schema additions such as richer
  `ClassLiteral`, `Await`, `YieldStar`, `Hash`, `withCall`, and `module`
  support were not merged into the active serializer path yet.

- Path: `src/taint_tracking/protos/logrecord.capnp`
  Status: old patch series created this file; upstream V8 14.8 has no native
  equivalent.
  Current port action: created this file in the modern tree from a late
  patch-series reconstruction so the broader taint-log schema is preserved.
  Uncertain area: this schema has not been build-verified in the modern tree
  yet, because the Cap'n Proto generation path and downstream consumers are not
  wired back up.

- Path: `src/full-codegen/full-codegen.cc`
  Status: old upstream V8 file that the NDSS patch series modified heavily.
  Current V8 14.8 state: this file no longer exists.
  Current port action: no replacement file was created, because forcing a fake
  `full-codegen.cc` into the modern tree would be misleading.
  Uncertain area: the old full-codegen hooks will need to migrate into modern
  bytecode/interpreter/baseline/compiler hook points, and that landing zone is
  still a manual follow-up item.

## API Change Mapping

- Old interface or assumption: `AstVisitor<Subclass>` plus
  `DEFINE_AST_REWRITER_SUBCLASS_MEMBERS()`
  V8 14.8 adaptation: `AstVisitor<AstSerializer>` plus
  `DEFINE_AST_VISITOR_SUBCLASS_MEMBERS()`
  Notes: aligned with the modern visitor API.

- Old interface or assumption: `FunctionLiteral::function_type()`
  V8 14.8 adaptation: `FunctionLiteral::syntax_kind()`
  Notes: `FunctionSyntaxKind::kWrapped` is still kept as an explicit TODO
  fallback.

- Old interface or assumption: legacy `FunctionKind` switch from the original
  patch
  V8 14.8 adaptation: merged and extended modern `FunctionKind` switch
  Notes: current code handles renamed constructor kinds and modern enum members,
  while keeping lossy cases as TODOs.

- Old interface or assumption: `ZoneList<Statement*>` and
  `ZoneList<Expression*>`
  V8 14.8 adaptation: `ZonePtrList<Statement>` and `ZonePtrList<Expression>`
  Notes: current AST containers use pointer lists instead of the old zone-list
  API.

- Old interface or assumption: `ZoneList<Declaration*>`
  V8 14.8 adaptation: `Declaration::List`
  Notes: declaration traversal now follows the modern declaration container.

- Old interface or assumption: declaration serialization directly from old
  declaration proxy and scope accessors
  V8 14.8 adaptation: `Declaration::var()` plus nested-scope handling
  Notes: resolved proxy information is rebuilt from the bound `Variable`.

- Old interface or assumption: `Literal::raw_value()` and `AstValue`
  V8 14.8 adaptation: `Literal::type()` plus typed literal accessors
  Notes: the serializer now branches through `AsSmiLiteral()`, `AsNumber()`,
  `AsRawString()`, `AsConsString()`, and `AsBooleanLiteral()`.

- Old interface or assumption: flat `JsString` payload with direct
  `content/isOneByte`
  V8 14.8 adaptation: `JsString.segments`
  Notes: this follows the provided `ast.capnp`, which is the active schema
  reference for the current port.

- Old interface or assumption: cons strings should be flattened into one legacy
  string payload
  V8 14.8 adaptation: emit one Cap'n Proto segment per raw-string segment
  Notes: this matches the provided `ast.capnp` better than the earlier
  flattening assumption.

- Old interface or assumption: `CallRuntime` stores the runtime target directly
  on `fn`
  V8 14.8 adaptation: `CallRuntime.info.fn`
  Notes: this was corrected to match the provided schema layout.

- Old interface or assumption: `WithStatement` only serializes scope and
  expression
  V8 14.8 adaptation: `WithStatement.statement` is serialized too
  Notes: this was merged from the patch-series history.

- Old interface or assumption: calls always serialize as
  `CallType::UNKNOWN`
  V8 14.8 adaptation: map `Call::GetCallType()` into the legacy enum set
  Notes: the mapping is now constrained by what the provided `ast.capnp`
  actually defines.

- Old interface or assumption: unsupported modern nodes can be left with empty
  visitors
  V8 14.8 adaptation: emit explicit placeholder payloads before marking TODO
  Notes: this avoids silently dropping modern AST nodes during serialization.

- Old interface or assumption: `ClassLiteral`, `Spread`, and
  `ImportCallExpression` have usable payload fields in the active schema
  V8 14.8 adaptation: treat them according to the provided `ast.capnp`
  Notes: `ClassLiteral` and `Spread` are only empty schema shells there, and
  `ImportCallExpression` is absent entirely.

- Old interface or assumption: `VariableMode::UNKNOWN`,
  `Variable::Location::MODULE`, and `Call::CallType::WITH_CALL` exist in the
  active schema
  V8 14.8 adaptation: fall back to TODO-guided compatibility handling
  Notes: those entries do not exist in the provided `ast.capnp`, so the code
  now treats them as unsupported schema gaps rather than valid builder targets.

## Resolved In This Revision

- Merged the original patch's function-literal, declaration, statement, and
  expression visitor logic into the modernized serializer where the logic still
  has a direct V8 14.8 equivalent.

- Changed raw-string serialization to `JsString.segments`, matching the
  provided `ast.capnp`.

- Changed cons-string serialization to multi-segment output, again matching the
  provided `ast.capnp`.

- Kept the patch-derived `WithStatement.statement` export instead of dropping
  the body.

- Merged patch-derived `Call::CallType` handling instead of hardcoding
  `UNKNOWN` for every call.

- Corrected `CallRuntime` to write through `initInfo().getFn()`, which matches
  the provided schema.

- Added explicit placeholder emission for unsupported modern nodes such as
  `Await`, `NaryOperation`, `ConditionalChain`, `OptionalChain`,
  `TemplateLiteral`, and `YieldStar`.

- Rebased the serializer's schema assumptions away from later patch-history
  guesses and back onto the provided `ast.capnp` where those two sources
  conflict.

## Remaining TODO Checklist

- `src/taint_tracking/ast_serialization.cc:107`
  `FunctionSyntaxKind::kWrapped` still has no confirmed legacy schema mapping.

- `src/taint_tracking/ast_serialization.cc:127`
  Static concise methods still lose static metadata when downgraded to the
  legacy `CONCISE_METHOD` enum.

- `src/taint_tracking/ast_serialization.cc:135`
  Static concise generator methods still lose static metadata.

- `src/taint_tracking/ast_serialization.cc:143`
  Static getters still lose static metadata.

- `src/taint_tracking/ast_serialization.cc:151`
  Static setters still lose static metadata.

- `src/taint_tracking/ast_serialization.cc:172`
  Static async concise methods still lose static metadata.

- `src/taint_tracking/ast_serialization.cc:187`
  Modern `FunctionKind` values such as modules, async generators, and class
  initializers still do not have a lossless legacy mapping.

- `src/taint_tracking/ast_serialization.cc:215`
  Modern `VariableMode` values such as `kUsing`, `kAwaitUsing`, and private
  accessor modes are not representable in the provided `ast.capnp`.

- `src/taint_tracking/ast_serialization.cc:234`
  `VariableLocation::MODULE` does not exist in the provided `ast.capnp`.

- `src/taint_tracking/ast_serialization.cc:237`
  `VariableLocation::REPL_GLOBAL` also has no exact schema equivalent.

- `src/taint_tracking/ast_serialization.cc:248`
  `Call::CallType::WITH_CALL` is present in modern V8 but absent from the
  provided `ast.capnp`.

- `src/taint_tracking/ast_serialization.cc:370`
  Modern nullish and logical-assignment tokens such as `??`, `??=`,
  logical-or-assignment, and logical-and-assignment still have no legacy token
  enum entry.

- `src/taint_tracking/ast_serialization.cc:381`
  Assignment store-mode accessors are gone in modern V8, so serializer output
  still uses a fallback store mode.

- `src/taint_tracking/ast_serialization.cc:392`
  Count-operation store-mode accessors are also gone in modern V8, so serializer
  output still uses a fallback store mode.

- `src/taint_tracking/ast_serialization.cc:420`
  `SLOPPY_BLOCK_FUNCTION_VARIABLE` and `SLOPPY_FUNCTION_NAME_VARIABLE` still
  have no exact legacy `Variable::Kind` equivalent.

- `src/taint_tracking/ast_serialization.cc:620`
  Modern `ForOfStatement` no longer exposes the old desugared iterator
  temporaries required by the legacy schema payload.

- `src/taint_tracking/ast_serialization.cc:714`
  `InitializeClassMembersStatement` still has no legacy schema node.

- `src/taint_tracking/ast_serialization.cc:721`
  `InitializeClassStaticElementsStatement` still has no legacy schema node.

- `src/taint_tracking/ast_serialization.cc:727`
  `AutoAccessorGetterBody` still has no legacy schema node.

- `src/taint_tracking/ast_serialization.cc:733`
  `AutoAccessorSetterBody` still has no legacy schema node.

- `src/taint_tracking/ast_serialization.cc:773`
  `ObjectLiteralProperty::SPREAD` still has no exact `LiteralProperty::Kind`
  in the provided schema.

- `src/taint_tracking/ast_serialization.cc:800`
  `Assignment::IsUninitialized()` no longer exists in modern V8, so the legacy
  `isUninitializedField` bit still falls back to `false`.

- `src/taint_tracking/ast_serialization.cc:819`
  `Await` is still unsupported because the provided `ast.capnp` has no `Await`
  node.

- `src/taint_tracking/ast_serialization.cc:831`
  `NaryOperation` is still unsupported because the provided `ast.capnp` has no
  matching node.

- `src/taint_tracking/ast_serialization.cc:845`
  `SuperCallForwardArgs` is still unsupported because the provided `ast.capnp`
  has no matching node.

- `src/taint_tracking/ast_serialization.cc:874`
  `ClassLiteral` exists only as an empty shell in the provided `ast.capnp`, so
  its payload fields are still unresolved.

- `src/taint_tracking/ast_serialization.cc:887`
  `ConditionalChain` is still unsupported because the provided `ast.capnp` has
  no matching node.

- `src/taint_tracking/ast_serialization.cc:920`
  `GetTemplateObject` is still unsupported because the provided `ast.capnp` has
  no matching node.

- `src/taint_tracking/ast_serialization.cc:926`
  `ImportCallExpression` is still unsupported because the provided `ast.capnp`
  has no `ImportCall` node at all.

- `src/taint_tracking/ast_serialization.cc:974`
  `BigInt` literal payloads still have no dedicated field in the provided
  literal union.

- `src/taint_tracking/ast_serialization.cc:991`
  `OptionalChain` is still unsupported because the provided `ast.capnp` has no
  matching node.

- `src/taint_tracking/ast_serialization.cc:998`
  `Property::is_for_call()` and `Property::IsStringAccess()` were removed from
  the modern AST API, so those schema bits still fall back to `false`.

- `src/taint_tracking/ast_serialization.cc:1008`
  `Spread` exists only as an empty shell in the provided `ast.capnp`, so its
  payload remains unresolved.

- `src/taint_tracking/ast_serialization.cc:1031`
  `TemplateLiteral` is still unsupported because the provided `ast.capnp` has
  no matching node.

- `src/taint_tracking/ast_serialization.cc:1059`
  `Yield` has a schema node in the provided `ast.capnp`, but modern V8 no
  longer exposes the old generator-object accessor used by the original patch.

- `src/taint_tracking/ast_serialization.cc:1064`
  `YieldStar` is still unsupported because the provided `ast.capnp` has no
  dedicated node for it.

## Notes

- The current serializer still carries a structural mismatch with the provided
  `ast.capnp`: the C++ file is written around a generic `current_.getNodeVal()`
  workflow, while the provided schema is split across `Expression`,
  `Statement`, `Declaration`, `FunctionLiteralNode`, `BlockNode`, and
  `VariableProxyNode`. This revision merged logic and schema fixes first, but a
  full builder-layer rewrite is still the next major cleanup step.

- The checked-in `src/taint_tracking/protos/ast.capnp` is intentionally the
  earlier provided schema snapshot, not the late reconstructed schema, because
  the current `ast_serialization.cc` was already ported against that earlier
  layout. This keeps the serializer and schema on the same provisional footing.

- The checked-in `src/taint_tracking/protos/logrecord.capnp` comes from a later
  patch-series reconstruction. That file was preserved now because it is
  additive and useful as a reference even before the downstream logging path is
  fully rebuilt.
