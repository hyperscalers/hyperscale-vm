;; A component that defines a resource of its own, whose destructor
;; creates and drops another handle of the same resource.
;;
;; Every edge is sound on its own. What closes the cycle is the canonical
;; ABI: dropping a handle runs the destructor, so the destructor's own
;; drop runs it again, and nothing in the call graph carries that edge —
;; `resource.drop` is a canon builtin, and the walk that bounds the stack
;; treats a builtin as a frame that leaves the instance.
;;
;; The two calls go through a table because the cycle is one the module
;; graph cannot spell directly: the destructor must exist before the
;; resource type that names it, and the builtins it calls come after.
(component
  (core module $shim
    (table (export "t") 2 2 funcref)
    (type $drop_t (func (param i32)))
    (type $new_t (func (param i32) (result i32)))
    (func (export "dtor") (param i32)
      i32.const 0
      i32.const 0
      call_indirect (type $new_t)
      i32.const 1
      call_indirect (type $drop_t))
    (func (export "go") (result i64)
      i32.const 0
      i32.const 0
      call_indirect (type $new_t)
      i32.const 1
      call_indirect (type $drop_t)
      i64.const 0))
  (core instance $s (instantiate $shim))

  (type $r (resource (rep i32) (dtor (func $s "dtor"))))
  (core func $new (canon resource.new $r))
  (core func $drop (canon resource.drop $r))

  (core module $fixups
    (import "t" "t" (table 2 2 funcref))
    (import "k" "new" (func (param i32) (result i32)))
    (import "k" "drop" (func (param i32)))
    (elem (i32.const 0) func 0 1))
  (core instance $f (instantiate $fixups
    (with "t" (instance $s))
    (with "k" (instance (export "new" (func $new)) (export "drop" (func $drop))))))

  (func (export "go") (result u64) (canon lift (core func $s "go"))))
