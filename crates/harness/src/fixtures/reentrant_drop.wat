(component
  (import "hyperscale:kernel/env" (instance $env
    (export "randomness" (func (result (list u8))))))
  (alias export $env "randomness" (func $randomness))
  (import "hyperscale:kernel/state" (instance $state
    (export "read-cell" (type $rc (sub resource)))))
  (alias export $state "read-cell" (type $rcell))

  (core func $drop (canon resource.drop $rcell))

  (core module $alloc
    (import "k" "drop" (func $drop (param i32)))
    (memory (export "mem") 4 4)
    (global $next (mut i32) (i32.const 1024))
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      (local $ret i32)
      global.get $next
      local.set $ret
      global.get $next
      local.get 3
      i32.add
      global.set $next
      i32.const 0
      call $drop
      local.get $ret))
  (core instance $a (instantiate $alloc
    (with "k" (instance (export "drop" (func $drop))))))

  (core func $randomness_l (canon lower (func $randomness)
    (memory $a "mem") (realloc (func $a "realloc"))))

  (core module $main
    (import "env" "mem" (memory 4 4))
    (import "k" "randomness" (func $randomness (param i32)))
    (func (export "draw") (result i64)
      i32.const 8
      call $randomness
      i32.const 8
      i32.load
      i64.extend_i32_u))
  (core instance $m (instantiate $main
    (with "env" (instance $a))
    (with "k" (instance (export "randomness" (func $randomness_l))))))

  (func (export "draw") (result u64) (canon lift (core func $m "draw"))))
