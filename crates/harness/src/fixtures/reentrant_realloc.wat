(component
  (import "hyperscale:kernel/env" (instance $env
    (export "randomness" (func (result (list u8))))))
  (alias export $env "randomness" (func $randomness))

  (core module $shim
    (type $sig (func (param i32)))
    (table (export "t") 1 1 funcref)
    (func (export "stub") (param i32)
      local.get 0
      i32.const 0
      call_indirect (type $sig)))
  (core instance $is (instantiate $shim))

  (core module $alloc
    (import "shim" "stub" (func $stub (param i32)))
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
      i32.const 16
      call $stub
      local.get $ret))
  (core instance $a (instantiate $alloc (with "shim" (instance $is))))

  (core func $randomness_l (canon lower (func $randomness)
    (memory $a "mem") (realloc (func $a "realloc"))))

  (core module $fixups
    (import "shim" "t" (table $t 1 1 funcref))
    (import "k" "randomness" (func $target (param i32)))
    (elem (table $t) (i32.const 0) func $target))
  (core instance (instantiate $fixups
    (with "shim" (instance $is))
    (with "k" (instance (export "randomness" (func $randomness_l))))))

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
