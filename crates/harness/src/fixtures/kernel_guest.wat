(module
  (import "hyperscale:kernel/state" "site-get" (func $site_get (param i32 i32) (result i32)))
  (import "hyperscale:kernel/state" "site-set" (func $site_set (param i32 i32 i32 i32)))
  (import "hyperscale:kernel/state" "site-put" (func $site_put (param i32 i32 i32)))
  (import "hyperscale:kernel/state" "site-reserve-take" (func $reserve_take (param i32 i32) (result i32)))
  (import "hyperscale:kernel/state" "bucket-amount" (func $bucket_amount (param i32 i32)))
  (import "hyperscale:kernel/state" "site-count" (func $site_count (param i32 i32) (result i32)))
  (import "hyperscale:kernel/state" "site-order" (func $site_order (param i32 i32 i32 i32)))
  (import "hyperscale:kernel/state" "site-entry" (func $site_entry (param i32 i32 i32) (result i32)))
  (import "hyperscale:kernel/state" "site-entry-set" (func $site_entry_set (param i32 i32 i32 i32 i32)))
  (import "hyperscale:kernel/state" "site-insert" (func $site_insert (param i32 i32 i32 i32 i32)))
  (import "hyperscale:kernel/state" "site-remove" (func $site_remove (param i32 i32 i32)))
  (import "hyperscale:kernel/env" "clock" (func $clock (result i64)))
  (import "hyperscale:kernel/crypto" "hash" (func $hash (param i32 i32 i32)))
  (import "hyperscale:kernel/abi" "take" (func $take (param i32)))
  (import "hyperscale:kernel/abi" "reply" (func $reply (param i32 i32)))
  (import "hyperscale:kernel/abi" "answer" (func $answer (param i32 i32)))

  (memory (export "memory") 1 1)

  ;; Scratch: 0..8 four zero bytes to hash, 8..40 the digest, 64.. the
  ;; bytes a register is collected at, 128..144 an order, 512.. entry
  ;; bytes, 640..656 an order to insert at, 660 the value inserted,
  ;; 1024..1032 the answer, 1032..1036 the edge.

  ;; Answer a u64 as eight little-endian bytes, and reply with no edge.
  (func $answer_u64 (param $v i64)
    i32.const 1024
    local.get $v
    i64.store
    i32.const 1024
    i32.const 8
    call $answer
    i32.const 0
    i32.const 0
    call $reply)

  ;; Reply with one bucket as the edge.
  (func $reply_edge (param $b i32)
    i32.const 1032
    local.get $b
    i32.store
    i32.const 1032
    i32.const 1
    call $reply)

  ;; Take what the reservation grants and put it into the delta cell;
  ;; answer the low half of what moved.
  (func (export "transfer") (param $a i32) (param $b i32)
    (local $funds i32)
    local.get $a
    i32.const 0
    call $reserve_take
    local.set $funds
    local.get $funds
    i32.const 8
    call $bucket_amount
    local.get $b
    i32.const 0
    local.get $funds
    call $site_put
    i32.const 8
    i64.load
    call $answer_u64)

  ;; The digest of four zero bytes of scratch, folded to its first
  ;; byte: the host's hash function is the one kernel interface a guest
  ;; cannot check for itself, so what this compares is that both
  ;; runtimes call the same one and write its result the same way.
  (func (export "hash-tag")
    i32.const 0
    i32.const 4
    i32.const 8
    call $hash
    i32.const 8
    i32.load8_u
    i64.extend_i32_u
    call $answer_u64)

  ;; The cell's length plus the clock.
  (func (export "peek") (param $c i32)
    (local $len i32)
    local.get $c
    i32.const 0
    call $site_get
    local.set $len
    i32.const 64
    call $take
    local.get $len
    i64.extend_i32_u
    call $clock
    i64.add
    call $answer_u64)

  ;; Bump the cell's first byte and write it back; answer its length.
  (func (export "rmw") (param $c i32)
    (local $len i32)
    local.get $c
    i32.const 0
    call $site_get
    local.set $len
    i32.const 64
    call $take
    local.get $len
    if
      i32.const 64
      i32.const 64
      i32.load8_u
      i32.const 1
      i32.add
      i32.store8
    end
    local.get $c
    i32.const 0
    i32.const 64
    local.get $len
    call $site_set
    local.get $len
    i64.extend_i32_u
    call $answer_u64)

  ;; Fold every entry's first byte and every order's first byte.
  (func (export "scan-sum") (param $r i32)
    (local $n i32) (local $i i32) (local $sum i64)
    local.get $r
    i32.const 0
    call $site_count
    local.set $n
    block
      loop
        local.get $i
        local.get $n
        i32.ge_u
        br_if 1
        i32.const 64
        i32.const 0
        i32.store8
        local.get $r
        i32.const 0
        local.get $i
        call $site_entry
        drop
        i32.const 64
        call $take
        local.get $sum
        i32.const 64
        i32.load8_u
        i64.extend_i32_u
        i64.add
        local.set $sum
        local.get $r
        i32.const 0
        local.get $i
        i32.const 128
        call $site_order
        local.get $sum
        i32.const 128
        i32.load8_u
        i64.extend_i32_u
        i64.add
        local.set $sum
        local.get $i
        i32.const 1
        i32.add
        local.set $i
        br 0
      end
    end
    local.get $sum
    call $answer_u64)

  ;; Rewrite entry zero and remove the last entry; answer the count seen.
  (func (export "fill") (param $r i32)
    (local $n i32)
    local.get $r
    i32.const 0
    call $site_count
    local.set $n
    local.get $n
    if
      i32.const 512
      i32.const 9
      i32.store8
      i32.const 513
      i32.const 9
      i32.store8
      local.get $r
      i32.const 0
      i32.const 0
      i32.const 512
      i32.const 2
      call $site_entry_set
      local.get $r
      i32.const 0
      local.get $n
      i32.const 1
      i32.sub
      call $site_remove
    end
    local.get $n
    i64.extend_i32_u
    call $answer_u64)

  ;; Insert one byte at order 42; answer the count afterwards.
  (func (export "place") (param $r i32)
    i32.const 640
    i64.const 42
    i64.store
    i32.const 648
    i64.const 0
    i64.store
    i32.const 660
    i32.const 7
    i32.store8
    local.get $r
    i32.const 0
    i32.const 640
    i32.const 660
    i32.const 1
    call $site_insert
    local.get $r
    i32.const 0
    call $site_count
    i64.extend_i32_u
    call $answer_u64)

  ;; Read bytes through a site the declaration lent as a commutative
  ;; movement, which the capability refuses.
  (func (export "escape") (param $c i32)
    local.get $c
    i32.const 0
    call $site_get
    i64.extend_i32_u
    call $answer_u64)

  ;; A site index the session never seated.
  (func (export "forge")
    i32.const 9999
    i32.const 0
    call $site_get
    i64.extend_i32_u
    call $answer_u64)

  ;; The site index itself, as the body sees it.
  (func (export "handle-value") (param $c i32)
    local.get $c
    i64.extend_i32_u
    call $answer_u64)

  ;; Read whatever read cell it is handed; answer its length.
  (func (export "read-value") (param $c i32)
    (local $len i32)
    local.get $c
    i32.const 0
    call $site_get
    local.set $len
    i32.const 64
    call $take
    local.get $len
    i64.extend_i32_u
    call $answer_u64)

  ;; Collect the answer register twice: the second collect finds it
  ;; cleared, which is the register rule's own violation.
  (func (export "retake") (param $c i32)
    local.get $c
    i32.const 0
    call $site_get
    drop
    i32.const 64
    call $take
    i32.const 64
    call $take
    i64.const 0
    call $answer_u64)

  ;; Remove past the interval's last entry, a deterministic refusal.
  (func (export "no-such-entry") (param $r i32)
    local.get $r
    i32.const 0
    i32.const 99
    call $site_remove
    i64.const 0
    call $answer_u64))
