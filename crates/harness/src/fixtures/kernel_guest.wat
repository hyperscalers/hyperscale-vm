(component
  (import "hyperscale:kernel/state" (instance $state
    (export "read-cell" (type $rc (sub resource)))
    (export "locked-cell" (type $sc (sub resource)))
    (export "write-cell" (type $wc (sub resource)))
    (export "delta-cell" (type $dc (sub resource)))
    (export "reserve-cell" (type $vc (sub resource)))
    (export "range-read" (type $rr (sub resource)))
    (export "range-write" (type $rw (sub resource)))
    (type $amt_decl (record (field "low" u64) (field "high" u64)))
    (export "amount" (type $amt (eq $amt_decl)))
    (export "read-cell-get" (func (param "c" (borrow $rc)) (result (list u8))))
    (export "locked-cell-get" (func (param "c" (borrow $sc)) (result (list u8))))
    (export "write-cell-get" (func (param "c" (borrow $wc)) (result (list u8))))
    (export "write-cell-set" (func (param "c" (borrow $wc)) (param "value" (list u8))))
    (export "bucket" (type $bk (sub resource)))
    (export "delta-cell-put" (func (param "c" (borrow $dc)) (param "funds" (own $bk))))
    (export "reserve-cell-take" (func (param "c" (borrow $vc)) (result (own $bk))))
    (export "bucket-amount" (func (param "b" (borrow $bk)) (result $amt)))
    (export "range-read-count" (func (param "r" (borrow $rr)) (result u32)))
    (export "range-read-order" (func (param "r" (borrow $rr)) (param "index" u32) (result $amt)))
    (export "range-read-entry" (func (param "r" (borrow $rr)) (param "index" u32) (result (list u8))))
    (export "range-write-count" (func (param "r" (borrow $rw)) (result u32)))
    (export "range-write-set" (func (param "r" (borrow $rw)) (param "index" u32) (param "value" (list u8))))
    (export "range-write-insert" (func (param "r" (borrow $rw)) (param "order" $amt) (param "value" (list u8))))
    (export "range-write-remove" (func (param "r" (borrow $rw)) (param "index" u32)))))
  (import "hyperscale:kernel/env" (instance $env
    (export "clock" (func (result u64)))))
  (import "hyperscale:kernel/crypto" (instance $crypto
    (export "hash" (func (param "data" (list u8)) (result (list u8))))))

  (alias export $state "read-cell" (type $rcell))
  (alias export $state "locked-cell" (type $scell))
  (alias export $state "write-cell" (type $wcell))
  (alias export $state "delta-cell" (type $dcell))
  (alias export $state "reserve-cell" (type $vcell))
  (alias export $state "range-read" (type $rrange))
  (alias export $state "range-write" (type $wrange))
  (alias export $state "read-cell-get" (func $read_get))
  (alias export $state "locked-cell-get" (func $locked_get))
  (alias export $state "write-cell-get" (func $write_get))
  (alias export $state "write-cell-set" (func $write_set))
  (alias export $state "delta-cell-put" (func $delta_put))
  (alias export $state "reserve-cell-take" (func $reserve_take))
  (alias export $state "bucket-amount" (func $bucket_amount))
  (alias export $state "range-read-count" (func $rr_count))
  (alias export $state "range-read-order" (func $rr_order))
  (alias export $state "range-read-entry" (func $rr_entry))
  (alias export $state "range-write-count" (func $rw_count))
  (alias export $state "range-write-set" (func $rw_set))
  (alias export $state "range-write-insert" (func $rw_insert))
  (alias export $state "range-write-remove" (func $rw_remove))
  (alias export $env "clock" (func $clock))
  (alias export $crypto "hash" (func $hash))

  (core module $alloc
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
      local.get $ret))
  (core instance $a (instantiate $alloc))

  (core func $read_get_l (canon lower (func $read_get)
    (memory $a "mem") (realloc (func $a "realloc"))))
  (core func $locked_get_l (canon lower (func $locked_get)
    (memory $a "mem") (realloc (func $a "realloc"))))
  (core func $write_get_l (canon lower (func $write_get)
    (memory $a "mem") (realloc (func $a "realloc"))))
  (core func $write_set_l (canon lower (func $write_set)
    (memory $a "mem")))
  (core func $delta_put_l (canon lower (func $delta_put)))
  (core func $reserve_take_l (canon lower (func $reserve_take)))
  (core func $bucket_amount_l (canon lower (func $bucket_amount)
    (memory $a "mem")))
  (core func $rr_count_l (canon lower (func $rr_count)))
  (core func $rr_order_l (canon lower (func $rr_order)
    (memory $a "mem") (realloc (func $a "realloc"))))
  (core func $rr_entry_l (canon lower (func $rr_entry)
    (memory $a "mem") (realloc (func $a "realloc"))))
  (core func $rw_count_l (canon lower (func $rw_count)))
  (core func $rw_set_l (canon lower (func $rw_set)
    (memory $a "mem")))
  (core func $rw_insert_l (canon lower (func $rw_insert)
    (memory $a "mem")))
  (core func $rw_remove_l (canon lower (func $rw_remove)))
  (core func $clock_l (canon lower (func $clock)))
  (core func $hash_l (canon lower (func $hash)
    (memory $a "mem") (realloc (func $a "realloc"))))
  (core func $drop_r (canon resource.drop $rcell))
  (core func $drop_s (canon resource.drop $scell))
  (core func $drop_w (canon resource.drop $wcell))
  (core func $drop_d (canon resource.drop $dcell))
  (core func $drop_v (canon resource.drop $vcell))
  (core func $drop_rr (canon resource.drop $rrange))
  (core func $drop_rw (canon resource.drop $wrange))

  (core module $m
    (import "env" "mem" (memory 4 4))
    (import "k" "read-get" (func $read_get (param i32 i32)))
    (import "k" "locked-get" (func $locked_get (param i32 i32)))
    (import "k" "write-get" (func $write_get (param i32 i32)))
    (import "k" "write-set" (func $write_set (param i32 i32 i32)))
    (import "k" "delta-put" (func $delta_put (param i32 i32)))
    (import "k" "reserve-take" (func $reserve_take (param i32) (result i32)))
    (import "k" "bucket-amount" (func $bucket_amount (param i32 i32)))
    (import "k" "rr-count" (func $rr_count (param i32) (result i32)))
    (import "k" "rr-order" (func $rr_order (param i32 i32 i32)))
    (import "k" "rr-entry" (func $rr_entry (param i32 i32 i32)))
    (import "k" "rw-count" (func $rw_count (param i32) (result i32)))
    (import "k" "rw-set" (func $rw_set (param i32 i32 i32 i32)))
    (import "k" "rw-insert" (func $rw_insert (param i32 i64 i64 i32 i32)))
    (import "k" "rw-remove" (func $rw_remove (param i32 i32)))
    (import "k" "clock" (func $clock (result i64)))
    (import "k" "hash" (func $hash (param i32 i32 i32)))
    (import "k" "drop-r" (func $drop_r (param i32)))
    (import "k" "drop-s" (func $drop_s (param i32)))
    (import "k" "drop-w" (func $drop_w (param i32)))
    (import "k" "drop-d" (func $drop_d (param i32)))
    (import "k" "drop-v" (func $drop_v (param i32)))
    (import "k" "drop-rr" (func $drop_rr (param i32)))
    (import "k" "drop-rw" (func $drop_rw (param i32)))

    (func (export "transfer") (param i32 i32) (result i64)
      (local $funds i32)
      local.get 0
      call $reserve_take
      local.set $funds
      local.get $funds
      i32.const 8
      call $bucket_amount
      i32.const 8
      i64.load
      local.get 1
      local.get $funds
      call $delta_put
      local.get 0
      call $drop_v
      local.get 1
      call $drop_d)

    ;; The digest of four zero bytes of scratch, folded to its first
    ;; byte: the host's hash function is the one kernel interface a guest
    ;; cannot check for itself, so what this compares is that both
    ;; runtimes call the same one and lift its result the same way.
    (func (export "hash-tag") (result i64)
      i32.const 0
      i32.const 4
      i32.const 8
      call $hash
      i32.const 8
      i32.load
      i32.load8_u
      i64.extend_i32_u)

    (func (export "peek") (param i32) (result i64)
      local.get 0
      i32.const 8
      call $locked_get
      i32.const 12
      i32.load
      i64.extend_i32_u
      call $clock
      i64.add
      local.get 0
      call $drop_s)

    (func (export "rmw") (param i32) (result i64)
      (local $ptr i32) (local $len i32)
      local.get 0
      i32.const 8
      call $write_get
      i32.const 8
      i32.load
      local.set $ptr
      i32.const 12
      i32.load
      local.set $len
      local.get $len
      if
        local.get $ptr
        local.get $ptr
        i32.load8_u
        i32.const 1
        i32.add
        i32.store8
      end
      local.get 0
      local.get $ptr
      local.get $len
      call $write_set
      local.get $len
      i64.extend_i32_u
      local.get 0
      call $drop_w)

    (func (export "scan-sum") (param i32) (result i64)
      (local $n i32) (local $i i32) (local $sum i64)
      local.get 0
      call $rr_count
      local.set $n
      block
        loop
          local.get $i
          local.get $n
          i32.ge_u
          br_if 1
          local.get 0
          local.get $i
          i32.const 8
          call $rr_entry
          local.get $sum
          i32.const 8
          i32.load
          i32.load8_u
          i64.extend_i32_u
          i64.add
          local.set $sum
          local.get 0
          local.get $i
          i32.const 16
          call $rr_order
          local.get $sum
          i32.const 16
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
      local.get 0
      call $drop_rr)

    (func (export "fill") (param i32) (result i64)
      (local $n i32)
      local.get 0
      call $rw_count
      local.set $n
      local.get $n
      if
        i32.const 512
        i32.const 9
        i32.store8
        i32.const 513
        i32.const 9
        i32.store8
        local.get 0
        i32.const 0
        i32.const 512
        i32.const 2
        call $rw_set
        local.get 0
        local.get $n
        i32.const 1
        i32.sub
        call $rw_remove
      end
      local.get $n
      i64.extend_i32_u
      local.get 0
      call $drop_rw)

    (func (export "place") (param i32) (result i64)
      i32.const 660
      i32.const 7
      i32.store8
      local.get 0
      i64.const 42
      i64.const 0
      i32.const 660
      i32.const 1
      call $rw_insert
      local.get 0
      call $rw_count
      i64.extend_i32_u
      local.get 0
      call $drop_rw)

    (func (export "escape") (param i32) (result i64)
      local.get 0
      i32.const 8
      call $read_get
      i32.const 12
      i32.load
      i64.extend_i32_u)

    (func (export "forge") (result i64)
      i32.const 9999
      i32.const 8
      call $read_get
      i32.const 12
      i32.load
      i64.extend_i32_u)

    (func (export "handle-value") (param i32) (result i64)
      local.get 0
      i64.extend_i32_u
      local.get 0
      call $drop_r)

    (func (export "forge-zero") (result i64)
      i32.const 0
      i32.const 8
      call $read_get
      i32.const 12
      i32.load
      i64.extend_i32_u)

    (func (export "read-value") (param i32) (result i64)
      local.get 0
      i32.const 8
      call $read_get
      local.get 0
      call $drop_r
      i32.const 12
      i32.load
      i64.extend_i32_u)

    (func (export "leak") (param i32) (result i64)
      local.get 0
      i32.const 8
      call $read_get
      i32.const 12
      i32.load
      i64.extend_i32_u)

    (func (export "no-such-entry") (param i32) (result i64)
      local.get 0
      i32.const 99
      call $rw_remove
      i64.const 0))

  (core instance $i (instantiate $m
    (with "env" (instance (export "mem" (memory $a "mem"))))
    (with "k" (instance
      (export "read-get" (func $read_get_l))
      (export "locked-get" (func $locked_get_l))
      (export "write-get" (func $write_get_l))
      (export "write-set" (func $write_set_l))
      (export "delta-put" (func $delta_put_l))
      (export "reserve-take" (func $reserve_take_l))
      (export "bucket-amount" (func $bucket_amount_l))
      (export "rr-count" (func $rr_count_l))
      (export "rr-order" (func $rr_order_l))
      (export "rr-entry" (func $rr_entry_l))
      (export "rw-count" (func $rw_count_l))
      (export "rw-set" (func $rw_set_l))
      (export "rw-insert" (func $rw_insert_l))
      (export "rw-remove" (func $rw_remove_l))
      (export "clock" (func $clock_l))
      (export "hash" (func $hash_l))
      (export "drop-r" (func $drop_r))
      (export "drop-s" (func $drop_s))
      (export "drop-w" (func $drop_w))
      (export "drop-d" (func $drop_d))
      (export "drop-v" (func $drop_v))
      (export "drop-rr" (func $drop_rr))
      (export "drop-rw" (func $drop_rw))))))

  (func (export "transfer")
    (param "a" (borrow $vcell)) (param "b" (borrow $dcell)) (result u64)
    (canon lift (core func $i "transfer")))
  (func (export "hash-tag") (result u64)
    (canon lift (core func $i "hash-tag")))
  (func (export "peek")
    (param "c" (borrow $scell)) (result u64)
    (canon lift (core func $i "peek")))
  (func (export "rmw")
    (param "c" (borrow $wcell)) (result u64)
    (canon lift (core func $i "rmw")))
  (func (export "scan-sum")
    (param "r" (borrow $rrange)) (result u64)
    (canon lift (core func $i "scan-sum")))
  (func (export "fill")
    (param "r" (borrow $wrange)) (result u64)
    (canon lift (core func $i "fill")))
  (func (export "place")
    (param "r" (borrow $wrange)) (result u64)
    (canon lift (core func $i "place")))
  (func (export "escape")
    (param "c" (borrow $dcell)) (result u64)
    (canon lift (core func $i "escape")))
  (func (export "forge") (result u64)
    (canon lift (core func $i "forge")))
  (func (export "handle-value")
    (param "c" (borrow $rcell)) (result u64)
    (canon lift (core func $i "handle-value")))
  (func (export "forge-zero") (result u64)
    (canon lift (core func $i "forge-zero")))
  (func (export "read-value")
    (param "c" (borrow $rcell)) (result u64)
    (canon lift (core func $i "read-value")))
  (func (export "leak")
    (param "c" (borrow $rcell)) (result u64)
    (canon lift (core func $i "leak")))
  (func (export "no-such-entry")
    (param "r" (borrow $wrange)) (result u64)
    (canon lift (core func $i "no-such-entry"))))
