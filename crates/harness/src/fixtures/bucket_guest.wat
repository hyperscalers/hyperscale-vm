(component
  (import "hyperscale:kernel/state" (instance $state
    (export "bucket" (type $bk (sub resource)))
    (export "issuer" (type $is (sub resource)))
    (export "read-cell" (type $rc (sub resource)))
    (export "amount-cell" (type $wc (sub resource)))
    (export "delta-cell" (type $dc (sub resource)))
    (export "reserve-cell" (type $vc (sub resource)))
    (type $amt_decl (record (field "low" u64) (field "high" u64)))
    (export "amount" (type $amt (eq $amt_decl)))
    (export "read-cell-get" (func (param "c" (borrow $rc)) (result (list u8))))
    (export "mint" (func (param "i" (borrow $is)) (param "amount" $amt) (result (own $bk))))
    (export "amount-cell-take" (func (param "c" (borrow $wc)) (param "amount" $amt) (result (own $bk))))
    (export "amount-cell-put" (func (param "c" (borrow $wc)) (param "funds" (own $bk))))
    (export "bucket-amount" (func (param "b" (borrow $bk)) (result $amt)))
    (export "bucket-take" (func (param "b" (borrow $bk)) (param "amount" $amt) (result (own $bk))))
    (export "instance-range" (type $rw (sub resource)))
    (export "instance-range-count" (func (param "r" (borrow $rw)) (result u32)))
    (export "instance-range-take" (func (param "r" (borrow $rw)) (param "ids" (list u64)) (result (own $bk))))
    (export "instance-range-put" (func (param "r" (borrow $rw)) (param "funds" (own $bk)) (param "value" (list u8))))
    (export "bucket-put" (func (param "b" (borrow $bk)) (param "other" (own $bk))))
    (export "delta-cell-put" (func (param "c" (borrow $dc)) (param "funds" (own $bk))))
    (export "delta-cell-take" (func (param "c" (borrow $dc)) (param "amount" $amt) (result (own $bk))))
    (export "reserve-cell-take" (func (param "c" (borrow $vc)) (result (own $bk))))))

  (alias export $state "bucket" (type $bucket))
  (alias export $state "issuer" (type $issuer))
  (alias export $state "read-cell" (type $rcell))
  (alias export $state "amount-cell" (type $wcell))
  (alias export $state "delta-cell" (type $dcell))
  (alias export $state "reserve-cell" (type $vcell))
  (alias export $state "read-cell-get" (func $read_get))
  (alias export $state "mint" (func $issue))
  (alias export $state "amount-cell-take" (func $write_take))
  (alias export $state "amount-cell-put" (func $write_put))
  (alias export $state "bucket-amount" (func $bucket_amount))
  (alias export $state "instance-range" (type $wrange))
  (alias export $state "bucket-take" (func $bucket_take))
  (alias export $state "instance-range-count" (func $rw_count))
  (alias export $state "instance-range-take" (func $range_take))
  (alias export $state "instance-range-put" (func $range_put))
  (alias export $state "bucket-put" (func $bucket_put))
  (alias export $state "delta-cell-put" (func $delta_put))
  (alias export $state "delta-cell-take" (func $delta_take))
  (alias export $state "reserve-cell-take" (func $reserve_take))

  (core module $alloc
    (memory (export "mem") 1 1)
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
  (core func $issue_l (canon lower (func $issue)))
  (core func $write_take_l (canon lower (func $write_take)))
  (core func $write_put_l (canon lower (func $write_put)))
  (core func $bucket_amount_l (canon lower (func $bucket_amount)
    (memory $a "mem")))
  (core func $bucket_take_l (canon lower (func $bucket_take)))
  (core func $rw_count_l (canon lower (func $rw_count)))
  (core func $range_take_l (canon lower (func $range_take)
    (memory $a "mem")))
  (core func $range_put_l (canon lower (func $range_put)
    (memory $a "mem")))
  (core func $drop_wrange (canon resource.drop $wrange))
  (core func $bucket_put_l (canon lower (func $bucket_put)))
  (core func $delta_put_l (canon lower (func $delta_put)))
  (core func $delta_take_l (canon lower (func $delta_take)))
  (core func $reserve_take_l (canon lower (func $reserve_take)))
  (core func $drop_bucket (canon resource.drop $bucket))
  (core func $drop_read (canon resource.drop $rcell))
  (core func $drop_issuer (canon resource.drop $issuer))
  (core func $drop_write (canon resource.drop $wcell))
  (core func $drop_delta (canon resource.drop $dcell))
  (core func $drop_reserve (canon resource.drop $vcell))

  (core module $m
    (import "env" "mem" (memory 1 1))
    (import "k" "read-get" (func $read_get (param i32 i32)))
    (import "k" "issue" (func $issue (param i32 i64 i64) (result i32)))
    (import "k" "write-take" (func $write_take (param i32 i64 i64) (result i32)))
    (import "k" "write-put" (func $write_put (param i32 i32)))
    (import "k" "bucket-amount" (func $bucket_amount (param i32 i32)))
    (import "k" "bucket-take" (func $bucket_take (param i32 i64 i64) (result i32)))
    (import "k" "rw-count" (func $rw_count (param i32) (result i32)))
    (import "k" "range-take" (func $range_take (param i32 i32 i32) (result i32)))
    (import "k" "range-put" (func $range_put (param i32 i32 i32 i32)))
    (import "k" "drop-wrange" (func $drop_wrange (param i32)))
    (import "k" "bucket-put" (func $bucket_put (param i32 i32)))
    (import "k" "delta-put" (func $delta_put (param i32 i32)))
    (import "k" "delta-take" (func $delta_take (param i32 i64 i64) (result i32)))
    (import "k" "reserve-take" (func $reserve_take (param i32) (result i32)))
    (import "k" "drop-bucket" (func $drop_bucket (param i32)))
    (import "k" "drop-read" (func $drop_read (param i32)))
    (import "k" "drop-issuer" (func $drop_issuer (param i32)))
    (import "k" "drop-write" (func $drop_write (param i32)))
    (import "k" "drop-delta" (func $drop_delta (param i32)))
    (import "k" "drop-reserve" (func $drop_reserve (param i32)))
    (global $held (mut i32) (i32.const 0))

    (func (export "hold") (param i32) (result i64)
      local.get 0
      global.set $held
      local.get 0
      i64.extend_i32_u)

    (func (export "release") (result i32)
      global.get $held)

    (func (export "peek") (param i32) (result i64)
      local.get 0
      i32.const 8
      call $read_get
      local.get 0
      i64.extend_i32_u
      local.get 0
      call $drop_read)

    (func (export "discard") (param i32) (result i64)
      local.get 0
      i64.extend_i32_u
      local.get 0
      call $drop_bucket)

    (func (export "issue") (param i32 i64) (result i32)
      local.get 0
      local.get 1
      i64.const 0
      call $issue
      local.get 0
      call $drop_issuer)

    ;; Take the named instances out of the interval and hand them on: the
    ;; removal and the edge are one operation, so a body cannot pass on
    ;; what it left where it was. The ids arrive in the framing a declared
    ;; id list already crosses in, so they pass straight through.
    (func (export "lift") (param i32 i32 i32) (result i32)
      (local $held i32)
      local.get 0
      local.get 1
      local.get 2
      call $range_take
      local.set $held
      local.get 0
      call $drop_wrange
      local.get $held)

    ;; Take them out and file them straight back, which has to leave the
    ;; collection as it was.
    (func (export "relift") (param i32 i32 i32) (result i64)
      i32.const 700
      i32.const 1
      i32.store8
      local.get 0
      local.get 0
      local.get 1
      local.get 2
      call $range_take
      i32.const 700
      i32.const 1
      call $range_put
      local.get 0
      call $rw_count
      i64.extend_i32_u
      local.get 0
      call $drop_wrange)

    ;; Split the bucket, merge the halves back, and hand the whole thing
    ;; on: what comes off and what is left are the kernel's own
    ;; subtraction, so a round trip through both has to come back whole.
    (func (export "halve") (param i32 i64) (result i32)
      (local $off i32)
      local.get 0
      local.get 1
      i64.const 0
      call $bucket_take
      local.set $off
      local.get 0
      local.get $off
      call $bucket_put
      local.get 0)

    ;; Name one bucket as both sides of a merge. The lend the borrow
    ;; takes is still standing when the owned argument is lifted, so
    ;; the boundary refuses before the kernel is reached at all.
    (func (export "self-merge") (param i32) (result i64)
      local.get 0
      local.get 0
      call $bucket_put
      i64.const 0)

    ;; Split and hand back only the part that came off, putting the rest
    ;; into a cell: two edges out of one, which is what a split is for.
    (func (export "split") (param i32 i64 i32) (result i32)
      (local $off i32)
      local.get 0
      local.get 1
      i64.const 0
      call $bucket_take
      local.set $off
      local.get 2
      local.get 0
      call $delta_put
      local.get 2
      call $drop_delta
      local.get $off)

    ;; Read what the bucket carries without moving it, then put it
    ;; somewhere: a borrow costs the body nothing and leaves the value
    ;; where it was, and what a body holds it has to put down.
    (func (export "weigh") (param i32 i32) (result i64)
      local.get 0
      i32.const 32
      call $bucket_amount
      i32.const 32
      i64.load
      local.get 1
      local.get 0
      call $delta_put
      local.get 1
      call $drop_delta)

    ;; Credit the cell with the bucket, then say whether the handle it
    ;; consumed still names anything: a live one would answer, and a
    ;; consumed one traps, which is what the negative index reports.
    (func (export "put-write") (param i32 i32) (result i64)
      local.get 0
      local.get 1
      call $write_put
      local.get 0
      call $drop_write
      i64.const 0)

    (func (export "put-delta") (param i32 i32) (result i64)
      local.get 0
      local.get 1
      call $delta_put
      local.get 0
      call $drop_delta
      i64.const 0)

    ;; The same credit, then a second drop of the handle it consumed.
    (func (export "put-write-then-drop") (param i32 i32) (result i64)
      local.get 0
      local.get 1
      call $write_put
      local.get 1
      call $drop_bucket
      local.get 0
      call $drop_write
      i64.const 0)

    ;; Two debits, from two cells, handed back together: the handles go
    ;; into the return area in declared order and the area's pointer is
    ;; what a spilled result returns.
    (func (export "take-two") (param i32 i32 i64 i64) (result i32)
      (local $one i32) (local $two i32)
      local.get 0
      local.get 2
      i64.const 0
      call $delta_take
      local.set $one
      local.get 1
      local.get 3
      i64.const 0
      call $write_take
      local.set $two
      i32.const 64
      local.get $one
      i32.store
      i32.const 68
      local.get $two
      i32.store
      local.get 0
      call $drop_delta
      local.get 1
      call $drop_write
      i32.const 64)

    (func (export "take-write") (param i32 i64) (result i32)
      local.get 0
      local.get 1
      i64.const 0
      call $write_take
      local.get 0
      call $drop_write)

    (func (export "take-delta") (param i32 i64) (result i32)
      local.get 0
      local.get 1
      i64.const 0
      call $delta_take
      local.get 0
      call $drop_delta)

    (func (export "take-reserve") (param i32) (result i32)
      local.get 0
      call $reserve_take
      local.get 0
      call $drop_reserve)

    ;; The first grant is left on the table rather than dropped: letting
    ;; go of value is its own refusal, and what this asks is whether one
    ;; hold answers twice. The trap on the second take is what ends the
    ;; call, so nothing is owed a disposal.
    (func (export "take-reserve-twice") (param i32) (result i32)
      local.get 0
      call $reserve_take
      drop
      local.get 0
      call $reserve_take
      local.get 0
      call $drop_reserve))

  (core instance $i (instantiate $m
    (with "env" (instance (export "mem" (memory $a "mem"))))
    (with "k" (instance
      (export "read-get" (func $read_get_l))
      (export "issue" (func $issue_l))
      (export "write-take" (func $write_take_l))
      (export "write-put" (func $write_put_l))
      (export "bucket-amount" (func $bucket_amount_l))
      (export "bucket-take" (func $bucket_take_l))
      (export "rw-count" (func $rw_count_l))
      (export "range-take" (func $range_take_l))
      (export "range-put" (func $range_put_l))
      (export "drop-wrange" (func $drop_wrange))
      (export "bucket-put" (func $bucket_put_l))
      (export "delta-put" (func $delta_put_l))
      (export "delta-take" (func $delta_take_l))
      (export "reserve-take" (func $reserve_take_l))
      (export "drop-bucket" (func $drop_bucket))
      (export "drop-read" (func $drop_read))
      (export "drop-issuer" (func $drop_issuer))
      (export "drop-write" (func $drop_write))
      (export "drop-delta" (func $drop_delta))
      (export "drop-reserve" (func $drop_reserve))))))

  (func (export "hold")
    (param "b" (own $bucket)) (result u64)
    (canon lift (core func $i "hold")))
  (func (export "release") (result (own $bucket))
    (canon lift (core func $i "release")))
  (func (export "peek")
    (param "c" (borrow $rcell)) (result u64)
    (canon lift (core func $i "peek")))
  (func (export "discard")
    (param "b" (own $bucket)) (result u64)
    (canon lift (core func $i "discard")))
  (func (export "issue")
    (param "i" (borrow $issuer)) (param "amount" u64) (result (own $bucket))
    (canon lift (core func $i "issue")))
  (func (export "take-two")
    (param "d" (borrow $dcell)) (param "w" (borrow $wcell))
    (param "a" u64) (param "b" u64)
    (result (tuple (own $bucket) (own $bucket)))
    (canon lift (core func $i "take-two") (memory $a "mem")))
  (func (export "lift")
    (param "r" (borrow $wrange)) (param "ids" (list u64))
    (result (own $bucket))
    (canon lift (core func $i "lift") (memory $a "mem") (realloc (func $a "realloc"))))
  (func (export "relift")
    (param "r" (borrow $wrange)) (param "ids" (list u64)) (result u64)
    (canon lift (core func $i "relift") (memory $a "mem") (realloc (func $a "realloc"))))
  (func (export "halve")
    (param "b" (own $bucket)) (param "amount" u64) (result (own $bucket))
    (canon lift (core func $i "halve")))
  (func (export "self-merge")
    (param "b" (own $bucket)) (result u64)
    (canon lift (core func $i "self-merge")))
  (func (export "split")
    (param "b" (own $bucket)) (param "amount" u64) (param "c" (borrow $dcell))
    (result (own $bucket))
    (canon lift (core func $i "split")))
  (func (export "weigh")
    (param "b" (own $bucket)) (param "c" (borrow $dcell)) (result u64)
    (canon lift (core func $i "weigh")))
  (func (export "put-write")
    (param "c" (borrow $wcell)) (param "funds" (own $bucket)) (result u64)
    (canon lift (core func $i "put-write")))
  (func (export "put-delta")
    (param "c" (borrow $dcell)) (param "funds" (own $bucket)) (result u64)
    (canon lift (core func $i "put-delta")))
  (func (export "put-write-then-drop")
    (param "c" (borrow $wcell)) (param "funds" (own $bucket)) (result u64)
    (canon lift (core func $i "put-write-then-drop")))
  (func (export "take-write")
    (param "c" (borrow $wcell)) (param "amount" u64) (result (own $bucket))
    (canon lift (core func $i "take-write")))
  (func (export "take-delta")
    (param "c" (borrow $dcell)) (param "amount" u64) (result (own $bucket))
    (canon lift (core func $i "take-delta")))
  (func (export "take-reserve")
    (param "v" (borrow $vcell)) (result (own $bucket))
    (canon lift (core func $i "take-reserve")))
  (func (export "take-reserve-twice")
    (param "v" (borrow $vcell)) (result (own $bucket))
    (canon lift (core func $i "take-reserve-twice"))))
