(module
  (import "kernel/state" "site_get" (func $site_get (param i32 i32) (result i32)))
  (import "kernel/state" "mint" (func $mint (param i32 i32) (result i32)))
  (import "kernel/state" "site_take" (func $site_take (param i32 i32 i32) (result i32)))
  (import "kernel/state" "site_put" (func $site_put (param i32 i32 i32)))
  (import "kernel/state" "bucket_amount" (func $bucket_amount (param i32 i32)))
  (import "kernel/state" "bucket_take" (func $bucket_take (param i32 i32) (result i32)))
  (import "kernel/state" "site_count" (func $site_count (param i32 i32) (result i32)))
  (import "kernel/state" "site_instance_take" (func $instance_take (param i32 i32 i32 i32) (result i32)))
  (import "kernel/state" "site_instance_put" (func $instance_put (param i32 i32 i32 i32 i32)))
  (import "kernel/state" "bucket_put" (func $bucket_put (param i32 i32)))
  (import "kernel/state" "site_reserve_take" (func $reserve_take (param i32 i32) (result i32)))
  (import "kernel/state" "bucket_drop" (func $bucket_drop (param i32)))
  (import "kernel/abi" "arg" (func $arg (param i32 i32)))
  (import "kernel/abi" "reply" (func $reply (param i32 i32)))
  (import "kernel/abi" "answer" (func $answer (param i32 i32)))

  (memory (export "memory") 1 1)
  (global $held (mut i32) (i32.const 0))

  ;; Scratch: 32..48 and 48..64 amounts, 64..72 two edges, 128.. an id
  ;; list collected from its register, 700 one entry byte, 1024..1032
  ;; the answer, 1032..1036 one edge.

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

  ;; An amount at `at`: the low half, and a zero high half.
  (func $amount (param $at i32) (param $low i64)
    local.get $at
    local.get $low
    i64.store
    local.get $at
    i32.const 8
    i32.add
    i64.const 0
    i64.store)

  ;; Keep the bucket's index in a global, so it outlives the call that
  ;; delivered it; answer the index.
  (func (export "hold") (param $b i32)
    local.get $b
    global.set $held
    local.get $b
    i64.extend_i32_u
    call $answer_u64)

  ;; Hand the kept bucket back as the edge.
  (func (export "release")
    global.get $held
    call $reply_edge)

  ;; Read a cell; answer the site index it was handed.
  (func (export "peek") (param $c i32)
    local.get $c
    i32.const 0
    call $site_get
    drop
    local.get $c
    i64.extend_i32_u
    call $answer_u64)

  ;; The held bucket's index, read as though it named a site.
  ;;
  ;; Buckets and sites are two tables, so the number names whatever the
  ;; site table has at that position — and the kernel, not the boundary,
  ;; is what judges it.
  (func (export "read-held") (param $b i32)
    local.get $b
    global.set $held
    global.get $held
    i32.const 0
    call $site_get
    i64.extend_i32_u
    call $answer_u64)

  ;; Let go of the bucket; answer its index.
  (func (export "discard") (param $b i32)
    local.get $b
    call $bucket_drop
    local.get $b
    i64.extend_i32_u
    call $answer_u64)

  ;; The one issuance a fixture declares, so the grant is index zero.
  (func (export "issue") (param $amount i64)
    i32.const 32
    local.get $amount
    call $amount
    i32.const 0
    i32.const 32
    call $mint
    call $reply_edge)

  ;; Take the named instances out of the interval and hand them on: the
  ;; removal and the edge are one operation, so a body cannot pass on
  ;; what it left where it was. The ids arrive through their register,
  ;; eight bytes each.
  (func (export "lift") (param $r i32) (param $ids i32)
    i32.const 1
    i32.const 128
    call $arg
    local.get $r
    i32.const 0
    i32.const 128
    local.get $ids
    i32.const 3
    i32.shr_u
    call $instance_take
    call $reply_edge)

  ;; Take them out and file them straight back, which has to leave the
  ;; collection as it was; answer the count afterwards.
  (func (export "relift") (param $r i32) (param $ids i32)
    i32.const 1
    i32.const 128
    call $arg
    i32.const 700
    i32.const 1
    i32.store8
    local.get $r
    i32.const 0
    local.get $r
    i32.const 0
    i32.const 128
    local.get $ids
    i32.const 3
    i32.shr_u
    call $instance_take
    i32.const 700
    i32.const 1
    call $instance_put
    local.get $r
    i32.const 0
    call $site_count
    i64.extend_i32_u
    call $answer_u64)

  ;; Split the bucket, merge the halves back, and hand the whole thing
  ;; on: what comes off and what is left are the kernel's own
  ;; subtraction, so a round trip through both has to come back whole.
  (func (export "halve") (param $b i32) (param $amount i64)
    (local $off i32)
    i32.const 32
    local.get $amount
    call $amount
    local.get $b
    i32.const 32
    call $bucket_take
    local.set $off
    local.get $b
    local.get $off
    call $bucket_put
    local.get $b
    call $reply_edge)

  ;; Name one bucket as both sides of a merge, which the kernel judges.
  (func (export "self-merge") (param $b i32)
    local.get $b
    local.get $b
    call $bucket_put
    i64.const 0
    call $answer_u64)

  ;; Split and hand back only the part that came off, putting the rest
  ;; into a cell: two edges out of one, which is what a split is for.
  (func (export "split") (param $b i32) (param $amount i64) (param $c i32)
    (local $off i32)
    i32.const 32
    local.get $amount
    call $amount
    local.get $b
    i32.const 32
    call $bucket_take
    local.set $off
    local.get $c
    i32.const 0
    local.get $b
    call $site_put
    local.get $off
    call $reply_edge)

  ;; Read what the bucket carries without moving it, then put it
  ;; somewhere: asking costs the body nothing and leaves the value where
  ;; it was, and what a body holds it has to put down.
  (func (export "weigh") (param $b i32) (param $c i32)
    local.get $b
    i32.const 32
    call $bucket_amount
    local.get $c
    i32.const 0
    local.get $b
    call $site_put
    i32.const 32
    i64.load
    call $answer_u64)

  ;; Credit the cell with the bucket.
  (func (export "put-write") (param $c i32) (param $funds i32)
    local.get $c
    i32.const 0
    local.get $funds
    call $site_put
    i64.const 0
    call $answer_u64)

  (func (export "put-delta") (param $c i32) (param $funds i32)
    local.get $c
    i32.const 0
    local.get $funds
    call $site_put
    i64.const 0
    call $answer_u64)

  ;; The same credit, then a drop of the bucket it consumed.
  (func (export "put-write-then-drop") (param $c i32) (param $funds i32)
    local.get $c
    i32.const 0
    local.get $funds
    call $site_put
    local.get $funds
    call $bucket_drop
    i64.const 0
    call $answer_u64)

  ;; Two debits, from two cells, handed back together in declared order.
  (func (export "take-two") (param $d i32) (param $w i32) (param $a i64) (param $b i64)
    i32.const 32
    local.get $a
    call $amount
    i32.const 48
    local.get $b
    call $amount
    i32.const 64
    local.get $d
    i32.const 0
    i32.const 32
    call $site_take
    i32.store
    i32.const 68
    local.get $w
    i32.const 0
    i32.const 48
    call $site_take
    i32.store
    i32.const 64
    i32.const 2
    call $reply)

  (func (export "take-write") (param $c i32) (param $amount i64)
    i32.const 32
    local.get $amount
    call $amount
    local.get $c
    i32.const 0
    i32.const 32
    call $site_take
    call $reply_edge)

  (func (export "take-delta") (param $c i32) (param $amount i64)
    i32.const 32
    local.get $amount
    call $amount
    local.get $c
    i32.const 0
    i32.const 32
    call $site_take
    call $reply_edge)

  (func (export "take-reserve") (param $v i32)
    local.get $v
    i32.const 0
    call $reserve_take
    call $reply_edge)

  ;; The first grant is left on the table rather than dropped: letting
  ;; go of value is its own refusal, and what this asks is whether one
  ;; hold answers twice. The refusal on the second take is what ends the
  ;; call, so nothing is owed a disposal.
  (func (export "take-reserve-twice") (param $v i32)
    local.get $v
    i32.const 0
    call $reserve_take
    drop
    local.get $v
    i32.const 0
    call $reserve_take
    call $reply_edge))
