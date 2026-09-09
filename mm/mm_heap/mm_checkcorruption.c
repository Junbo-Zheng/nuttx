/****************************************************************************
 * mm/mm_heap/mm_checkcorruption.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS"
 * BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing permissions
 * and limitations under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <assert.h>
#include <stdio.h>
#include <debug.h>
#include <execinfo.h>

#include <nuttx/arch.h>
#include <nuttx/irq.h>
#include <nuttx/sched.h>

#include <nuttx/mm/mm.h>
#include <nuttx/mm/kasan.h>
#include <nuttx/mm/mempool.h>

#include "mm_heap/mm.h"

/****************************************************************************
 * Private Types
 ****************************************************************************/

/* One heap corruption check: the address window within which node
 * pointers are considered valid, and the corrupted nodes found
 */

struct heap_check_s
{
  FAR void *addr_min;             /* Lowest address of the heap descriptor
                                   * and all heap regions */
  FAR void *addr_max;             /* Highest address of all heap regions */
  unsigned int nbad;              /* Number of corrupted nodes detected */
};

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: addr_in_heap
 ****************************************************************************/

static bool addr_in_heap(FAR struct heap_check_s *check,
                         FAR void *mem)
{
  /* The end sentinel node (mm_heapend) itself is a valid address: the
   * next pointer of the last real node points at it.
   */

  mem = kasan_clear_tag(mem);
  return mem >= check->addr_min && mem <= check->addr_max;
}

/****************************************************************************
 * Name: dump_backtrace
 *
 * Description:
 *   Print one recorded backtrace array, eight addresses per line.  The
 *   array is embedded in the scanned structure and ends at its first
 *   NULL entry, exactly like the allocation path leaves it.
 *
 ****************************************************************************/

#if CONFIG_MM_BACKTRACE > 0
static void dump_backtrace(FAR const char *tag, FAR void *const *backtrace)
{
  int i;

  for (i = 0; i < CONFIG_MM_BACKTRACE && backtrace[i] != NULL; i += 8)
    {
      char chunk[8 * (BACKTRACE_PTR_FMT_WIDTH + 1) + 1];
      int j;
      int n = 0;

      for (j = i; j < i + 8 && j < CONFIG_MM_BACKTRACE &&
                   backtrace[j] != NULL; j++)
        {
          n += snprintf(chunk + n, sizeof(chunk) - n, "%p ",
                        backtrace[j]);
        }

      merr("[%s]   bt: %s", tag, chunk);
    }
}
#endif

/****************************************************************************
 * Name: dump_node
 *
 * Description:
 *   Dump one heap node with the recorded pid and allocation backtrace
 *   (when enabled).  The raw flink/blink fields are printed even for
 *   allocated nodes, because a corrupted allocated node may contain
 *   leftover or overwritten link pointers useful for forensics.
 *
 ****************************************************************************/

static void dump_node(FAR struct heap_check_s *check,
                      const char *tag, FAR struct mm_freenode_s *node,
                      bool bt_safe)
{
  const char *node_state;

  /* A corrupted node may compute an adjacent node outside the heap;
   * such an address is reported as-is, never dereferenced.
   */

  if (!addr_in_heap(check, node))
    {
      merr("[heap]  %s node:%p out of heap range", tag, node);
      return;
    }

  node_state = MM_NODE_IS_ALLOC(node) ? "alloc" : "free";

  merr("[heap]  %s node:%p state:%s size:0x%zx preceding:0x%zx"
       " flink:%p blink:%p",
       tag, node, node_state, MM_SIZEOF_NODE(node),
       node->preceding, node->flink, node->blink);

#if CONFIG_MM_BACKTRACE >= 0
  FAR struct tcb_s *tcb = nxsched_get_tcb(node->pid);

  if (tcb != NULL)
    {
      merr("[heap]   pid:%d (%s)", node->pid, get_task_name(tcb));
    }
  else
    {
      merr("[heap]   pid:%d", node->pid);
    }
#endif

#if CONFIG_MM_BACKTRACE > 0
  /* The backtrace array is embedded in the node, so it is only read
   * when the walk validated the node header: a corrupted header makes
   * the node bounds, and thus the array bounds, untrustworthy.
   */

  if (bt_safe)
    {
      dump_backtrace("heap", node->backtrace);
    }
  else
    {
      merr("[heap]   bt: skipped (unverified node)");
    }
#endif
}

/****************************************************************************
 * Name: dump_badnode
 *
 * Description:
 *   Dump the corrupted node together with its physically adjacent nodes.
 *
 ****************************************************************************/

static void dump_badnode(FAR struct heap_check_s *check,
                         const char *reason, int region, unsigned int index,
                         FAR struct mm_freenode_s *prev,
                         FAR struct mm_freenode_s *cur,
                         FAR struct mm_freenode_s *next)
{
  merr("[heap] corrupted node: region:%d index:%u reason:%s",
       region, index, reason);

  /* prev was validated by the walk, except in the first iteration
   * where it is the start guard node whose record fields were never
   * initialized; cur and nex may carry a corrupted header, so their
   * recorded backtrace is not read.
   */

  dump_node(check, "pre", prev, index > 0);
  dump_node(check, "cur", cur, false);
  dump_node(check, "nex", next, false);
  check->nbad++;
}

/****************************************************************************
 * Name: check_region
 *
 * Description:
 *   Walk one heap region node by node and validate every field that the
 *   allocator relies on:
 *
 *   - node and next-node addresses stay inside the heap
 *   - node size stays inside the region size
 *   - preceding size of the next node matches the current node size
 *   - free-node flink/blink stay inside the heap and stay consistent
 *
 *   On the first corrupted node the walk stops after dumping the node
 *   and its physically adjacent nodes.  Walking relies on the size field
 *   to advance, so continuing past an inconsistent size is not possible.
 *
 ****************************************************************************/

static void check_region(FAR struct heap_check_s *check,
                         FAR struct mm_heap_s *heap, int region)
{
  FAR struct mm_freenode_s *prev = (FAR void *)heap->mm_heapstart[region];
  FAR struct mm_allocnode_s *node;
  size_t regionsize = (size_t)((FAR char *)heap->mm_heapend[region] -
                               (FAR char *)heap->mm_heapstart[region]);
  unsigned int index = 0;
  size_t nodesize = 0;

  for (node = heap->mm_heapstart[region];
       (uintptr_t)node < (uintptr_t)heap->mm_heapend[region];
       node = (FAR struct mm_allocnode_s *)((FAR char *)node + nodesize))
    {
      FAR struct mm_freenode_s *fnode = (FAR void *)node;
      FAR struct mm_freenode_s *next;

      nodesize = MM_SIZEOF_NODE(node);
      next = (FAR struct mm_freenode_s *)((FAR char *)node + nodesize);

      if (!addr_in_heap(check, next))
        {
          dump_badnode(check, "next out of range", region,
                       index, prev, fnode, next);
          break;
        }

      /* The size field must stay inside the region and the next node must
       * agree on the preceding chunk size when the previous node is free.
       * A size below the node-type minimum (a zero size would stall the
       * walk) is corrupt; the start guard node legitimately carries the
       * bare MM_SIZEOF_ALLOCNODE.
       */

      if ((MM_NODE_IS_ALLOC(node) && nodesize < MM_SIZEOF_ALLOCNODE) ||
          (MM_NODE_IS_FREE(node) && nodesize < MM_MIN_CHUNK) ||
          nodesize > regionsize ||
          (MM_PREVNODE_IS_FREE(next) && next->preceding != nodesize))
        {
          dump_badnode(check, "inconsistent size", region,
                       index, prev, fnode, next);
          break;
        }

      /* A free node must be linked into the nodelist chain with both
       * pointers inside the heap.  The single tail of the whole chain
       * legitimately has flink == NULL; blink always points at the
       * chain predecessor, at least at a nodelist sentinel.
       */

      if (MM_NODE_IS_FREE(fnode))
        {
          if ((fnode->flink != NULL && !addr_in_heap(check, fnode->flink)) ||
              !addr_in_heap(check, fnode->blink))
            {
              dump_badnode(check, "freelist pointer out of range", region,
                           index, prev, fnode, next);
              break;
            }

          if (fnode->blink->flink != fnode ||
              (fnode->flink != NULL && fnode->flink->blink != fnode))
            {
              merr("[heap] freelist broken: index:%u node:%p"
                   " blink:%p blink->flink:%p"
                   " flink:%p flink->blink:%p",
                   index, fnode, fnode->blink, fnode->blink->flink,
                   fnode->flink, fnode->flink->blink);
              dump_badnode(check, "freelist not doubly linked", region,
                           index, prev, fnode, next);
              break;
            }
        }

      prev = fnode;
      index++;
    }
}

#ifdef CONFIG_MM_HEAP_MEMPOOL
/****************************************************************************
 * Name: dump_mempool_block
 *
 * Description:
 *   Dump one mempool block with the fields recorded at alloc/free time.
 *   A corrupted block header may contain garbage in every field, so the
 *   caller validates the block address before reaching here.
 *
 ****************************************************************************/

#if CONFIG_MM_BACKTRACE >= 0
static void dump_mempool_block(FAR const char *tag,
                               FAR struct heap_check_s *check,
                               FAR struct mempool_s *pool,
                               FAR struct mempool_backtrace_s *buf)
{
  size_t blocksize = MEMPOOL_REALBLOCKSIZE(pool);

  /* The adjacent blocks are computed blindly, so a block outside the
   * heap is reported by address only, without dereferencing it.
   */

  if (!addr_in_heap(check, buf))
    {
      merr("[pool]  %s node:%p out of heap range", tag, buf);
      return;
    }

  merr("[pool]  %s node:%p size:0x%zx magic:0x%x pid:%d"
#ifdef CONFIG_MM_BACKTRACE_SEQNO
       " seqno:%lu"
#endif
       ,
       tag,
       (FAR void *)((FAR char *)buf - pool->blocksize),
       blocksize, buf->magic, buf->pid
#ifdef CONFIG_MM_BACKTRACE_SEQNO
       , buf->seqno
#endif
      );

  /* The backtrace array is embedded in the block header, so it is only
   * read when the magic is intact: magic is the first field of the
   * header, so an overflow that reached the backtrace array must have
   * destroyed the magic first.
   */

#  if CONFIG_MM_BACKTRACE > 0
  if (buf->magic == MEMPOOL_MAGIC_FREE ||
      buf->magic == MEMPOOL_MAGIC_ALLOC)
    {
      dump_backtrace("pool", buf->backtrace);
    }
#  endif
}
#endif

/****************************************************************************
 * Name: check_pool_blocks
 *
 * Description:
 *   Scan one run of pool blocks for a corrupted block magic: every block
 *   carries a magic that must be MEMPOOL_MAGIC_FREE or MEMPOOL_MAGIC_ALLOC.
 *   A block whose magic is neither was overwritten; the block and its
 *   physically adjacent blocks are dumped.
 *
 ****************************************************************************/

#if CONFIG_MM_BACKTRACE >= 0
static void check_pool_blocks(
    FAR struct heap_check_s *check,
    FAR struct mempool_s *pool, unsigned int pool_id,
    FAR char *base, size_t nblks)
{
  size_t blocksize = MEMPOOL_REALBLOCKSIZE(pool);
  size_t i;

  for (i = 0; i < nblks; i++)
    {
      FAR struct mempool_backtrace_s *buf =
        (FAR void *)(base + i * blocksize + pool->blocksize);

      if (buf->magic != MEMPOOL_MAGIC_FREE &&
          buf->magic != MEMPOOL_MAGIC_ALLOC)
        {
          merr("[pool] corrupted block: pool:%u block:%zu", pool_id, i);
          dump_mempool_block("pre", check, pool,
                             (FAR void *)((FAR char *)buf - blocksize));
          dump_mempool_block("cur", check, pool, buf);
          dump_mempool_block("nex", check, pool,
                             (FAR void *)((FAR char *)buf + blocksize));
          check->nbad++;
          break;
        }
    }
}
#endif

/****************************************************************************
 * Name: check_mempool_runs
 *
 * Description:
 *   Scan one pool with backtrace enabled.  The interrupt run is tracked
 *   by ibase; every other run of blocks carries the equeue entry at its
 *   end, so the entry address recovers the run base.  The initial run is
 *   the first equeue entry and is sized by initialsize; later runs are
 *   sized by expandsize.
 *
 ****************************************************************************/

#if CONFIG_MM_BACKTRACE >= 0
static void check_mempool_runs(FAR struct heap_check_s *check,
                               FAR struct mempool_s *pool,
                               unsigned int pool_id)
{
  size_t blocksize = MEMPOOL_REALBLOCKSIZE(pool);
  bool has_initial = pool->initialsize >= blocksize + MEMPOOL_HEADER_SIZE;
  FAR sq_entry_t *entry;
  size_t nexp = 0;

  /* Upper bound on the runs that fit in the address window; exceeding
   * it means the corrupted expand queue loops.
   */

  size_t maxexp = ((size_t)((FAR char *)check->addr_max -
                            (FAR char *)check->addr_min) / blocksize) + 1;

  if (pool->ibase != NULL &&
      pool->interruptsize >= blocksize &&
      addr_in_heap(check, pool->ibase) &&
      addr_in_heap(check, (FAR char *)pool->ibase + pool->interruptsize))
    {
      check_pool_blocks(check, pool, pool_id,
                        (FAR char *)pool->ibase,
                        pool->interruptsize / blocksize);
    }

  sq_for_every(&pool->equeue, entry)
    {
      size_t runsize = has_initial && nexp == 0 ?
                         pool->initialsize : pool->expandsize;
      size_t nblks;
      FAR char *base;

      if (nexp++ >= maxexp)
        {
          merr("[pool] expand queue loop suspected: pool:%u", pool_id);
          check->nbad++;
          break;
        }

      if (runsize < blocksize + MEMPOOL_HEADER_SIZE)
        {
          merr("[pool] run too small: pool:%u entry:%p", pool_id, entry);
          check->nbad++;
          break;
        }

      nblks = (runsize - MEMPOOL_HEADER_SIZE) / blocksize;
      base = (FAR char *)entry - nblks * blocksize;

      if (!addr_in_heap(check, entry) ||
          !addr_in_heap(check, base))
        {
          merr("[pool] expansion out of range: pool:%u entry:%p base:%p",
               pool_id, entry, (FAR void *)base);
          check->nbad++;
          break;
        }

      check_pool_blocks(check, pool, pool_id, base, nblks);
    }
}
#endif

/****************************************************************************
 * Name: check_mempool_queue
 *
 * Description:
 *   Validate the free queue links of one pool.  A queue entry sits at
 *   the user pointer of the block, so a block that was used after free
 *   (or hit by a neighbor overflow) shows up as a queue pointer outside
 *   the heap, like the free node check of check_region().
 *
 ****************************************************************************/

static void check_mempool_queue(FAR struct heap_check_s *check,
                                FAR struct mempool_s *pool,
                                unsigned int pool_id,
                                FAR sq_queue_t *queue)
{
  size_t blocksize = MEMPOOL_REALBLOCKSIZE(pool);
  FAR sq_entry_t *entry;
  unsigned int index = 0;

  /* Upper bound on the distinct queue entries that fit in the address
   * window; exceeding it means the corrupted queue loops.
   */

  size_t maxblk = ((size_t)((FAR char *)check->addr_max -
                            (FAR char *)check->addr_min) / blocksize) + 1;

  sq_for_every(queue, entry)
    {
      if (index >= maxblk)
        {
          merr("[pool] free queue loop suspected: pool:%u block:%u",
               pool_id, index);
          check->nbad++;
          break;
        }

      /* The flink of the queue tail is legitimately NULL, so only a
       * non-NULL flink outside the heap marks corruption.
       */

      if (!addr_in_heap(check, entry) ||
          (entry->flink != NULL && !addr_in_heap(check, entry->flink)))
        {
          FAR sq_entry_t *pre = (FAR sq_entry_t *)
            ((FAR char *)entry - blocksize);
          FAR sq_entry_t *nex = (FAR sq_entry_t *)
            ((FAR char *)entry + blocksize);

          merr("[pool] corrupted free queue entry: pool:%u block:%u",
               pool_id, index);
          merr("[pool]  cur node:%p flink:%p", entry, entry->flink);
          if (addr_in_heap(check, pre))
            {
              merr("[pool]  pre node:%p flink:%p", pre, pre->flink);
            }
          else
            {
              merr("[pool]  pre node:%p out of range", pre);
            }

          if (addr_in_heap(check, nex))
            {
              merr("[pool]  nex node:%p flink:%p", nex, nex->flink);
            }
          else
            {
              merr("[pool]  nex node:%p out of range", nex);
            }

          check->nbad++;
          break;
        }

      index++;
    }
}

/****************************************************************************
 * Name: check_one_mempool
 *
 * Description:
 *   Scan one pool of the multiple mempool owned by the heap.  Pool
 *   blocks are fixed size and contiguous inside each run, so a bad
 *   write is detected by checking each block's magic and every free
 *   queue link.
 *
 ****************************************************************************/

struct mempool_check_s
{
  FAR struct heap_check_s *check;  /* The heap check in progress */
  unsigned int pool_id;            /* Index of the pool being scanned */
};

static void check_one_mempool(FAR struct mempool_s *pool, FAR void *arg)
{
  FAR struct mempool_check_s *mcheck = arg;
  size_t blocksize = MEMPOOL_REALBLOCKSIZE(pool);

  if (!addr_in_heap(mcheck->check, pool) || blocksize == 0)
    {
      merr("[pool] corrupted pool struct: pool:%u addr:%p",
           mcheck->pool_id, pool);
      mcheck->check->nbad++;
      return;
    }

  check_mempool_queue(mcheck->check, pool, mcheck->pool_id, &pool->iqueue);
  check_mempool_queue(mcheck->check, pool, mcheck->pool_id, &pool->queue);
#if CONFIG_MM_BACKTRACE >= 0
  check_mempool_runs(mcheck->check, pool, mcheck->pool_id);
#endif
  mcheck->pool_id++;
}

/****************************************************************************
 * Name: check_mempool
 *
 * Description:
 *   Scan the multiple mempool owned by the heap for out-of-bounds writes.
 *
 ****************************************************************************/

static void check_mempool(FAR struct heap_check_s *check,
                          FAR struct mm_heap_s *heap)
{
  FAR struct mempool_multiple_s *mpool = heap->mm_mpool;
  struct mempool_check_s mcheck;

  if (mpool == NULL)
    {
      return;
    }

  if (!addr_in_heap(check, mpool))
    {
      merr("[pool] mpool out of heap range:%p", mpool);
      check->nbad++;
      return;
    }

  mcheck.check = check;
  mcheck.pool_id = 0;
  mempool_multiple_foreach(mpool, check_one_mempool, &mcheck);
}
#endif /* CONFIG_MM_HEAP_MEMPOOL */

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: mm_checkcorruption
 *
 * Description:
 *   mm_checkcorruption walks every node of every region of the heap and
 *   checks the node fields for corruption; when the heap owns a multiple
 *   mempool, every pool block is checked as well.  On corruption it does
 *   not panic: it dumps the corrupted node and its physically adjacent
 *   nodes, including the recorded pid and allocation backtrace when
 *   CONFIG_MM_BACKTRACE is enabled, so a crash dump handler can capture
 *   the scene before reboot.
 *
 *   Locking: in thread context the heap lock is taken and the delayed
 *   free list is flushed first, like the regular allocator entry points.
 *   In interrupt context the scan always runs without the lock: taking
 *   the heap lock from interrupt context is not allowed, the heap is
 *   quiescent in the crash dump path, and a periodic check only risks
 *   a torn read that is never fatal, since the scan only reads and
 *   never dereferences a pointer outside the heap.
 *
 * Input Parameters:
 *   heap - The heap to scan.
 *
 ****************************************************************************/

void mm_checkcorruption(FAR struct mm_heap_s *heap)
{
  struct heap_check_s check;
  bool locked = false;
#if CONFIG_MM_REGIONS > 1
  int nregions = heap->mm_nregions;
#else
  int nregions = 1;
#endif
  int region;

  if (!up_interrupt_context())
    {
      mm_free_delaylist(heap);
      DEBUGVERIFY(mm_lock(heap));
      locked = true;
    }

  /* The lower bound starts at the heap descriptor itself: free nodes may
   * legitimately link to the mm_nodelist[] sentinel nodes embedded in the
   * struct, which live outside the heap regions.
   */

  check.addr_min = heap;
  check.addr_max = heap->mm_heapend[0];
  check.nbad = 0;

#if CONFIG_MM_REGIONS > 1
  for (region = 0; region < nregions; region++)
    {
      if (check.addr_min > (FAR void *)heap->mm_heapstart[region])
        {
          check.addr_min = heap->mm_heapstart[region];
        }

      if (check.addr_max < (FAR void *)heap->mm_heapend[region])
        {
          check.addr_max = heap->mm_heapend[region];
        }
    }
#endif

  mwarn("[heap] scan: heap:%p addr_min:%p addr_max:%p\n",
        heap, check.addr_min, check.addr_max);

  for (region = 0; region < nregions; region++)
    {
      check_region(&check, heap, region);
    }

#ifdef CONFIG_MM_HEAP_MEMPOOL
  check_mempool(&check, heap);
#endif

  mwarn("[scan] corrupted node num:%u\n", check.nbad);

  if (locked)
    {
      mm_unlock(heap);
    }
}
