/*
 *  emulator main execution loop
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "trace.h"
#include "disas/disas.h"
#include "exec/exec-all.h"
#include "tcg.h"
#include "qemu/atomic.h"
#include "sysemu/qtest.h"
#include "qemu/timer.h"
#include "exec/address-spaces.h"
#include "qemu/rcu.h"
#include "exec/tb-hash.h"
#include "exec/log.h"
#include "qemu/main-loop.h"
#if defined(TARGET_I386) && !defined(CONFIG_USER_ONLY)
#include "hw/i386/apic.h"
#endif
#include "sysemu/cpus.h"
#include "sysemu/replay.h"

#include "../../afl-qemu-cpu-inl.h"

/* -icount align implementation. */

typedef struct SyncClocks {
    int64_t diff_clk;
    int64_t last_cpu_icount;
    int64_t realtime_clock;
} SyncClocks;

#if !defined(CONFIG_USER_ONLY)
/* Allow the guest to have a max 3ms advance.
 * The difference between the 2 clocks could therefore
 * oscillate around 0.
 */
#define VM_CLOCK_ADVANCE 3000000
#define THRESHOLD_REDUCE 1.5
#define MAX_DELAY_PRINT_RATE 2000000000LL
#define MAX_NB_PRINTS 100

static void align_clocks(SyncClocks *sc, const CPUState *cpu)
{
    int64_t cpu_icount;

    if (!icount_align_option) {
        return;
    }

    cpu_icount = cpu->icount_extra + cpu->icount_decr.u16.low;
    sc->diff_clk += cpu_icount_to_ns(sc->last_cpu_icount - cpu_icount);
    sc->last_cpu_icount = cpu_icount;

    if (sc->diff_clk > VM_CLOCK_ADVANCE) {
#ifndef _WIN32
        struct timespec sleep_delay, rem_delay;
        sleep_delay.tv_sec = sc->diff_clk / 1000000000LL;
        sleep_delay.tv_nsec = sc->diff_clk % 1000000000LL;
        if (nanosleep(&sleep_delay, &rem_delay) < 0) {
            sc->diff_clk = rem_delay.tv_sec * 1000000000LL + rem_delay.tv_nsec;
        } else {
            sc->diff_clk = 0;
        }
#else
        Sleep(sc->diff_clk / SCALE_MS);
        sc->diff_clk = 0;
#endif
    }
}

static void print_delay(const SyncClocks *sc)
{
    static float threshold_delay;
    static int64_t last_realtime_clock;
    static int nb_prints;

    if (icount_align_option &&
        sc->realtime_clock - last_realtime_clock >= MAX_DELAY_PRINT_RATE &&
        nb_prints < MAX_NB_PRINTS) {
        if ((-sc->diff_clk / (float)1000000000LL > threshold_delay) ||
            (-sc->diff_clk / (float)1000000000LL <
             (threshold_delay - THRESHOLD_REDUCE))) {
            threshold_delay = (-sc->diff_clk / 1000000000LL) + 1;
            printf("Warning: The guest is now late by %.1f to %.1f seconds\n",
                   threshold_delay - 1,
                   threshold_delay);
            nb_prints++;
            last_realtime_clock = sc->realtime_clock;
        }
    }
}

static void init_delay_params(SyncClocks *sc,
                              const CPUState *cpu)
{
    if (!icount_align_option) {
        return;
    }
    sc->realtime_clock = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL_RT);
    sc->diff_clk = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) - sc->realtime_clock;
    sc->last_cpu_icount = cpu->icount_extra + cpu->icount_decr.u16.low;
    if (sc->diff_clk < max_delay) {
        max_delay = sc->diff_clk;
    }
    if (sc->diff_clk > max_advance) {
        max_advance = sc->diff_clk;
    }

    /* Print every 2s max if the guest is late. We limit the number
       of printed messages to NB_PRINT_MAX(currently 100) */
    print_delay(sc);
}
#else
static void align_clocks(SyncClocks *sc, const CPUState *cpu)
{
}

static void init_delay_params(SyncClocks *sc, const CPUState *cpu)
{
}
#endif /* CONFIG USER ONLY */

/* Execute a TB, and fix up the CPU state afterwards if necessary */
static int next_output = 1;
extern int httpd_pgd;
int after = 0;

static inline tcg_target_ulong cpu_tb_exec(CPUState *cpu, TranslationBlock *itb)
{
    CPUArchState *env = cpu->env_ptr;
    uintptr_t ret;
    TranslationBlock *last_tb;
    int tb_exit;
    uint8_t *tb_ptr = itb->tc_ptr;

    target_ulong pc = env->active_tc.PC; //zyw mips
    AFL_QEMU_CPU_SNIPPET2(env, pc);

    qemu_log_mask_and_addr(CPU_LOG_EXEC, itb->pc,
                           "Trace %p [%d: " TARGET_FMT_lx "] %s\n",
                           itb->tc_ptr, cpu->cpu_index, itb->pc,
                           lookup_symbol(itb->pc));

#if defined(DEBUG_DISAS)
    if (qemu_loglevel_mask(CPU_LOG_TB_CPU)
        && qemu_log_in_addr_range(itb->pc)) {
        qemu_log_lock();
#if defined(TARGET_I386)
        log_cpu_state(cpu, CPU_DUMP_CCOP);
#else
        log_cpu_state(cpu, 0);
#endif
        qemu_log_unlock();
    }
#endif /* DEBUG_DISAS */

    cpu->can_do_io = !use_icount;

/*
    if(httpd_pgd !=0 && itb->pc == 0x453c50)   
    {
        DECAF_printf("before tcg_qemu_tb_exec pc:%x\n", itb->pc);
    }

    if(httpd_pgd !=0 && after > 0 && itb->pc < 0x70000000)   
    {
        DECAF_printf("********************pc:%x\n", itb->pc);
        after--;
    }
*/


    ret = tcg_qemu_tb_exec(env, tb_ptr);
    cpu->can_do_io = 1;
    
    last_tb = (TranslationBlock *)(ret & ~TB_EXIT_MASK);
    tb_exit = ret & TB_EXIT_MASK;
    trace_exec_tb_exit(last_tb, tb_exit);

    if (tb_exit > TB_EXIT_IDX1) {
        /* We didn't start executing this TB (eg because the instruction
         * counter hit zero); we must restore the guest PC to the address
         * of the start of the TB.
         */
        CPUClass *cc = CPU_GET_CLASS(cpu);
        qemu_log_mask_and_addr(CPU_LOG_EXEC, last_tb->pc,
                               "Stopped execution of TB chain before %p ["
                               TARGET_FMT_lx "] %s\n",
                               last_tb->tc_ptr, last_tb->pc,
                               lookup_symbol(last_tb->pc));
        if (cc->synchronize_from_tb) {
            cc->synchronize_from_tb(cpu, last_tb);
        } else {
            assert(cc->set_pc);
            cc->set_pc(cpu, last_tb->pc);
        }
    }
//zyw fix

    else
    {	
    	 AFL_QEMU_CPU_SNIPPET2(env, pc);
    }

    return ret;
}

#ifndef CONFIG_USER_ONLY
/* Execute the code without caching the generated code. An interpreter
   could be used if available. */
static void cpu_exec_nocache(CPUState *cpu, int max_cycles,
                             TranslationBlock *orig_tb, bool ignore_icount)
{
    TranslationBlock *tb;

    /* Should never happen.
       We only end up here when an existing TB is too long.  */
    if (max_cycles > CF_COUNT_MASK)
        max_cycles = CF_COUNT_MASK;

    tb_lock();
    tb = tb_gen_code(cpu, orig_tb->pc, orig_tb->cs_base, orig_tb->flags,
                     max_cycles | CF_NOCACHE
                         | (ignore_icount ? CF_IGNORE_ICOUNT : 0));
    tb->orig_tb = orig_tb;
    tb_unlock();

    /* execute the generated code */
    trace_exec_tb_nocache(tb, tb->pc);
    cpu_tb_exec(cpu, tb);

    tb_lock();
    tb_phys_invalidate(tb, -1);
    tb_free(tb);
    tb_unlock();
}
#endif

static void cpu_exec_step(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint32_t flags;

    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    if (sigsetjmp(cpu->jmp_env, 0) == 0) {
        mmap_lock();
        tb_lock();
        tb = tb_gen_code(cpu, pc, cs_base, flags,
                         1 | CF_NOCACHE | CF_IGNORE_ICOUNT);
        tb->orig_tb = NULL;
        tb_unlock();
        mmap_unlock();

        cc->cpu_exec_enter(cpu);
        /* execute the generated code */
        trace_exec_tb_nocache(tb, pc);
        cpu_tb_exec(cpu, tb);
        cc->cpu_exec_exit(cpu);

        tb_lock();
        tb_phys_invalidate(tb, -1);
        tb_free(tb);
        tb_unlock();
    } else {
        /* We may have exited due to another problem here, so we need
         * to reset any tb_locks we may have taken but didn't release.
         * The mmap_lock is dropped by tb_gen_code if it runs out of
         * memory.
         */
#ifndef CONFIG_SOFTMMU
        tcg_debug_assert(!have_mmap_lock());
#endif
        tb_lock_reset();
    }
}

void cpu_exec_step_atomic(CPUState *cpu)
{
    start_exclusive();

    /* Since we got here, we know that parallel_cpus must be true.  */
    parallel_cpus = false;
    cpu_exec_step(cpu);
    parallel_cpus = true;

    end_exclusive();
}

struct tb_desc {
    target_ulong pc;
    target_ulong cs_base;
    CPUArchState *env;
    tb_page_addr_t phys_page1;
    uint32_t flags;
    uint32_t trace_vcpu_dstate;
};

static bool tb_cmp(const void *p, const void *d)
{
    const TranslationBlock *tb = p;
    const struct tb_desc *desc = d;

    if (tb->pc == desc->pc &&
        tb->page_addr[0] == desc->phys_page1 &&
        tb->cs_base == desc->cs_base &&
        tb->flags == desc->flags &&
        tb->trace_vcpu_dstate == desc->trace_vcpu_dstate &&
        !atomic_read(&tb->invalid)) {
        /* check next page if needed */
        if (tb->page_addr[1] == -1) {
            return true;
        } else {
            tb_page_addr_t phys_page2;
            target_ulong virt_page2;

            virt_page2 = (desc->pc & TARGET_PAGE_MASK) + TARGET_PAGE_SIZE;
            phys_page2 = get_page_addr_code(desc->env, virt_page2);
            if (tb->page_addr[1] == phys_page2) {
                return true;
            }
        }
    }
    return false;
}

TranslationBlock *tb_htable_lookup(CPUState *cpu, target_ulong pc,
                                   target_ulong cs_base, uint32_t flags)
{
    tb_page_addr_t phys_pc;
    struct tb_desc desc;
    uint32_t h;

    desc.env = (CPUArchState *)cpu->env_ptr;
    desc.cs_base = cs_base;
    desc.flags = flags;
    desc.trace_vcpu_dstate = *cpu->trace_dstate;
    desc.pc = pc;
    phys_pc = get_page_addr_code(desc.env, pc);
//zyw    
    //printf("phys_pc is:%x,%x\n", pc, phys_pc);
    desc.phys_page1 = phys_pc & TARGET_PAGE_MASK;
    h = tb_hash_func(phys_pc, pc, flags, *cpu->trace_dstate);
    return qht_lookup(&tcg_ctx.tb_ctx.htable, tb_cmp, &desc, h);
}


extern int flagg;
extern int helper_flag;
int curr_state_pc;
extern int httpd_pgd;
struct timeval tlb_handle_begin_new;
struct timeval tlb_handle_begin;
struct timeval tlb_handle_end;
struct timeval syscall_begin;
struct timeval syscall_end;
struct timeval syscall_codegen_begin;
struct timeval syscall_codegen_end;
double syscall_codegen_time = 0.0;
double total_syscall_codegen_time = 0.0;
int into_syscall = 0;
int into_tlb_handle = 0;

static inline TranslationBlock *tb_find(CPUState *cpu,
                                        TranslationBlock *last_tb,
                                        int tb_exit)
{
    CPUArchState *env = (CPUArchState *)cpu->env_ptr;
    TranslationBlock *tb;
    target_ulong cs_base, pc;
    uint32_t flags;
    bool have_tb_lock = false;

    /* we record a subset of the CPU state. It will
       always be the same before a given translated block
       is executed. */
    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    tb = atomic_rcu_read(&cpu->tb_jmp_cache[tb_jmp_cache_hash_func(pc)]);
    if (unlikely(!tb || tb->pc != pc || tb->cs_base != cs_base ||
                 tb->flags != flags ||
                 tb->trace_vcpu_dstate != *cpu->trace_dstate)) {
        tb = tb_htable_lookup(cpu, pc, cs_base, flags);
        
        if (!tb) {
            /* mmap_lock is needed by tb_gen_code, and mmap_lock must be
             * taken outside tb_lock. As system emulation is currently
             * single threaded the locks are NOPs.
             */
            mmap_lock();
            tb_lock();
            have_tb_lock = true;

            /* There's a chance that our desired tb has been translated while
             * taking the locks so we check again inside the lock.
             */
            tb = tb_htable_lookup(cpu, pc, cs_base, flags);
            if (!tb) {
                /* if no translated code available, then translate it now */
/*
                if(afl_user_fork)
                {   
                    target_ulong pgd = DECAF_getPGD(cpu);
                    printf("regenerate code????????????? pgd:%x\n", pgd);
                }
*/
                tb = tb_gen_code(cpu, pc, cs_base, flags, 0);
                //AFL_QEMU_CPU_SNIPPET1; //zyw should determined if in specific program
            
            }

            mmap_unlock();
        }
        /* We add the TB in the virtual pc hash table for the fast lookup */
        atomic_set(&cpu->tb_jmp_cache[tb_jmp_cache_hash_func(pc)], tb);
    }

#ifdef NOPE_NOT_NEVER 

#ifndef CONFIG_USER_ONLY
    /* We don't take care of direct jumps when address mapping changes in
     * system emulation. So it's not safe to make a direct jump to a TB
     * spanning two pages because the mapping for the second page can change.
     */
    if (tb->page_addr[1] != -1) {
        last_tb = NULL;
    }
#endif
//zyw


    /* See if we can patch the calling TB. */
    if (last_tb && !qemu_loglevel_mask(CPU_LOG_TB_NOCHAIN)) {
        if (!have_tb_lock) {
            tb_lock();
            have_tb_lock = true;
        }
        if (!tb->invalid) {
            tb_add_jump(last_tb, tb_exit, tb);
        }
    }
#endif
//zyw
    if (have_tb_lock) {
        tb_unlock();
    }
    return tb;
}


static inline bool cpu_handle_halt(CPUState *cpu)
{
    if (cpu->halted) {
#if defined(TARGET_I386) && !defined(CONFIG_USER_ONLY)
        if ((cpu->interrupt_request & CPU_INTERRUPT_POLL)
            && replay_interrupt()) {
            X86CPU *x86_cpu = X86_CPU(cpu);
            qemu_mutex_lock_iothread();
            apic_poll_irq(x86_cpu->apic_state);
            cpu_reset_interrupt(cpu, CPU_INTERRUPT_POLL);
            qemu_mutex_unlock_iothread();
        }
#endif
        if (!cpu_has_work(cpu)) {
            return true;
        }

        cpu->halted = 0;
    }

    return false;
}

static inline void cpu_handle_debug_exception(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    CPUWatchpoint *wp;

    if (!cpu->watchpoint_hit) {
        QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
            wp->flags &= ~BP_WATCHPOINT_HIT;
        }
    }

    cc->debug_excp_handler(cpu);
}

static inline bool cpu_handle_exception(CPUState *cpu, int *ret)
{
    if (cpu->exception_index >= 0) {
        if (cpu->exception_index >= EXCP_INTERRUPT) {
            /* exit request from the cpu execution loop */
            *ret = cpu->exception_index;
            if (*ret == EXCP_DEBUG) {
                cpu_handle_debug_exception(cpu);
            }
            cpu->exception_index = -1;
            return true;
        } else {
#if defined(CONFIG_USER_ONLY)
            /* if user mode only, we simulate a fake exception
               which will be handled outside the cpu execution
               loop */
#if defined(TARGET_I386)
            CPUClass *cc = CPU_GET_CLASS(cpu);
            cc->do_interrupt(cpu);
#endif
            *ret = cpu->exception_index;
            cpu->exception_index = -1;
            return true;
#else
            if (replay_exception()) {
                CPUClass *cc = CPU_GET_CLASS(cpu);
                qemu_mutex_lock_iothread();
                cc->do_interrupt(cpu);
                qemu_mutex_unlock_iothread();
                cpu->exception_index = -1;
            } else if (!replay_has_interrupt()) {
                /* give a chance to iothread in replay mode */
                *ret = EXCP_INTERRUPT;
                return true;
            }
#endif
        }
#ifndef CONFIG_USER_ONLY
    } else if (replay_has_exception()
               && cpu->icount_decr.u16.low + cpu->icount_extra == 0) {
        /* try to cause an exception pending in the log */
        cpu_exec_nocache(cpu, 1, tb_find(cpu, NULL, 0), true);
        *ret = -1;
        return true;
#endif
    }

    return false;
}

extern int flagg;
static inline bool cpu_handle_interrupt(CPUState *cpu, TranslationBlock **last_tb)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    if (unlikely(atomic_read(&cpu->interrupt_request))) {
        int interrupt_request;
        qemu_mutex_lock_iothread();
        interrupt_request = cpu->interrupt_request;
        if (unlikely(cpu->singlestep_enabled & SSTEP_NOIRQ)) {
            /* Mask out external interrupts for this step. */
            interrupt_request &= ~CPU_INTERRUPT_SSTEP_MASK;
        }
	//if (flagg == 2) DECAF_printf("interrupt:%x\n", interrupt_request);
        if (interrupt_request & CPU_INTERRUPT_DEBUG) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_DEBUG;
            cpu->exception_index = EXCP_DEBUG;
            qemu_mutex_unlock_iothread();
            return true;
        }
        if (replay_mode == REPLAY_MODE_PLAY && !replay_has_interrupt()) {
            /* Do nothing */
        } else if (interrupt_request & CPU_INTERRUPT_HALT) {
            replay_interrupt();
            cpu->interrupt_request &= ~CPU_INTERRUPT_HALT;
            cpu->halted = 1;
            cpu->exception_index = EXCP_HLT;
            qemu_mutex_unlock_iothread();
            return true;
        }
#if defined(TARGET_I386)
        else if (interrupt_request & CPU_INTERRUPT_INIT) {
            X86CPU *x86_cpu = X86_CPU(cpu);
            CPUArchState *env = &x86_cpu->env;
            replay_interrupt();
            cpu_svm_check_intercept_param(env, SVM_EXIT_INIT, 0, 0);
            do_cpu_init(x86_cpu);
            cpu->exception_index = EXCP_HALTED;
            qemu_mutex_unlock_iothread();
            return true;
        }
#else
        else if (interrupt_request & CPU_INTERRUPT_RESET) {
            replay_interrupt();
            cpu_reset(cpu);
            qemu_mutex_unlock_iothread();
            return true;
        }
#endif
        /* The target hook has 3 exit conditions:
           False when the interrupt isn't processed,
           True when it is, and we should restart on a new TB,
           and via longjmp via cpu_loop_exit.  */
        else {
            if (cc->cpu_exec_interrupt(cpu, interrupt_request)) {
                replay_interrupt();
                *last_tb = NULL;
            }
            /* The target hook may have updated the 'cpu->interrupt_request';
             * reload the 'interrupt_request' value */
            interrupt_request = cpu->interrupt_request;
        }
        if (interrupt_request & CPU_INTERRUPT_EXITTB) {
            cpu->interrupt_request &= ~CPU_INTERRUPT_EXITTB;
            /* ensure that no TB jump will be modified as
               the program flow was changed */
            *last_tb = NULL;
        }

        /* If we exit via cpu_loop_exit/longjmp it is reset in cpu_exec */
        qemu_mutex_unlock_iothread();
    }

    /* Finally, check if we need to exit to the main loop.  */
    if (unlikely(atomic_read(&cpu->exit_request)
        || (use_icount && cpu->icount_decr.u16.low + cpu->icount_extra == 0))) {
        atomic_set(&cpu->exit_request, 0);
        cpu->exception_index = EXCP_INTERRUPT;
        return true;
    }

    return false;
}

//zyw

void afl_wait_tsl(CPUState *cpu, int fd) {

  struct afl_tsl t;
  TranslationBlock *tb;

  while (1) {


    if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
      break;
    if(t.pc < 0x80000000 && t.pc>0x70000000) continue;
    printf("read pc:%x\n",  t.pc);
    qemu_mutex_unlock_iothread();
    int ret;
    if (sigsetjmp(cpu->jmp_env, 0) != 0) {
        cpu->can_do_io = 1;
        tb_lock_reset();
        if (qemu_mutex_iothread_locked()) {
            qemu_mutex_unlock_iothread();
        }
    }
    while (!cpu_handle_exception(cpu, &ret)) {
      TranslationBlock *last_tb = NULL;
      int tb_exit = 0;
      while (!cpu_handle_interrupt(cpu, &last_tb)) {
        tb = tb_htable_lookup(cpu, t.pc, t.cs_base, t.flags);
        if(!tb) {
          mmap_lock();
          tb_lock();
          tb_gen_code(cpu, t.pc, t.cs_base, t.flags, 0);
          mmap_unlock();
          tb_unlock();
        }
        goto end;
      }
    }
end:
    qemu_mutex_lock_iothread();

  }
  close(fd);

}

/*
void afl_wait_tsl(CPUState *cpu, int fd) {

  struct afl_tsl t;
  TranslationBlock *tb;

  while (1) {
    if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
      break;

    tb = tb_htable_lookup(cpu, t.pc, t.cs_base, t.flags);
    if(!tb) {
      mmap_lock();
      tb_lock();
      tb_gen_code(cpu, t.pc, t.cs_base, t.flags, 0);
      mmap_unlock();
      tb_unlock();
    }

  }
  close(fd);

}
*/

static inline void cpu_loop_exec_tb(CPUState *cpu, TranslationBlock *tb,
                                    TranslationBlock **last_tb, int *tb_exit)
{
    uintptr_t ret;
    int32_t insns_left;
    trace_exec_tb(tb, tb->pc);
    CPUArchState *env = cpu->env_ptr;
    ret = cpu_tb_exec(cpu, tb);
    tb = (TranslationBlock *)(ret & ~TB_EXIT_MASK);
    *tb_exit = ret & TB_EXIT_MASK;
    if (*tb_exit != TB_EXIT_REQUESTED) {
        *last_tb = tb;
        return;
    }
    *last_tb = NULL;
    
    insns_left = atomic_read(&cpu->icount_decr.u32);
    atomic_set(&cpu->icount_decr.u16.high, 0);
    if (insns_left < 0) {
        /* Something asked us to stop executing chained TBs; just
         * continue round the main loop. Whatever requested the exit
         * will also have set something else (eg exit_request or
         * interrupt_request) which we will handle next time around
         * the loop.  But we need to ensure the zeroing of icount_decr
         * comes before the next read of cpu->exit_request
         * or cpu->interrupt_request.
         */
        smp_mb();
        return;
    }
    /* Instruction counter expired.  */
    assert(use_icount);
#ifndef CONFIG_USER_ONLY
    /* Ensure global icount has gone forward */
    cpu_update_icount(cpu);
    /* Refill decrementer and continue execution.  */
    insns_left = MIN(0xffff, cpu->icount_budget);
    cpu->icount_decr.u16.low = insns_left;
    cpu->icount_extra = cpu->icount_budget - insns_left;
    if (!cpu->icount_extra) {
        /* Execute any remaining instructions, then let the main loop
         * handle the next event.
         */
        if (insns_left > 0) {
            cpu_exec_nocache(cpu, insns_left, tb, false);
        }
    }
#endif
}

int fork_times = 0;
/* main execution loop */

int cpu_exec(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    int ret;
    SyncClocks sc = { 0 };

    /* replay_interrupt may need current_cpu */
    current_cpu = cpu;

    if (cpu_handle_halt(cpu)) {
        return EXCP_HALTED;
    }
    rcu_read_lock();

    cc->cpu_exec_enter(cpu);
    /* Calculate difference between guest clock and host clock.
     * This delay includes the delay of the last cycle, so
     * what we have to do is sleep until it is 0. As for the
     * advance/delay we gain here, we try to fix it next time.
     */
    init_delay_params(&sc, cpu);

    /* prepare setjmp context for exception handling */
    if (sigsetjmp(cpu->jmp_env, 0) != 0) {
#if defined(__clang__) || !QEMU_GNUC_PREREQ(4, 6)
        /* Some compilers wrongly smash all local variables after
         * siglongjmp. There were bug reports for gcc 4.5.0 and clang.
         * Reload essential local variables here for those compilers.
         * Newer versions of gcc would complain about this code (-Wclobbered). */
        cpu = current_cpu;
        cc = CPU_GET_CLASS(cpu);
#else /* buggy compiler */
        /* Assert that the compiler does not smash local variables. */
        g_assert(cpu == current_cpu);
        g_assert(cc == CPU_GET_CLASS(cpu));
#endif /* buggy compiler */
        cpu->can_do_io = 1;
        tb_lock_reset();
        if (qemu_mutex_iothread_locked()) {
            qemu_mutex_unlock_iothread();
        }
    }
    CPUArchState * env = cpu->env_ptr;

//zyw
#ifdef FIND_FORK_START
    if(afl_user_fork == 0 && cpu->exception_index == 17)
    {
        curr_state_pc = env->active_tc.PC;
        into_syscall = env->active_tc.gpr[2];
        target_ulong pgd = DECAF_getPGD(cpu);
        if(pgd == httpd_pgd) {
            //DECAF_printf("sys num:%d pc:%x\n", env->active_tc.gpr[2], env->active_tc.PC);
        }
    }
#endif
    if(afl_user_fork && cpu->exception_index == 17 && into_syscall == 0)
    {
        target_ulong pgd = DECAF_getPGD(cpu);
        if(pgd == httpd_pgd) {
            gettimeofday(&syscall_begin, NULL);
            into_syscall = env->active_tc.gpr[2];
            curr_state_pc = env->active_tc.PC;
            if(print_debug)
            {   
                DECAF_printf("----------------------------------------------------------\n");
                DECAF_printf("sys num:%d pc:%x ra:%x, a0:%x, sp:%x, pgd:%x, epc:%x, status:%x, cause:%x\n", 
                    env->active_tc.gpr[2], env->active_tc.PC, env->active_tc.gpr[31], env->active_tc.gpr[4], env->active_tc.gpr[29], pgd, env->CP0_EPC, env->CP0_Status, env->CP0_Cause);
            }
#ifndef NO_FORKSERVER
            //zyw need change
            //if(env->active_tc.gpr[2] == 4142){ //tplink httpd _newselect
           //if(env->active_tc.gpr[2] == 4001 || env->active_tc.gpr[2] == 4246){//exit, exit_group 
            // if(env->active_tc.gpr[2] == 4188){//poll Netgear lighttpd
            //if(env->active_tc.gpr[2] == 4002){//fork httpd d-link
            //if(env->active_tc.gpr[2] == 4175){//fork httpd tplink user mode 
            //if(env->active_tc.gpr[2] ==4169) {//d-link dnsmasq cannot go over brk
            // (env->active_tc.gpr[2] == 4002) {//d-link dnsmasq cannot go over brk
           if(env->active_tc.gpr[2] == 4002 || env->active_tc.gpr[2] == 4001 || env->active_tc.gpr[2] == 4246){
#ifndef QEMU_SNAPSHOT
                gettimeofday(&restore_begin, NULL);
                restore_page(0);
                gettimeofday(&restore_end, NULL);      
                double restore_time = (double)restore_end.tv_sec - restore_begin.tv_sec + (restore_end.tv_usec - restore_begin.tv_usec)/1000000.0;
#else
                double restore_time = (double)load_snapshot_end.tv_sec - load_snapshot_start.tv_sec + (load_snapshot_end.tv_usec - load_snapshot_start.tv_usec)/1000000.0;
#endif

                gettimeofday(&loop_end, NULL);
                double total_loop_time =  (double)loop_end.tv_sec - loop_begin.tv_sec + (loop_end.tv_usec - loop_begin.tv_usec)/1000000.0;

                if(print_loop_count == print_loop_times)
                {
                    print_loop_count = 0;
                    //DECAF_printf("total loop time:%fs,syacall execute:%fs, tlb_handle_time:%fs, snapshot time:%fs, rest time:%fs\n", total_loop_time, time_interval_total, tlb_time_interval_total, restore_time*2, total_loop_time - time_interval_total - restore_time *2);
                    DECAF_printf("%f:%f:%f:%f:%f:%d\n", total_loop_time, time_interval_total, tlb_time_interval_total, restore_time, total_loop_time - time_interval_total - restore_time, syscall_count);
                }
                tlb_time_interval_total = 0.0;
                time_interval_total = 0.0;
                syscall_count = 0;
                total_syscall_codegen_time = 0.0;

                struct itimerval tick;
                memset(&tick, 0, sizeof(tick));    
                tick.it_value.tv_sec = 1;  // sec  //set to 5
                tick.it_value.tv_usec = 0; // micro sec
                int ret = setitimer(ITIMER_REAL, &tick, NULL);


#ifndef QEMU_SNAPSHOT
                int ret_value = env->active_tc.gpr[4];
                if(ret_value = -1)
                {   
                    ret_value = 0;
                }
                doneWork(ret_value);
#else           
                endWork(0);
#endif
                //afl_endWork_restart(env);
                //afl_wants_cpu_to_stop = 1;
            
            }
#endif

        }

    } 
    /* if an exception is pending, we execute it here */
#ifndef TLB_NEW_CAL
    if(afl_user_fork && (cpu->exception_index == 26 || cpu->exception_index == 27) && into_tlb_handle == 0 && env->active_tc.PC < 0x80000000) //target/mips/cpu.h  EXCP_TLBL 26  EXCP_TLBS 27
    {
        target_ulong new_pgd = DECAF_getPGD(cpu);
        if(new_pgd == httpd_pgd){ //user_stack_count
            gettimeofday(&tlb_handle_begin, NULL);
            //DECAF_printf("exception:%d\n", cpu->exception_index);
            into_tlb_handle = cpu->exception_index;
        }
    }
#endif

    while (!cpu_handle_exception(cpu, &ret)) {
        TranslationBlock *last_tb = NULL;
        int tb_exit = 0;
        while (!cpu_handle_interrupt(cpu, &last_tb)) {
            if(env->active_tc.PC == start_fork_pc && afl_user_fork == 0 && fork_times == 0) 
            {
                /*
                DECAF_printf("meet start_fork_pc:%x\n", start_fork_pc);
                char buf[1000];
                DECAF_read_mem(cpu, env->active_tc.gpr[5], 1000, buf);
                //if(strstr(buf, "hedwig")!=0)
                //if(strstr(buf, "PingIframeRpm.htm")!=0) //tplink

                if(strstr(buf, "chrome-extension")!=0)
                {
                    startTrace(cpu, 0x400000L, 0x500000L);
                    fork_times = 1;
                    afl_wants_cpu_to_stop = 1;
                    goto end;
                }
                */
                target_ulong pgd = DECAF_getPGD(cpu);
                if(pgd == httpd_pgd)
                {
                    startTrace(cpu, 0, 0x80000000);
                    fork_times = 1;
                    afl_wants_cpu_to_stop = 1;
                    goto end; 
                }    
                
            }

//zyw
#ifdef FIND_FORK_START
            if(afl_user_fork == 0 && env->active_tc.PC ==  curr_state_pc + 4 && into_syscall)
            {    
                if(into_syscall == 4175 || into_syscall == 4176 || into_syscall == 4003)
                {
                    target_ulong pgd = DECAF_getPGD(cpu);
                    if(pgd == httpd_pgd) {
                        char buf[1000];
                        DECAF_read_mem(cpu, env->active_tc.gpr[5], 1000, buf);
                        //if(strstr(buf, "hedwig")!=0)
                        //if(strstr(buf, "PingIframeRpm.htm")!=0) //tplink
                        if(strstr(buf, "chrome-extension")!=0)
                        {
                            target_ulong pgd = DECAF_getPGD(cpu);
                            DECAF_printf("recv:%s pgd:%x, stack:%x\n", buf, pgd, env->active_tc.gpr[29]);
                            print_pc_times = 5;
                        }       
                    }
                }
                /*
                else if(into_syscall == 4045)
                {
                    target_ulong pgd = DECAF_getPGD(cpu);
                    if(pgd == httpd_pgd) {
                        print_pc_times = 5;
                    }
                }
                */
                curr_state_pc = 0;
                into_syscall = 0;              
            }
#endif
            if(afl_user_fork && env->active_tc.PC ==  curr_state_pc + 4 && into_syscall)
            {
                target_ulong new_pgd = DECAF_getPGD(cpu);
                if(new_pgd == httpd_pgd){ //user_stack_count
                    if(print_debug){
                        DECAF_printf("end pc:%x, ra:%x, ret:%x, err:%x, sp:%x, exit:%x, pid:%d\n", env->active_tc.PC,env->active_tc.gpr[31],  env->active_tc.gpr[2], env->active_tc.gpr[7], env->active_tc.gpr[29], ret, getpid());
                    }
                    /*
                    if(into_syscall == 4045){
                        DECAF_printf("end pc:%x, ret:%x, err:%x, sp:%x, exit:%x, pid:%d\n", env->active_tc.PC, env->active_tc.gpr[2], env->active_tc.gpr[7], env->active_tc.gpr[29], ret, getpid());
                        print_pc_times = 5;
                    }
                    */
#ifndef NO_FORKSERVER                  
                    //if(into_syscall == 4002){//fork httpd d-link
                    //if(into_syscall == 4004){//hedwig.cgi next is exit
                    //if(into_syscall == 4169){//d-link dnsmasq
                    //if(into_syscall == 4169){//tplink httpd
                    //if(into_syscall == 4006 && env->active_tc.gpr[31] == 0x40aeb8){ //jhttpd
                    //if(into_syscall == 4142 && env->active_tc.gpr[31] != 0x4f1b74){ //tplink httpd
                    //if(into_syscall == 4116 && env->active_tc.gpr[31] != 0x4c85b4){ //tplink httpd
                    if(into_syscall == 4001){ //tplink httpd
#ifndef QEMU_SNAPSHOT
                        gettimeofday(&restore_begin, NULL);
                        restore_page(0);
                        gettimeofday(&restore_end, NULL);      
                        double restore_time = (double)restore_end.tv_sec - restore_begin.tv_sec + (restore_end.tv_usec - restore_begin.tv_usec)/1000000.0;
#else
                        double restore_time = (double)load_snapshot_end.tv_sec - load_snapshot_start.tv_sec + (load_snapshot_end.tv_usec - load_snapshot_start.tv_usec)/1000000.0;
#endif

                        gettimeofday(&loop_end, NULL);
                        double total_loop_time =  (double)loop_end.tv_sec - loop_begin.tv_sec + (loop_end.tv_usec - loop_begin.tv_usec)/1000000.0;

                        if(print_loop_count == print_loop_times)
                        {
                            print_loop_count = 0;
                            //DECAF_printf("total loop time:%fs,syacall execute:%fs, tlb_handle_time:%fs, snapshot time:%fs, rest time:%fs\n", total_loop_time, time_interval_total, tlb_time_interval_total, restore_time*2, total_loop_time - time_interval_total - restore_time *2);
                            DECAF_printf("%f:%f:%f:%f:%f:%d\n", total_loop_time, time_interval_total, tlb_time_interval_total, restore_time, total_loop_time - time_interval_total - restore_time -tlb_time_interval_total, syscall_count);

                        }
                        tlb_time_interval_total = 0.0;
                        time_interval_total = 0.0;
                        syscall_count = 0;
                        total_syscall_codegen_time = 0.0;
#ifndef QEMU_SNAPSHOT
                        doneWork(0);
#else
                        endWork(0);
#endif
                    }
#endif

                    
                    //if(env->acti/ve_tc.gpr[7]!=0)  env->active_tc.gpr[2]=0xffffffff;  //NEED MODIFY for http accept, zywzyw
                    gettimeofday(&syscall_end, NULL);
                    time_interval = (double)syscall_end.tv_sec - syscall_begin.tv_sec + (syscall_end.tv_usec - syscall_begin.tv_usec)/1000000.0;
                    time_interval_total += time_interval;
                    //DECAF_printf("syscall execute:%f, syscall without code gen:%f, pid:%x\n",time_interval, time_interval - syscall_codegen_time, getpid());
                    //DECAF_printf("syscall execute:%f, pid:%x\n",time_interval, getpid());
                    total_syscall_codegen_time += syscall_codegen_time;
                    //DECAF_printf("syscall codegen time:%fs,%fs\n", syscall_codegen_time, total_syscall_codegen_time);
                    syscall_count++;
                    syscall_codegen_time = 0.0;

                    curr_state_pc = 0;
                    into_syscall = 0;

//

                }
            }
            if(afl_user_fork && into_tlb_handle && env->active_tc.PC < 0x80000000) //target/mips/cpu.h  EXCP_TLBL 26  EXCP_TLBS 27
            {
                //target_ulong new_pgd = DECAF_getPGD(cpu);
                //if(new_pgd == httpd_pgd){ 
                    into_tlb_handle = 0;
                    gettimeofday(&tlb_handle_end, NULL);
                    //DECAF_printf("exception end:%d\n", cpu->exception_index);
                    #ifdef TLB_NEW_CAL
                        tlb_time_interval = (double)tlb_handle_end.tv_sec - tlb_handle_begin_new.tv_sec + (tlb_handle_end.tv_usec - tlb_handle_begin_new.tv_usec)/1000000.0;
                    #else
                        tlb_time_interval = (double)tlb_handle_end.tv_sec - tlb_handle_begin.tv_sec + (tlb_handle_end.tv_usec - tlb_handle_begin.tv_usec)/1000000.0;
                    #endif
                    tlb_time_interval_total += tlb_time_interval;
               // }
            }

#ifdef FIND_FORK_START
            if(print_pc_times && env->active_tc.PC < 0x70000000){
                target_ulong pgd = DECAF_getPGD(cpu);
                if(pgd == httpd_pgd)
                {
                    DECAF_printf("pc:%x, pgd:%x\n", env->active_tc.PC, pgd);
                    sleep(1);
                    print_pc_times--;
                }  
            }
#endif

#ifdef NO_FORKSERVER          
            //if(afl_user_fork && env->active_tc.PC == 0x415bac && into_syscall == 0)// before exit dnsmasq dlink httpd;
            //if(afl_user_fork && env->active_tc.PC == 0x457850 && into_syscall == 0)// before poll netgear lighttpd;
            //if(afl_user_fork && env->active_tc.PC == 0x40ae58 && into_syscall == 0)// Trendnet jjhttpd
            if(afl_user_fork && (env->active_tc.PC == 0x4033e8 || env->active_tc.PC == 0x4033e8) && into_syscall == 0)// Trendnet jjhttpd
            {
                
                target_ulong new_pgd = DECAF_getPGD(cpu);
                if(new_pgd == httpd_pgd){ //user_stack_count
                    gettimeofday(&restore_begin, NULL);
                    restore_page(0);
                    gettimeofday(&restore_end, NULL);      
                    double restore_time = (double)restore_end.tv_sec - restore_begin.tv_sec + (restore_end.tv_usec - restore_begin.tv_usec)/1000000.0;

                    gettimeofday(&loop_end, NULL);
                    double total_loop_time =  (double)loop_end.tv_sec - loop_begin.tv_sec + (loop_end.tv_usec - loop_begin.tv_usec)/1000000.0;

                    //DECAF_printf("----------------------------------------------------------\n");
                    if(print_loop_count == print_loop_times)
                    {
                        print_loop_count = 0;
                        //DECAF_printf("total loop time:%fs,syacall execute:%fs, tlb_handle_time:%fs, snapshot time:%fs, rest time:%fs\n", total_loop_time, time_interval_total, tlb_time_interval_total, restore_time*2, total_loop_time - time_interval_total - restore_time *2);
                        DECAF_printf("%f:%f:%f:%f:%f:%d\n", total_loop_time, time_interval_total, tlb_time_interval_total, restore_time, total_loop_time - time_interval_total - restore_time -tlb_time_interval_total, syscall_count);

                    }

                    tlb_time_interval_total = 0.0;
                    time_interval_total = 0.0;
                    syscall_count = 0;
                    total_syscall_codegen_time = 0.0;


                    //doneWork(0);
                    //afl_wants_cpu_to_stop = 1;
                    afl_endWork_restart(env);
                }
                
            }
#endif

            //if(afl_user_fork && into_syscall) gettimeofday(&syscall_codegen_begin, NULL);

            TranslationBlock *tb = tb_find(cpu, last_tb, tb_exit);
/*
            if(afl_user_fork && into_syscall) 
            {
                gettimeofday(&syscall_codegen_end, NULL);
                double block_codegen_time = (double)syscall_codegen_end.tv_sec - syscall_codegen_begin.tv_sec + (syscall_codegen_end.tv_usec - syscall_codegen_begin.tv_usec)/1000000.0;
                syscall_codegen_time += block_codegen_time;
            }
*/

//feed input
#ifdef FEED_INPUT
            if(afl_user_fork == 1 && env->active_tc.PC == start_fork_pc)
            {   
                //int feed_input_addr = env->active_tc.gpr[5];
                //int feed_input_addr = env->active_tc.gpr[4]; //sample
                int feed_input_addr = env->active_tc.gpr[2]; //sample
                char buf[1000];
                char ori_buf[1000];
                int len = getWork(env, buf, 1000);
                DECAF_read_mem(cpu, feed_input_addr, 1000, ori_buf); // //cpu_memory_rw_debug(cpu, feed_input_addr, ori_buf, 1000, 0); slow

                /*    
                FILE * fp = fopen("/home/zyw/tmp/triforceafl_new/inputs_bak/Trendnet_input", "a+");
                fprintf(fp, "%s", ori_buf);
                fclose(fp);
                */
                DECAF_printf("orig_input:%s,%d, feed_input:%s,%d\n", ori_buf, env->active_tc.gpr[2], buf, len);
                DECAF_write_mem(cpu, feed_input_addr, len, ori_buf);// cpu_memory_rw_debug(cpu, feed_input_addr, ori_buf, len, 1); slow hang the system?
                env->active_tc.gpr[2] =len;
            }
#endif
            /*
            if(afl_user_fork == 1 && env->active_tc.PC < 0x80000000)
            {
                target_ulong new_pgd = DECAF_getPGD(cpu);
                if(new_pgd == httpd_pgd){
                    DECAF_printf("pc is :%x\n", env->active_tc.PC);
                    //sleep(1);
                }

            }
            */
  
            cpu_loop_exec_tb(cpu, tb, &last_tb, &tb_exit);
            /* Try to align the host and virtual clocks
               if the guest is in advance */
            align_clocks(&sc, cpu);
        }
    }
end:
    cc->cpu_exec_exit(cpu);
    rcu_read_unlock();
    return ret;
}


void stopWork()
{
#ifndef QEMU_SNAPSHOT
    gettimeofday(&restore_begin, NULL);
    restore_page(0);
    gettimeofday(&restore_end, NULL);      
    double restore_time = (double)restore_end.tv_sec - restore_begin.tv_sec + (restore_end.tv_usec - restore_begin.tv_usec)/1000000.0;
#else
    double restore_time = (double)load_snapshot_end.tv_sec - load_snapshot_start.tv_sec + (load_snapshot_end.tv_usec - load_snapshot_start.tv_usec)/1000000.0;
#endif

    gettimeofday(&loop_end, NULL);
    double total_loop_time =  (double)loop_end.tv_sec - loop_begin.tv_sec + (loop_end.tv_usec - loop_begin.tv_usec)/1000000.0;

    if(print_loop_count == print_loop_times)
    {
        print_loop_count = 0;
        //DECAF_printf("total loop time:%fs,syacall execute:%fs, tlb_handle_time:%fs, snapshot time:%fs, rest time:%fs\n", total_loop_time, time_interval_total, tlb_time_interval_total, restore_time*2, total_loop_time - time_interval_total - restore_time *2);
        DECAF_printf("%f:%f:%f:%f:%f:%d\n", total_loop_time, time_interval_total, tlb_time_interval_total, restore_time, total_loop_time - time_interval_total - restore_time, syscall_count);
    }
    tlb_time_interval_total = 0.0;
    time_interval_total = 0.0;
    syscall_count = 0;
    total_syscall_codegen_time = 0.0;

    struct itimerval tick;
    memset(&tick, 0, sizeof(tick));    
    tick.it_value.tv_sec = 1;  // sec  //set to 5
    tick.it_value.tv_usec = 0; // micro sec
    int ret = setitimer(ITIMER_REAL, &tick, NULL);

#ifndef QEMU_SNAPSHOT
    doneWork(0);
#else
    endWork(0);
#endif

}