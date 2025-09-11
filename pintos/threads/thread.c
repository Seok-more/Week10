#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/fixed_point.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

// sleep_list 선언
static struct list sleep_list;

// mlfqs
static struct list all_list; 
int load_avg = 0;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	lock_init (&tid_lock);
	list_init (&ready_list);
	list_init (&destruction_req);
	list_init (&sleep_list);
	list_init(&all_list);

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT);

	// if (thread_mlfqs)
	// {
	// 	list_push_back(&all_list, &(initial_thread->all_elem));
	// }

	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */

// 새로운 커널 스레드를 생성하고, 지정한 우선순위(priority)로 ready queue(레디 리스트)에 넣는다.
// 생성된 스레드가 지정한 함수(function)를 인자로(aux)와 함께 실행한다.
// 생성된 스레드의 식별자(tid)를 반환한다. 만약 생성에 실패하면 TID_ERROR 반환.

tid_t thread_create (const char *name, int priority, thread_func *function, void *aux) 
{
	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread (t, name, priority);
	tid = t->tid = allocate_tid ();

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	/* Add to run queue. */
	thread_unblock (t);
	thread_swap_prior();

	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */

// 현재 진행중인 쓰레드를 블록으로 변경하고 슼케줄러에서 제외,
void thread_block (void) 
{
	ASSERT (!intr_context ()); // 인터럽트 컨텍스트에서 호출하면 안됨을 보장
	ASSERT (intr_get_level () == INTR_OFF); // 함수 실행 전에 인터럽트가 꺼져있어야함을 보장
	thread_current ()->status = THREAD_BLOCKED; // 현재 실행중인 쓰레드의 상태를 블록으로함 
	schedule (); // 스케줄러를 호출해서 다음에 실행할 쓰레드를 결정해서 전환함(레디상태인애)
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */

// 이 함수는 블록된 스레드를 ready 상태로 전환하지만, 
// 실행 중인 스레드를 중단시키지는 않는다. 
// 스레드가 블록 상태가 아니면 오류가 발생하며, 
// 인터럽트를 막은 상태라면 안전하게 다른 데이터랑 블록 해제를 처리할 수 있다.
// block->ready_list

// ready_list 찾았다
void thread_unblock (struct thread *t) 
{
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);
	
	// Priority 하게 바꾸자
	//list_push_back (&ready_list, &t->elem);
	list_insert_ordered(&ready_list, &t->elem, sort_thread_priority, NULL);
	//printf("[PS_basic] thread_yield: Inserted %s (priority=%d, tid=%d) into ready_list\n",curr->name, curr->priority, curr->tid);
	
	t->status = THREAD_READY;
	intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit ();
#endif
	/** project1-Advanced Scheduler */
	if (thread_mlfqs)
        list_remove(&thread_current()->all_elem);
	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}
// 현재 실행 중인 스레드를 READY 리스트에 넣고
// 스케줄러를 호출해 다른 스레드를 실행하도록 CPU를 양보하는 함수예요.
// **문맥 전환(Context Switch)**을 유발하는 대표적인 함수입니다.
// ready_list 찾았다
void thread_yield (void) 
{
	struct thread *curr = thread_current ();
	enum intr_level old_level;

	ASSERT (!intr_context ());

	old_level = intr_disable ();
	if (curr != idle_thread)
	{
		//list_push_back (&ready_list, &curr->elem);
		list_insert_ordered(&ready_list, &curr->elem, sort_thread_priority, NULL);
		//printf("[PS_basic] thread_yield: Inserted %s (priority=%d, tid=%d) into ready_list\n",curr->name, curr->priority, curr->tid);
	}
		
	do_schedule (THREAD_READY);
	intr_set_level (old_level);
}

// sleep상태인 쓰레드를 sleep_list에 넣음
// 스레드 구조체에 일어날 시각(ticks) 저장
// 슬립리스트에서 ticks가 작은 쓰레드 부터 넣도록 정렬까지 -> 추가함수 필요함
// 현재 쓰레드 슬립으로 -> block 호출
// 일반 커널 컨텍스트에서만 호출. 인터럽트 핸들러에서는 부르지마셈
void thread_sleep(int64_t ticks)
{
	ASSERT(!intr_context()); // 인터럽트 핸들러에서 부르면 오류

	enum intr_level old_level;
	old_level = intr_disable(); // 인터럽트 해제 -> Race Condition 막아서 sleep_list에 안전접근 

	struct thread *now = thread_current(); 
	ASSERT(now != idle_thread); // idle thread는 절대 sleep하면 안됨 (스케줄러 동작을 위해 항상 필요함)

	now->ticks_awake = ticks;  // 현재 쓰레드가 깨야하는 시간을 구조체에 저장

	list_insert_ordered(&sleep_list, &now->elem, sort_thread_ticks, NULL); // sleep_list에 추가(빨리 끝나는 애부터 정렬식으로)
	
	// printf("[AlarmClock] thread_sleep: %s will sleep until tick %lld\n", now->name, ticks);

	// 현재 스레드를 BLOCKED 상태로 바꿔 스케줄러에서 제외시킴 ->  timer interrupt에서 깨울 때까지 잠
	thread_block(); // 현재 스레드 재우기

	intr_set_level(old_level); // 인터럽트 상태를 원래 상태로 변경
}

// 슬립리스트안에서 빨리 깨는 쓰레드는 앞으로 정렬
bool sort_thread_ticks(struct list_elem *a, struct list_elem *b)
{
	// 리스트에서 꺼낸 값이 구조체의 멤버 -> 그 값으로는 원래 구조체의 다른 멤버에 접근 불가능
	// list_entry 매크로를 통해 전체 구조체의 포인터로 반환하면 다른 멤버에 접근 가능
	struct thread *thread_a = list_entry(a, struct thread, elem);
	struct thread *thread_b = list_entry(b, struct thread, elem);
	
	// if (thread_a->ticks_awake == thread_b->ticks_awake)
	// {
	// 	// Warning : FIFO 구조 해치고 있긴함
	// 	return thread_a->tid < thread_b->tid; // ticks가 같으면 tid 값으로 정렬 -> 테스트 조건에 안맞을 수도
	// 	// return 0; -> FIFO
	// }  
	
	return thread_a->ticks_awake < thread_b->ticks_awake;
}


// 슬립리스트안의 쓰레드들이 일어날 시간이 되면 레디 리스트로 옮김
// 지금 틱보다 작거나 같은 ticks_awake을 가진 쓰레드 모두 슬립리스트에서 제거 -> 레디리스트에 삽입
// 인터럽트 컨텍스트에서만 호출됨. 일반 커널 코드에서 부르면 안 됨.
void thread_awake(int64_t ticks)
{
	ASSERT(intr_context()); // 인터럽트 핸들러가 아니면 오류

    enum intr_level old_level = intr_disable();

    struct list_elem *now_elem = list_begin(&sleep_list);
    struct list_elem *next_elem;

    // 리스트를 순회하며 깰 애는 바로 깨워버림
    while (now_elem != list_end(&sleep_list))
    {
		// 지금 검사중인 elem이 속한 쓰레드 구조체
        struct thread *curr_thread = list_entry(now_elem, struct thread, elem);
        if (ticks >= curr_thread->ticks_awake) 
		{
            // 다음 요소 미리 저장
            next_elem = list_next(now_elem);

            list_remove(now_elem);         // sleep_list에서 제거
            thread_unblock(curr_thread);    // ready_list로 이동
			thread_swap_prior(); 

            now_elem = next_elem;   
        } 
		else 
		{
            break; // 더 이상 깰 쓰레드 없음
        }
    }

    intr_set_level(old_level); // 인터럽트 복귀
}


// 레디리스트안에서 우선순위가 높은 쓰레드를 앞으로 정렬
bool sort_thread_priority(struct list_elem *a, struct list_elem *b)
{
	struct thread *thread_a = list_entry(a, struct thread, elem);
	struct thread *thread_b = list_entry(b, struct thread, elem);
	
	// Error
	// tid 순으로 살리는 방법 X -> 테스트는 FIFO를 요구함 
	if (thread_a->priority == thread_b->priority)
	{	
		//return thread_a->tid > thread_b->tid;
		return 0;
	}  
	
	return thread_a->priority > thread_b->priority;
}

// 현재 실행중인 쓰레드랑 ready_list에 있는 쓰레드랑 우선순위비교
// 대기하는게 더 높다면 교체까지
void thread_swap_prior(void)
{
	// 예외처리
	if (list_empty(&ready_list)) return;

	struct thread *now = thread_current();
	struct thread *ready = list_entry(list_front(&ready_list),struct thread, elem);

	//printf("[PS_basic] thread_swap_prior: now(%s, priority=%d, tid=%d), ready(%s, priority=%d, tid=%d)\n",now->name, now->priority, now->tid,ready->name, ready->priority, ready->tid);

	if (now->priority < ready->priority || (now->priority == ready->priority && now != ready))
	{
		//printf("[PS_basic] thread_swap_prior: now->priority < ready->priority, yielding...\n");

		// Error
		// thread_awake()는 timer interrupt에서 실행됨 → 즉, 인터럽트 컨텍스트에서 실행됨
		// thread_yield()는 인터럽트 컨텍스트에서 실행하면 커널 패닉 (ASSERT(!intr_context()))
		// thread_yield 만 아니라 저렇게까지 해야함
		if (intr_context())
            intr_yield_on_return();
        else
            thread_yield();
	}

}


// 아 뭐야 여기있었네
void thread_set_priority (int new_priority) 
{
	if (thread_mlfqs) return;
	struct thread *now = thread_current();
	// 아 이거때문인가
	//now->priority = new_priority; 
	now->priority_original  = new_priority;

	update_priority(now);

	thread_swap_prior();

}

/* Returns the current thread's priority. */
int thread_get_priority (void) 
{
	return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void thread_set_nice (int nice UNUSED) 
{
	/* TODO: Your implementation goes here */
	struct thread *t = thread_current();

    enum intr_level old_level = intr_disable();
    t->nice = nice;
    mlfqs_priority(t);
    intr_set_level(old_level);
}

/* Returns the current thread's nice value. */
int thread_get_nice (void) 
{
	/* TODO: Your implementation goes here */
	 struct thread *t = thread_current();

    enum intr_level old_level = intr_disable();
    int nice = t->nice;
    intr_set_level(old_level);

    return nice;
}

/* Returns 100 times the system load average. */
int thread_get_load_avg (void) 
{
	/* TODO: Your implementation goes here */
	enum intr_level old_level = intr_disable();
    int load_avg_val = fp_to_int_round(mult_n(load_avg, 100));  
    intr_set_level(old_level);

    return load_avg_val;
}

/* Returns 100 times the current thread's recent_cpu value. */
int thread_get_recent_cpu (void) 
{
	/* TODO: Your implementation goes here */
	struct thread *t = thread_current();

    enum intr_level old_level = intr_disable();
    int recent_cpu = fp_to_int_round(mult_n(t->recent_cpu, 100)); 
    intr_set_level(old_level);

    return recent_cpu;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
// 새 쓰레드 구조체 초기화 -> 새로운 쓰레드 객체 만든다고 보면됨
static void init_thread (struct thread *t, const char *name, int priority) 
{
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);

	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);
	
	if (thread_mlfqs) 
	{
        mlfqs_priority(t);
        list_push_back(&all_list, &t->all_elem);
    } 
	else 
	{
        t->priority = priority;
    }
	t->magic = THREAD_MAGIC;

	// 여기추가
	t->priority_original = priority;
	t->lock_donated_for_waiting = NULL;
	list_init(&(t->lst_donation));

	t->nice = 0;
    t->recent_cpu = 0;

}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */


static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))
		return idle_thread;
	else
		return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current ()->status = status;
	schedule ();
}

static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next = next_thread_to_run ();

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used by the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_push_back (&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch (next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}

void mlfqs_priority (struct thread *t) 
{
    if (t == idle_thread) return;

    t->priority = fp_to_int(add_n(div_n(t->recent_cpu, -4), PRI_MAX - t->nice * 2));
}

void mlfqs_recent_cpu (struct thread *t) 
{
    if (t == idle_thread) return;

    t->recent_cpu = add_n(mult_fp(div_fp(mult_n(load_avg, 2), add_n(mult_n(load_avg, 2), 1)), t->recent_cpu), t->nice);
}

void mlfqs_load_avg (void) 
{
    int ready_threads = list_size(&ready_list);

    if (thread_current() != idle_thread)
    {
		ready_threads++;
	}

    load_avg = add_fp(mult_fp(div_fp(int_to_fp(59), int_to_fp(60)), load_avg), mult_n(div_fp(int_to_fp(1), int_to_fp(60)), ready_threads));
}

void mlfqs_update_recent_cpu (void) 
{
    struct list_elem *it = list_begin(&all_list);

    while (it != list_end(&all_list)) 
	{
        struct thread *t = list_entry(it, struct thread, all_elem);
        mlfqs_recent_cpu(t);

        it = list_next(it);
    }
}

void mlfqs_update_priority (void) 
{
    struct list_elem *it = list_begin(&all_list);

    while (it != list_end(&all_list)) 
	{
        struct thread *t = list_entry(it, struct thread, all_elem);
        mlfqs_priority(t);

        it = list_next(it);
    }
}