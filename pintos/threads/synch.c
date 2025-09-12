/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
   */

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
   decrement it.

   - up or "V": increment the value (and wake up one waiting
   thread, if any). */
void
sema_init (struct semaphore *sema, unsigned value) {
	ASSERT (sema != NULL);

	sema->value = value;
	list_init (&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */


// 찾았다 
// sema_down 함수는 공유자원(예: lock, 임계구역)에 접근하려는 스레드가 “자원을 얻기 위해” 호출하는 함수입니다.
// 세마포어 값이 1이면 호출한 쓰레드의 세마포어 값을 0으로 바꾸고 자원점유
// 세마포어 값이 0이면 이미 다른 쓰레드가 락 점유중이므로 대기
void sema_down (struct semaphore *sema) 
{
	enum intr_level old_level;

	ASSERT (sema != NULL);
	ASSERT (!intr_context ());

	old_level = intr_disable ();
	while (sema->value == 0) 
	{
		// printf("[sema_down] Block thread: %s (priority: %d)\n", thread_current()->name, thread_current()->priority);

		list_insert_ordered(&sema->waiters, &thread_current ()->elem, sort_thread_priority, NULL);
		
		// printf("[sema_down] Waiters: ");
		// struct list_elem *e;
		// for (e = list_begin(&sema->waiters); e != list_end(&sema->waiters); e = list_next(e)) {
		// 	struct thread *t = list_entry(e, struct thread, elem);
		// 	printf("%s(%d) ", t->name, t->priority);
		// }
		// printf("\n");
		
		thread_block ();
	}
	sema->value--;
	intr_set_level (old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema) {
	enum intr_level old_level;
	bool success;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	if (sema->value > 0)
	{
		sema->value--;
		success = true;
	}
	else
		success = false;
	intr_set_level (old_level);

	return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */

// Up(V) 연산은 자원을 하나 더 풀어준다(세마포어 값 증가).
// 만약 세마포어를 기다리는 스레드가 있으면, 그 중 가장 앞에 있는(우선순위 높은) 스레드를 깨워준다.
// waiters 리스트는 우선순위 정렬이 되어 있으므로, 항상 가장 높은 priority가 먼저 깨어남.
void sema_up (struct semaphore *sema) 
{
	enum intr_level old_level;

	ASSERT (sema != NULL);

	old_level = intr_disable ();

	if (!list_empty (&sema->waiters))
	{

		list_sort(&sema->waiters, sort_thread_priority, NULL);
		// struct thread *t = list_entry(list_front(&sema->waiters), struct thread, elem);
        // printf("[sema_up] Unblock thread: %s (priority: %d)\n", t->name, t->priority);
      
		thread_unblock (list_entry (list_pop_front (&sema->waiters),struct thread, elem));
	}
	
	sema->value++;
	thread_swap_prior();
	intr_set_level (old_level);
}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) {
	struct semaphore sema[2];
	int i;

	printf ("Testing semaphores...");
	sema_init (&sema[0], 0);
	sema_init (&sema[1], 0);
	thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
	for (i = 0; i < 10; i++)
	{
		sema_up (&sema[0]);
		sema_down (&sema[1]);
	}
	printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) {
	struct semaphore *sema = sema_;
	int i;

	for (i = 0; i < 10; i++)
	{
		sema_down (&sema[0]);
		sema_up (&sema[1]);
	}
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock) {
	ASSERT (lock != NULL);

	lock->holder = NULL;
	sema_init (&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
// 락을 획득(lock acquire)하는 함수
// 즉, 여러 스레드가 공유 자원을 사용할 때
// 한 번에 하나의 스레드만 접근하도록 하는 "상호배제(Mutual Exclusion)"를 보장합니다.
void lock_acquire(struct lock *lock) 
{
    ASSERT(lock != NULL);
    ASSERT(!intr_context());
    ASSERT(!lock_held_by_current_thread(lock));

    // mlfqs가 꺼져있을 때만 priority donation 동작
    if (!thread_mlfqs) 
	{
        struct thread *now = thread_current();
        if (lock->holder) 
		{
            now->lock_donated_for_waiting = lock;
            list_insert_ordered(&lock->holder->lst_donation, &now->lst_donation_elem, sort_donation_priority, NULL);
            donate(now, lock->holder);
        }
    }
    sema_down(&lock->semaphore);

    // lock의 holder는 무조건 현재 스레드로 갱신 (mlfqs 여부와 관계없음)
    lock->holder = thread_current();

    if (!thread_mlfqs)
    {
		thread_current()->lock_donated_for_waiting = NULL;
	}
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock) {
	bool success;

	ASSERT (lock != NULL);
	ASSERT (!lock_held_by_current_thread (lock));

	success = sema_try_down (&lock->semaphore);
	if (success)

		lock->holder = thread_current ();
	return success;
}

/* Releases LOCK, which must be owned by the current thread.
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void lock_release(struct lock *lock) 
{
    ASSERT(lock != NULL);
    ASSERT(lock_held_by_current_thread(lock));

    // lock의 holder는 항상 NULL로 세팅 (mlfqs 여부와 관계없음)
    lock->holder = NULL;

    // mlfqs가 꺼져있을 때만 donation 관련 코드
    if (!thread_mlfqs) 
	{
        remove_donation(thread_current(), lock);
        update_priority(thread_current());
    }
    sema_up(&lock->semaphore);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) {
	ASSERT (lock != NULL);

	return lock->holder == thread_current ();
}



/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond) {
	ASSERT (cond != NULL);

	list_init (&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */

// 조건 변수에 "대기(wait)"하는 함수.
// lock을 풀고, 조건이 만족될 때까지 block되었다가, 
// signal/broadcast로 깨어나서 다시 lock을 잡음.
// 찾았다 새끼
void cond_wait (struct condition *cond, struct lock *lock) 
{
	struct semaphore_elem waiter;

	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	sema_init (&waiter.semaphore, 0);

	list_insert_ordered(&cond->waiters,&waiter.elem,sort_sema_priority, NULL);

	lock_release (lock);
	sema_down (&waiter.semaphore);
	lock_acquire (lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
// cond_signal은 조건 변수에 "기다리고 있는(wait)" 스레드가 있다면,
// 그 중 한 스레드만 깨우는(signal) 함수입니다.
void cond_signal (struct condition *cond, struct lock *lock UNUSED) 
{
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	if (!list_empty (&cond->waiters))
	{
		// struct semaphore_elem *sema_elem = list_entry (list_front (&cond->waiters),struct semaphore_elem, elem);
		// struct thread *t = NULL;
		// if (!list_empty(&sema_elem->semaphore.waiters)) {
		// 	t = list_entry(list_front(&sema_elem->semaphore.waiters), struct thread, elem);
		// 	printf("[cond_signal] Signal: Unblock thread %s (priority: %d)\n", t->name, t->priority);
		// } else {
		// 	printf("[cond_signal] Signal: Unblock EMPTY (no thread)\n");
		// }

		list_sort(&cond->waiters, sort_sema_priority, NULL);
		sema_up (&list_entry (list_pop_front (&cond->waiters),struct semaphore_elem, elem)->semaphore);
	}
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);

	while (!list_empty (&cond->waiters))
		cond_signal (cond, lock);
}

// 두 세마포어의 waiters 중 elem(잠든 쓰레드)의 우선순위 비교해서 priority가 더 높은 쓰레드를 앞으로
bool sort_sema_priority(struct list_elem *a, struct list_elem *b)
{
	// 컨디션의 waiters에 있는 세마포어 갖고오고 
	struct semaphore_elem *sema_a = list_entry(a, struct semaphore_elem, elem);
	struct semaphore_elem *sema_b = list_entry(b, struct semaphore_elem, elem);

	// 그 세마포어의 waiter에 있는 제일 우선순위 높은 쓰레드 갖고오고 
	struct thread *thread_a = list_entry(list_begin(&(sema_a->semaphore.waiters)), struct thread, elem);
	struct thread *thread_b = list_entry(list_begin(&(sema_b->semaphore.waiters)), struct thread, elem);
	
	return thread_a->priority > thread_b->priority;

	
}

bool sort_donation_priority(struct list_elem *a, struct list_elem *b)
{
	struct thread *thread_a = list_entry(a, struct thread,lst_donation_elem);
	struct thread *thread_b = list_entry(b, struct thread,lst_donation_elem);

	return thread_a->priority > thread_b->priority;

}

void donate(struct thread *now, struct thread *holder)
{
	// 중첩 우선순위 한계 8로 하래
	for (int i = 0; i < 8; i++)
	{
		// 이제 중첩 안됨
		if (!now->lock_donated_for_waiting) return;

		holder = now->lock_donated_for_waiting->holder;
		holder->priority = now->priority;
		now = holder;
	}
}

// now의 lst_donation에서 현재 lock을 요청한 쓰레드를 탐색, 제거
void remove_donation(struct thread *now, struct lock *lock)
{
	if (list_empty(&now->lst_donation)) return;

	struct list_elem *it = list_front(&now->lst_donation);

	while (it != list_end(&now->lst_donation))
	{
		struct thread *thread_it = list_entry(it, struct thread, lst_donation_elem);
		struct list_elem *next = list_next(it);

		if (thread_it->lock_donated_for_waiting == lock)
		{
			list_remove(&thread_it->lst_donation_elem);
		}

		it = next;
	}
}

// 반환한 lock으로 인해 바뀐 우선순위 적용
void update_priority(struct thread *now)
{
	if (list_empty(&now->lst_donation))
	{
		now->priority = now->priority_original; // 기부 없으면 바로 복구
	}
	else
	{
		// donation 리스트 정렬이 최신이도록
		now->priority = list_entry(list_front(&now->lst_donation), struct thread, lst_donation_elem)->priority;
	}
}