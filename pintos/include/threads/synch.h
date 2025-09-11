#ifndef THREADS_SYNCH_H
#define THREADS_SYNCH_H

#include <list.h>
#include <stdbool.h>

/* A counting semaphore. */
struct semaphore {
	unsigned value;             /* Current value. */
	struct list waiters;        /* List of waiting threads. */
};

void sema_init (struct semaphore *, unsigned value);
void sema_down (struct semaphore *);
bool sema_try_down (struct semaphore *);
void sema_up (struct semaphore *);
void sema_self_test (void);

/* Lock. */
struct lock {
	struct thread *holder;      /* Thread holding lock (for debugging). */
	struct semaphore semaphore; /* Binary semaphore controlling access. */
};

void lock_init (struct lock *);
void lock_acquire (struct lock *);
bool lock_try_acquire (struct lock *);
void lock_release (struct lock *);
bool lock_held_by_current_thread (const struct lock *);


/* One semaphore in a list. */
struct semaphore_elem {
	struct list_elem elem;              /* List element. */
	struct semaphore semaphore;         /* This semaphore. */
};


/* Condition variable. */
// 어떤 "조건"이 만족될 때까지 스레드가 잠깐 잠드는 동기화 도구
// 직접 락 제어를 하는게 아니라 세마포어를 통해 쓰레드를 깨우는 역할만 함
// 결국 waiter 리스트의 정렬 기준에 따라 세마포어_elem들이 들어감
// 세마포어의 waiters안에는 쓰레드가
// 조건변수의 waiters안에는 쓰레드가 있지만,  semaphore_elem이라는 구조체 형태(세마포어와 리스트 요소를 포함)로써 접근함
// 실제로는 그 세마포어에 걸린 쓰레드가 하나씩 깨움
struct condition {
	struct list waiters;        /* List of waiting threads. */
};

void cond_init (struct condition *);
void cond_wait (struct condition *, struct lock *);
void cond_signal (struct condition *, struct lock *);
void cond_broadcast (struct condition *, struct lock *);

// 여기추가
bool sort_sema_priority(struct list_elem *a, struct list_elem *b);
bool sort_donation_priority(struct list_elem *a, struct list_elem *b);
void donate(struct thread *now, struct thread *holder);
void remove_donation(struct thread *now, struct lock *lock);
void update_priority(struct thread *now);

/* Optimization barrier.
 *
 * The compiler will not reorder operations across an
 * optimization barrier.  See "Optimization Barriers" in the
 * reference guide for more information.*/
#define barrier() asm volatile ("" : : : "memory")

#endif /* threads/synch.h */
