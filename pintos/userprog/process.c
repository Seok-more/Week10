#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

// 여기 추가
static void set_argument_Ustack(char **argv, uintptr_t *rsp, int argc);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */

// "initd"라는 첫 번째 사용자 프로세스를 생성하는 함수입니다.
tid_t process_create_initd (const char *file_name) 
{
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE); 

	// 허?
	char *ptr;
    strtok_r(file_name, " ", &ptr);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
	{
		palloc_free_page (fn_copy);
	}
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

// 현재 프로세스의 실행 상태를 복제해서, 자식 프로세스를 생성한 후, 
// 복제가 완료될 때까지 기다렸다가 자식의 thread id를 반환
tid_t process_fork (const char *name, struct intr_frame *if_ UNUSED) 
{
	struct thread *now = thread_current();

	// 부모 실행 컨텍스트 저장 
    struct intr_frame *if_child = (pg_round_up(rrsp()) - sizeof(struct intr_frame));  
    memcpy(&now->if_parent, if_child, sizeof(struct intr_frame));                  

    tid_t tid_child = thread_create(name, PRI_DEFAULT, __do_fork, now);

    if (tid_child == TID_ERROR) return TID_ERROR;
	
    struct thread *thread_child = get_child_process(tid_child);

	// 자식이 do_fork에서 복제 끝날 때까지 대기함 
    sema_down(&thread_child->sema_fork);  

    if (thread_child->status_exit == TID_ERROR) return TID_ERROR;
	
    return tid_child;  
}

// tid_t process_fork(const char *name, struct intr_frame *if_ UNUSED) 
// {
//     struct thread *now = thread_current();

//     struct intr_frame *if_child = (pg_round_up(rrsp()) - sizeof(struct intr_frame));  
//     memcpy(&now->if_parent, if_child, sizeof(struct intr_frame));                  

//     tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, now);

//     if (tid == TID_ERROR) {
//         printf("[DBG] process_fork: thread_create failed, returning TID_ERROR\n");
//         return TID_ERROR;
//     }
	
//     struct thread *child = get_child_process(tid);
//     sema_down(&child->sema_fork);  

//     if (child->status_exit == TID_ERROR) {
//         printf("[DBG] process_fork: child->status_exit == TID_ERROR, returning TID_ERROR\n");
//         return TID_ERROR;
//     }
	
//     return tid;  
// }

#ifndef VM
// 부모의 주소 공간(메모리 페이지들)을 자식 프로세스에 복제
static bool duplicate_pte (uint64_t *pte, void *va, void *aux) 
{
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if (is_kernel_vaddr(va)) return true;

	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);
	if (!parent_page) return false;

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page(PAL_ZERO);
    if (!newpage) return false;

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE);
    writable = is_writable(pte);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) 
	{
		/* 6. TODO: if fail to insert page, do error handling. */
		return false;
	}
	return true;
}
#endif

// 부모 프로세스의 실행 컨텍스트(레지스터, 메모리, 파일 등)를 복사해서
// 새로운 자식 스레드(프로세스)를 생성하는 함수입니다.
static void __do_fork (void *aux) 
{
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux;
	struct thread *now = thread_current ();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *if_parent_ = &parent->if_parent;
	bool succ = true;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, if_parent_, sizeof (struct intr_frame));
    if_.R.rax = 0;  // 자식 프로세스의 리턴

	/* 2. Duplicate PT */
	now->pml4 = pml4_create();
	if (now->pml4 == NULL)
		goto error;

	process_activate (now);

#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/

    if (parent->fd >= 128) goto error;

	// fd, fdt 복제
    now->fd = parent->fd;  
    for (int fd_ = 3; fd_ < parent->fd; fd_++) 
	{
        if (parent->fdt[fd_] == NULL) continue;
        now->fdt[fd_] = file_duplicate(parent->fdt[fd_]);
    }

    sema_up(&now->sema_fork);  // 성공, fork()에서 down한거 다시 up해줌

    process_init();

    /* Finally, switch to the newly created process. */
    if (succ)
    {
		do_iret(&if_);
	}  

error:
    sema_up(&now->sema_fork);  // 실패, fork()에서 down한거 다시 up해줌
    exit(TID_ERROR);
}

// static void __do_fork(void *aux) 
// {
//     struct intr_frame if_;
//     struct thread *parent = (struct thread *) aux;
//     struct thread *now = thread_current ();
//     struct intr_frame *if_parent_ = &parent->if_parent;
//     bool succ = true;

//     memcpy(&if_, if_parent_, sizeof(struct intr_frame));
//     if_.R.rax = 0;

//     now->pml4 = pml4_create();
//     if (now->pml4 == NULL) {
//         printf("[DBG] __do_fork: pml4_create failed, exiting with TID_ERROR\n");
//         goto error;
//     }

//     process_activate(now);

// #ifdef VM
//     supplemental_page_table_init(&current->spt);
//     if (!supplemental_page_table_copy(&current->spt, &parent->spt)) {
//         printf("[DBG] __do_fork: supplemental_page_table_copy failed, exiting with TID_ERROR\n");
//         goto error;
//     }
// #else
//     if (!pml4_for_each(parent->pml4, duplicate_pte, parent)) {
//         printf("[DBG] __do_fork: pml4_for_each/duplicate_pte failed, exiting with TID_ERROR\n");
//         goto error;
//     }
// #endif

//     if (parent->fd >= 128) {
//         printf("[DBG] __do_fork: parent->fd >= 128, exiting with TID_ERROR\n");
//         goto error;
//     }

//     now->fd = parent->fd;
//     for (int fd_ = 3; fd_ < parent->fd; fd_++) 
//     {
//         if (parent->fdt[fd_] == NULL)
//             continue;
//         now->fdt[fd_] = file_duplicate(parent->fdt[fd_]);
//         if (now->fdt[fd_] == NULL) {
//             printf("[DBG] __do_fork: file_duplicate failed for fd %d, exiting with TID_ERROR\n", fd_);
//             goto error;
//         }
//     }

//     sema_up(&now->sema_fork);

//     process_init();

//     if (succ) {
//         printf("[DBG] __do_fork: fork successful, switching to child\n");
//         do_iret(&if_);
//     }

// error:
//     printf("[DBG] __do_fork: error detected, calling exit(TID_ERROR)\n");
//     sema_up(&now->sema_fork);
//     exit(TID_ERROR);
// }

// 현재 실행 중인 프로세스(스레드)의 실행 컨텍스트(코드, 데이터 등)를 새 바이너리 파일로 교체하여, 
// 지정한 파일을 실행하도록 하는 역할을 합니다. 즉, 현재 프로세스가 다른 프로그램으로 "변신"하는 것입니다.
// int process_exec (void *f_name) // f_name: 실행 하려는 파일의 이름
// {
// 	char *file_name = f_name;
// 	bool success;

// 	/* We cannot use the intr_frame in the thread structure.
// 	 * This is because when current thread rescheduled,
// 	 * it stores the execution information to the member. */
// 	struct intr_frame _if;
// 	_if.ds = _if.es = _if.ss = SEL_UDSEG;
// 	_if.cs = SEL_UCSEG;
// 	_if.eflags = FLAG_IF | FLAG_MBS;

// 	/* We first kill the current context */
// 	process_cleanup ();

// 	// Error!
// 	// strtok_r가 file_name을 직접 변경해서 
// 	// "args-single onearg"라는 전체 문자열을 보존하지 않고, "onearg" 부분만 남거나, 첫 번째 토큰 뒤가 NULL로 잘림
// 	// 그 후, load (file_name, &_if)를 해서 file_name이 "onearg" 등으로 바뀌어서 못찾음 

// 	// 수정본
// 	char *argv[64];
// 	char *ptr_save;

// 	// file_name을 복사해서 파싱
// 	char file_name_copy[128];
// 	strlcpy(file_name_copy, file_name, sizeof(file_name_copy));

// 	char *parsed = strtok_r(file_name_copy, " ", &ptr_save);
// 	int argc = 0;
// 	while (parsed != NULL) 
// 	{
// 		argv[argc++] = parsed;
// 		parsed = strtok_r(NULL, " ", &ptr_save); // 다음
// 	}

// 	// 프로그램 이름만 넘기고 
// 	success = load(argv[0], &_if); // "args-single"

// 	set_argument_Ustack(argv, &_if.rsp, argc); 

// 	_if.R.rsi = (char *)_if.rsp + 8; // argv
// 	_if.R.rdi = argc; // argc

// 	// 디버깅 테스트
// 	// hex_dump(_if.rsp, _if.rsp, USER_STACK - (uint64_t)_if.rsp, true); 

// 	/* If load failed, quit. */
// 	palloc_free_page (file_name);
// 	if (!success) return -1;

// 	/* Start switched process. */
// 	do_iret (&_if);
// 	NOT_REACHED ();
// }

int process_exec (void *f_name) // f_name: 실행 하려는 파일의 이름
{
	char *file_name = f_name;
	bool success;

	printf("[DBG] process_exec: called with file_name='%s', tid=%d\n", file_name, thread_current()->tid);

	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	process_cleanup ();

	char *argv[64];
	char *ptr_save;

	char file_name_copy[128];
	strlcpy(file_name_copy, file_name, sizeof(file_name_copy));

	char *parsed = strtok_r(file_name_copy, " ", &ptr_save);
	int argc = 0;
	while (parsed != NULL) 
	{
		argv[argc++] = parsed;
		parsed = strtok_r(NULL, " ", &ptr_save);
	}

	printf("[DBG] process_exec: parsed argv[0]='%s', argc=%d\n", argv[0], argc);

	success = load(argv[0], &_if);
	printf("[DBG] process_exec: load('%s') returned %d\n", argv[0], success);

	set_argument_Ustack(argv, &_if.rsp, argc); 

	_if.R.rsi = (char *)_if.rsp + 8; // argv
	_if.R.rdi = argc; // argc

	palloc_free_page (file_name);

	if (!success) {
		printf("[DBG] process_exec: load failed, about to return -1 and exit(-1) will be called by syscall_handler.\n");
		return -1;
	}

	printf("[DBG] process_exec: load succeeded, switching to user code with do_iret.\n");
	do_iret (&_if);
	NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
// process_wait는 부모 프로세스가 자식 프로세스가 종료될 때까지 기다리게 하는 함수입니다.
// 부모가 호출하면, 자식이 종료(exit)할 때까지 블로킹(block) 되고, 종료 시 자식의 exit status를 반환합니다.
// int process_wait (tid_t child_tid UNUSED) 
// {
// 	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
// 	 * XXX:       to add infinite loop here before
// 	 * XXX:       implementing the process_wait. */

// 	struct thread *child = get_child_process(child_tid);
//     if (child == NULL) return -1;

//     sema_down(&child->sema_wait);  // 자식 프로세스가 종료될 때 까지 대기

//     int status_exit_ = child->status_exit;
//     list_remove(&child->child_elem);

//     sema_up(&child->sema_exit);  // 자식 프로세스의 process_exit에서 down한거 복구
 
//     return status_exit_;
// }

int process_wait (tid_t child_tid UNUSED) 
{
	struct thread *child = get_child_process(child_tid);
    if (child == NULL) {
		printf("[DBG] process_wait: get_child_process(%d) == NULL, returning -1\n", child_tid);
		return -1;
	}

    sema_down(&child->sema_wait);  // 자식 프로세스가 종료될 때 까지 대기

    int status_exit_ = child->status_exit;
	printf("[DBG] process_wait: child tid=%d exited with status=%d\n", child_tid, status_exit_);

    list_remove(&child->child_elem);

    sema_up(&child->sema_exit);  // 자식 프로세스의 process_exit에서 down한거 복구
 
    return status_exit_;
}

struct thread *get_child_process(int tid)
{
    struct thread *now = thread_current();
    struct thread *it_child;
    struct list_elem *it_e = list_begin(&now->lst_child);

    while (it_e != list_end(&now->lst_child)) 
    {
        it_child = list_entry(it_e, struct thread, child_elem);

        if (it_child->tid == tid)
		{
			return it_child;
		} 

        it_e = list_next(it_e);
    }

    return NULL;
}


int process_add_file_to_fdt(struct file *file)
{
	struct thread *now = thread_current();
    struct file **fdt = now->fdt;

    if (now->fd >= (128)) return -1;

    fdt[now->fd++] = file;

    return now->fd - 1;
}

struct file *process_get_file(int fd)
{
	struct thread *now = thread_current();

    if (fd >= (128)) return NULL;

    return now->fdt[fd];
}

// 그냥 fdt에서 제거하는거임
int process_remove_file_from_fdt(int fd)
{
	struct thread *now = thread_current();

    if (fd >= (128)) return -1;

    now->fdt[fd] = NULL;

    return 0;
}

/* Exit the process. This function is called by thread_exit (). */
// void process_exit (void) 
// {
// 	struct thread *curr = thread_current ();

//     for (int fd = 0; fd < curr->fd; fd++)  // FDT 비우기
//     { 
// 		close(fd);
// 	}

//     file_close(curr->file_running);  // 현재 프로세스가 실행중인 파일 종료

//     palloc_free_multiple(curr->fdt, 2);

//     process_cleanup();

//     sema_up(&curr->sema_wait);  // 부모 프로세스의 process_wait에서 down한거 복구

//     sema_down(&curr->sema_exit);  // 부모 프로세스가 종료될 떄까지 대기
// }

void process_exit (void) 
{
	struct thread *curr = thread_current ();
	printf("[DBG] process_exit: called for thread='%s', status_exit=%d, tid=%d\n",
		curr->name, curr->status_exit, curr->tid);

    for (int fd = 3; fd < 128; fd++) 
	{
    	if (curr->fdt[fd]) close(fd);
	}
	
	// 현재 프로세스가 실행중인 파일 종료
	
	//file_close(curr->file_running);  
	if (curr->file_running) 
	{
		file_close(curr->file_running);
		curr->file_running = NULL;
	}

    palloc_free_multiple(curr->fdt, 2);

    process_cleanup();

    sema_up(&curr->sema_wait);  // 부모 프로세스의 process_wait에서 down한거 복구

    sema_down(&curr->sema_exit);  // 부모 프로세스가 종료될 떄까지 대기
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
// static bool
// load (const char *file_name, struct intr_frame *if_) {
// 	struct thread *t = thread_current ();
// 	struct ELF ehdr;
// 	struct file *file = NULL;
// 	off_t file_ofs;
// 	bool success = false;
// 	int i;

// 	/* Allocate and activate page directory. */
// 	t->pml4 = pml4_create ();
// 	if (t->pml4 == NULL) goto done;
// 	process_activate (thread_current ());

// 	/* Open executable file. */
// 	file = filesys_open (file_name);
// 	if (file == NULL)
// 	{
// 		printf ("load: %s: open failed\n", file_name);
// 		goto done;
// 	}

// 	// 추가
// 	t->file_running = file;
// 	file_deny_write(file);

// 	/* Read and verify executable header. */
// 	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
// 			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
// 			|| ehdr.e_type != 2
// 			|| ehdr.e_machine != 0x3E // amd64
// 			|| ehdr.e_version != 1
// 			|| ehdr.e_phentsize != sizeof (struct Phdr)
// 			|| ehdr.e_phnum > 1024) {
// 		printf ("load: %s: error loading executable\n", file_name);
// 		goto done;
// 	}

// 	/* Read program headers. */
// 	file_ofs = ehdr.e_phoff;
// 	for (i = 0; i < ehdr.e_phnum; i++) {
// 		struct Phdr phdr;

// 		if (file_ofs < 0 || file_ofs > file_length (file))
// 			goto done;
// 		file_seek (file, file_ofs);

// 		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
// 			goto done;
// 		file_ofs += sizeof phdr;
// 		switch (phdr.p_type) {
// 			case PT_NULL:
// 			case PT_NOTE:
// 			case PT_PHDR:
// 			case PT_STACK:
// 			default:
// 				/* Ignore this segment. */
// 				break;
// 			case PT_DYNAMIC:
// 			case PT_INTERP:
// 			case PT_SHLIB:
// 				goto done;
// 			case PT_LOAD:
// 				if (validate_segment (&phdr, file)) {
// 					bool writable = (phdr.p_flags & PF_W) != 0;
// 					uint64_t file_page = phdr.p_offset & ~PGMASK;
// 					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
// 					uint64_t page_offset = phdr.p_vaddr & PGMASK;
// 					uint32_t read_bytes, zero_bytes;
// 					if (phdr.p_filesz > 0) {
// 						/* Normal segment.
// 						 * Read initial part from disk and zero the rest. */
// 						read_bytes = page_offset + phdr.p_filesz;
// 						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
// 								- read_bytes);
// 					} else {
// 						/* Entirely zero.
// 						 * Don't read anything from disk. */
// 						read_bytes = 0;
// 						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
// 					}
// 					if (!load_segment (file, file_page, (void *) mem_page,
// 								read_bytes, zero_bytes, writable))
// 						goto done;
// 				}
// 				else
// 					goto done;
// 				break;
// 		}
// 	}

// 	/* Set up stack. */
// 	if (!setup_stack (if_))
// 		goto done;

// 	/* Start address. */
// 	if_->rip = ehdr.e_entry;

// 	/* TODO: Your code goes here.
// 	 * TODO: Implement argument passing (see project2/argument_passing.html). */

// 	success = true;

// done:
// 	/* We arrive here whether the load is successful or not. */
// 	// 여기 수정
// 	//file_close (file);
// 	return success;
// }

static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	printf("[DBG] load: called with file_name='%s', tid=%d\n", file_name, t->tid);

	t->pml4 = pml4_create ();
	if (t->pml4 == NULL) {
		printf("[DBG] load: pml4_create failed\n");
		goto done;
	}
	process_activate (thread_current ());

	file = filesys_open (file_name);
	if (file == NULL)
	{
		printf ("[DBG] load: filesys_open('%s') failed\n", file_name);
		goto done;
	}

	t->file_running = file;
	file_deny_write(file);

	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("[DBG] load: ELF header check failed for '%s'\n", file_name);
		goto done;
	}

	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file)) {
			printf("[DBG] load: file_ofs invalid (segment %d)\n", i);
			goto done;
		}
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr) {
			printf("[DBG] load: file_read phdr failed (segment %d)\n", i);
			goto done;
		}
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				printf("[DBG] load: unsupported segment type %d\n", phdr.p_type);
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable)) {
						printf("[DBG] load: load_segment failed for segment %d\n", i);
						goto done;
					}
				}
				else {
					printf("[DBG] load: validate_segment failed for segment %d\n", i);
					goto done;
				}
				break;
		}
	}

	if (!setup_stack (if_)) {
		printf("[DBG] load: setup_stack failed\n");
		goto done;
	}

	if_->rip = ehdr.e_entry;
	success = true;

done:
	if (!success) printf("[DBG] load: overall load failed for '%s'\n", file_name);
	else printf("[DBG] load: load succeeded for '%s'\n", file_name);
	return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */

// main(argc, argv) 여기에 맞도록 유저 스택에 스택 프레임을 세팅
static void set_argument_Ustack(char **argv, uintptr_t *rsp, int argc)
{
	// 문자열의 스택 주소 저장용, 128바이트로 제한하래
    char *vec_argv[128];

	// 스택은 위 -> 아래
	// 인자도 큰 -> 작
    for (int i = argc - 1; i >= 0; i--)
    {
		// 각 인자 문자열을 스택에 복사
        size_t len = strlen(argv[i]) + 1;
        *rsp -= len;                    
        memcpy((void *)(*rsp), argv[i], len);
        vec_argv[i] = (char *)(*rsp);  // 스택 주소도 저장해주고
    }

	// 8바이트 정렬 삽입
    while (*rsp % 8 != 0)
    {
        (*rsp)--;
        *((uint8_t *)(*rsp)) = 0;	// 패딩값
    }

	// Error!
	// argv 배열은 마지막이 NULL로 끝나야 함
    (*rsp) -= 8;
    *((char **)(*rsp)) = NULL;

	// 각 인자 문자열의 주소도 스택에 넣음
	// main의 argv는 ver_argv를 봄
    for (int i = argc - 1; i >= 0; i--)
    {
        (*rsp) -= 8;
        *((char **)(*rsp)) = vec_argv[i];
    }

	// 마지막 페이크 리턴 주소
    (*rsp) -= 8;
    *((void **)(*rsp)) = NULL;
}



