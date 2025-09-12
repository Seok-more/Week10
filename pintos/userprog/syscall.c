#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

// 시스템 콜 번호(%rax)와 인자(%rdi, %rsi, %rdx, %r10, %r8, %r9) 추출
// 각 시스템 콜 종류에 따라 분기해서 처리
void syscall_handler(struct intr_frame *f UNUSED) 
{ 
    //int num_syscall = *(int*)(f->R.rax);

    // switch (num_syscall)
    // {
    //     case SYS_HALT:
    //     case SYS_EXIT:
    //     case SYS_FORK:
    //     case SYS_EXEC:
    //     case SYS_WAIT:
    //     case SYS_CREATE:
    //     case SYS_REMOVE:
    //     case SYS_OPEN:
    //     case SYS_FILESIZE:
    //     case SYS_READ:
    //     case SYS_WRITE:
    //     case SYS_SEEK:
    //     case SYS_TELL:
    //     case SYS_CLOSE:
    //         // 일단 임시
    //         printf("system call!\n");
    //         thread_exit();
    //         break;

    //     default:
    //         printf("Unknown syscall");
    //         thread_exit();
    //         break;
    // }

	printf("system call!\n");
	thread_exit();

}


// Pintos 종료(power_off() 호출).
void halt(void)
{

}

// 현재 사용자 프로그램 종료
// 부모 프로세스가 wait 시 status 반환(0: 성공, 그 외: 실패).
void exit(int status)
{

}

// 현재 프로세스를 복제(자식 생성). 자식은 리소스(파일 디스크립터, 가상 메모리 등)도 복제.
// 부모는 자식이 성공적으로 복제됐는지 알 때까지 반환하지 않아야 함.
// 자식은 0 반환, 실패 시 TID_ERROR 반환.
tid_t fork (const char *thread_name)
{

}


// 현재 프로세스를 cmd_line에서 지정한 실행 파일로 변경(인자 전달 포함).
// 성공 시 반환하지 않음, 실패 시 -1로 종료.
// 파일 디스크립터는 유지.
int exec (const char *cmd_line)
{

}

// 자식 프로세스 pid가 종료될 때까지 대기, exit status 반환.
// pid가 직접 자식이 아니거나, 이미 wait 했거나, 기타 오류 시 -1 반환.
int wait (tid_t tid)
{
	
}


// 새 파일 생성(성공: true, 실패: false).
bool create (const char *file, unsigned initial_size)
{

}

// 파일 삭제(성공: true, 실패: false).
bool remove (const char *file)
{

}


// 파일 오픈, 파일 디스크립터(fd) 반환(0, 1은 콘솔용으로 예약).
// 프로세스별로 독립적 fd 테이블, 자식에게 fd 상속.
int open (const char *file)
{

}

// fd로 열린 파일의 크기 반환.
int filesize (int fd)
{

}

// fd에서 size만큼 읽어 buffer에 저장, 읽은 바이트 수 반환(키보드는 fd 0).
int read (int fd, void *buffer, unsigned size)
{

}

// buffer를 fd로 쓰기, 실제 쓴 바이트 수 반환(콘솔은 fd 1).
int write (int fd, const void *buffer, unsigned size)
{

}

// fd의 읽기/쓰기 위치 변경.
void seek (int fd, unsigned position)
{

}

// fd의 현재 위치 반환.
unsigned tell (int fd)
{

}

// fd 닫기(프로세스 종료 시 모든 fd 자동 닫힘).
void close (int fd)
{
	
}
