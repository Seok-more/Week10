#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "userprog/process.h"
#include "filesys/off_t.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

// global lock
struct lock lock_file;

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

void check_address(void *address) {
    if (address == NULL) 
    {
        //printf("[DBG] check_address: NULL address, calling exit(-1)\n");
        exit(-1);
    }
    if (is_kernel_vaddr(address)) 
    {
        //printf("[DBG] check_address: Kernel address %p, calling exit(-1)\n", address);
        exit(-1);
    }
    if (pml4_get_page(thread_current()->pml4, address) == NULL) 
    {
        //printf("[DBG] check_address: Unmapped address %p, calling exit(-1)\n", address);
        exit(-1);
    }
}
void syscall_init (void) 
{
    lock_init(&lock_file);

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
    uint64_t num_syscall = f->R.rax;

    switch (num_syscall)
    {
        case SYS_HALT:
            halt();
            break;
        case SYS_EXIT:
            exit(f->R.rdi);
            break;
        case SYS_FORK:
            f->R.rax = fork(f->R.rdi);
            break;
        case SYS_EXEC:
            f->R.rax = exec(f->R.rdi);
            break;
        case SYS_WAIT:
            f->R.rax = process_wait(f->R.rdi);
            break;
        case SYS_CREATE:
            f->R.rax = create(f->R.rdi, f->R.rsi);
            break;
        case SYS_REMOVE:
            f->R.rax = remove(f->R.rdi);
            break;
        case SYS_OPEN:
            f->R.rax = open(f->R.rdi);
            break;
        case SYS_FILESIZE:
            f->R.rax = filesize(f->R.rdi);
            break;
        case SYS_READ:
            f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_WRITE:
            f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_SEEK:
            seek(f->R.rdi, f->R.rsi);
            break;
        case SYS_TELL:
            f->R.rax = tell(f->R.rdi);
            break;
        case SYS_CLOSE:
            close(f->R.rdi);
            break;
        default:
            exit(-1);
    }

}


// Pintos 종료(power_off() 호출).
void halt(void)
{
    power_off();
}

// 현재 사용자 프로그램 종료
// 부모 프로세스가 wait 시 status 반환(0: 성공, 그 외: 실패).
// void exit(int status)
// {
//     struct thread *now = thread_current();
//     now->status_exit = status;
//     printf("%s: exit(%d)\n", now->name, now->status_exit); 
//     thread_exit();
// }

void exit(int status) {
    struct thread *now = thread_current();
    printf("[DBG] exit() called for tid=%d, status=%d (old=%d)\n",
           now->tid, status, now->status_exit);
    now->status_exit = status;
    printf("%s: exit(%d)\n", now->name, now->status_exit);
    thread_exit();
}


// 현재 프로세스를 복제(자식 생성). 자식은 리소스(파일 디스크립터, 가상 메모리 등)도 복제.
// 부모는 자식이 성공적으로 복제됐는지 알 때까지 반환하지 않아야 함.
// 자식은 0 반환, 실패 시 TID_ERROR 반환.
tid_t fork (const char *thread_name)
{
    check_address(thread_name);

    return process_fork(thread_name, NULL);
}


// 현재 프로세스를 cmd_line에서 지정한 실행 파일로 변경(인자 전달 포함).
// 성공 시 반환하지 않음, 실패 시 -1로 종료.
// 파일 디스크립터는 유지.
int exec (const char *cmd_line)
{
    check_address(cmd_line);

    off_t size = strlen(cmd_line) + 1; // 마지막에 NULL
    char *cmd_copy = palloc_get_page(PAL_ZERO);

    if (cmd_copy == NULL) return -1;
    

    memcpy(cmd_copy, cmd_line, size);

    if (process_exec(cmd_copy) == -1) return -1;

    return 0; 
}

// 자식 프로세스 pid가 종료될 때까지 대기, exit status 반환.
// pid가 직접 자식이 아니거나, 이미 wait 했거나, 기타 오류 시 -1 반환.
int wait (tid_t tid)
{
	return process_wait(tid);
}


// 새 파일 생성(성공: true, 실패: false).
bool create (const char *file, unsigned initial_size)
{
    check_address(file);

    return filesys_create(file, initial_size);
}

// 파일 삭제(성공: true, 실패: false).
bool remove (const char *file)
{
    check_address(file);

    return filesys_remove(file);
}

// 파일 오픈, 파일 디스크립터(fd) 반환(0, 1은 콘솔용으로 예약).
// 프로세스별로 독립적 fd 테이블, 자식에게 fd 상속.
int open (const char *file)
{
    check_address(file);
    struct file *file_new = filesys_open(file);

    if (file_new == NULL) return -1;

    int fd = process_add_file_to_fdt(file_new);

    if (fd == -1)
    {
        file_close(file_new);
    }

    return fd;
}


// fd로 열린 파일의 크기 반환.
int filesize (int fd)
{
    struct file *file = process_get_file(fd);

    if (!file) return -1;

    return file_length(file);
}

// fd에서 size만큼 읽어 buffer에 저장, 읽은 바이트 수 반환(키보드는 fd 0).
int read (int fd, void *buffer, unsigned size)
{
    check_address(buffer);

   if (fd == 0) 
   {
        unsigned char *buf = buffer;
        int i = 0;
        while (i < size) 
        {
            char c = input_getc(); // 키보드에서 한 글자 입력
            buf[i++] = c;   // 입력받은 글자를 buffer에 저장하고 카운트 증가
            if (c == '\0') break;
        }

        return i; // 입력받은 바이트 개수 반환
    }
    else if (fd == 1 || fd == 2)  // stdout/stderr는 읽는거 아님
    {
        // Error
        // exit(-1) -> 읽기 실패만 한거지 프로세스 종료까지는 아니다?
        return -1; 
    }
    else
    {
        struct file *file = process_get_file(fd);
        if (!file) return -1;

        lock_acquire(&lock_file);
        off_t bytes = file_read(file, buffer, size); // 파일에서 size만큼 읽어 buffer에 저장
        lock_release(&lock_file);

        return bytes;
    }

}

// int 
// read(int fd, void *buffer, unsigned length) 
// {
//     check_address(buffer);

//     if (fd == 0) {  // 0(stdin) -> keyboard로 직접 입력
//         int i = 0;  // 쓰레기 값 return 방지
//         char c;
//         unsigned char *buf = buffer;

//         for (; i < length; i++) {
//             c = input_getc();
//             *buf++ = c;
//             if (c == '\0')
//                 break;
//         }

//         return i;
//     }
//     // 그 외의 경우
//     if (fd < 3)  // stdout, stderr를 읽으려고 할 경우 & fd가 음수일 경우
//         return -1;

//     struct file *file = process_get_file(fd);
//     off_t bytes = -1;

//     if (file == NULL)  // 파일이 비어있을 경우
//         return -1;

//     lock_acquire(&filesys_lock);
//     bytes = file_read(file, buffer, length);
//     lock_release(&filesys_lock);

//     return bytes;
// }


// buffer의 내용을 fd로 쓰고, 실제 쓴 바이트 수 반환 (콘솔은 fd 1).
int write(int fd, const void *buffer, unsigned size)
{
    check_address(buffer);

    if (fd == 0) //  stdin(0) ㄴㄴ
    {
        return -1;
    }
    else if (fd == 1 || fd == 2) // 출력, 에러도 출력임
    {
        putbuf(buffer, size); // 콘솔에 출력
        return size;          // 출력한 바이트 수 반환
    }
    else
    {
        struct file *file = process_get_file(fd);
        check_address(file);

        lock_acquire(&lock_file);
        off_t bytes = file_write(file, buffer, size); // 파일에 쓰기
        lock_release(&lock_file);

        return bytes; // 파일 쓴 바이트 수 반환
    }
}

// int 
// write(int fd, const void *buffer, unsigned length) 
// {
//     check_address(buffer);

//     off_t bytes = -1;

//     if (fd <= 0)  // stdin에 쓰려고 할 경우 & fd 음수일 경우
//         return -1;

//     if (fd < 3) {  // 1(stdout) * 2(stderr) -> console로 출력
//         putbuf(buffer, length);
//         return length;
//     }

//     struct file *file = process_get_file(fd);

//     if (file == NULL)
//         return -1;

//     lock_acquire(&filesys_lock);
//     bytes = file_write(file, buffer, length);
//     lock_release(&filesys_lock);

//     return bytes;
// }

// fd의 읽기/쓰기 위치 변경.
void seek (int fd, unsigned position)
{
    if (fd < 3 ) return;

    struct file *file = process_get_file(fd);

    if (!file)  return;

    file_seek(file, position);
}

// fd의 현재 위치 반환.
// unsigned?
unsigned tell (int fd)
{
    if (fd < 3 ) return -1;

    struct file *file = process_get_file(fd);

    if (!file)  return -1; 

    return file_tell(file);
}

// fd 닫기(프로세스 종료 시 모든 fd 자동 닫힘).
void close(int fd)
{
    if (fd < 3) return;  

    struct file *file = process_get_file(fd);
    if (!file) return;   // 이미 닫혔으면 return

    // fdt에서 제거
    process_remove_file_from_fdt(fd);

    // 파일 닫기
    file_close(file);
}




