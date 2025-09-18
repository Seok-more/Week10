Brand new pintos for Operating Systems and Lab (CS330), KAIST, by Youngjin Kwon.

The manual is available at https://casys-kaist.github.io/pintos-kaist/.

----------------------------------------------------------
1. 프로젝트 목표

Pintos 프로젝트 2(User Program)의 주 목표는 
사용자 프로그램을 실행하고 관리할 수 있는 OS 기능을 구현하는 것입니다.
핵심은 커널 모드와 사용자 모드 간의 전환, 시스템 콜 지원, 프로세스 관리입니다.

- 1.User Mode 지원
    - Pintos 기본 스레드는 커널 모드만 사용합니다.
    - 프로젝트 2에서는 사용자 프로그램을 실행하기 위해 User Mode를 구현해야 합니다.
    - 이를 위해 x86-64 아키텍처의 유저 스택, 레지스터, 코드 영역을 올바르게 설정해야 합니다.

- 2.System Call 지원

    - 사용자 프로그램에서 OS 기능을 사용하기 위한 시스템 콜을 구현합니다.
    - 예: halt(), exit(), exec(), wait(), read(), write(), create(), remove(), open(), filesize(), seek(), tell(), close()
    - 프로젝트 2에서는 시스템 콜 테이블을 작성하고 인터럽트 0x30을 통해 커널로 전환하여 처리합니다.

- 3.프로세스 관리
    - 프로세스 생성 (process_execute)
    - 프로세스 종료 (process_exit)
    - 프로세스 기다리기 (process_wait)
    - 각 프로세스의 exit status 관리
    - 부모-자식 관계 유지 (자식 프로세스가 종료될 때 부모가 status를 확인 가능)


2. 핵심 구조체
struct thread 
{
    ...
    uint64_t *pagedir;       // 64-bit KAIST 버전에서는 Page Table
    struct file **fd_table;  // 프로세스별 파일 디스크립터 테이블
    int next_fd;             // 다음 파일 디스크립터 번호
    struct semaphore load_sema; // exec 완료 대기
    int exit_status;         // exit() 값 저장
    ...
};
    - pagedir: 사용자 프로세스의 페이지 테이블
    - fd_table: 파일 디스크립터 관리 (open, close)
    - load_sema: 부모 프로세스가 자식 프로세스 로딩 완료까지 대기
    - exit_status: exit()에서 전달된 상태 저장


struct intr_frame 
{
    uint64_t rip;    // instruction pointer
    uint64_t rsp;    // stack pointer
    uint64_t rflags; // flags
    uint64_t rax, rbx, rcx, ... // 레지스터
    ...
};
    - 사용자 모드 진입 시 스택과 레지스터 초기화
    - 시스템 콜, 인터럽트에서 커널 모드 진입 시 현재 상태 저장

3. 시스템 콜 처리 흐름
    - 1.사용자 프로그램이 write() 호출
    - 2.CPU가 인터럽트 0x30 발생
    - 3.syscall_handler() 호출
    - 4.사용자 스택에서 인자 읽기
    - 5.권한 체크 및 검증
    - 6.실제 커널 함수 호출
    - 7.반환 값 레지스터에 저장 후 사용자 모드 복귀
    --> 사용자 프로그램이 직접 하드웨어 접근하지 못하게 하고, 시스템 콜로만 OS 기능 접근.

4. 프로세스 로딩 과정 (process_execute → load)
    1. process_execute() 호출 → 새 스레드 생성
    2. 스레드 내부 start_process()에서:
        - ELF 파일 파싱
        - 메모리 매핑
        - 사용자 스택 생성
        - argc/argv 스택에 세팅
    3. sema_up(&load_sema)로 부모에게 로딩 완료 알림
    4. intr_exit()를 통해 사용자 모드로 점프

5. 프로세스 종료 (process_exit)
    - 열린 파일 닫기
    - 페이지 테이블 해제
    - 부모에게 exit status 전달
    - 스레드 종료

6. 주의 포인트 (64비트 KAIST 버전)
    - 1.x86-64 레지스터와 스택 정렬
        System V AMD64 ABI에 따라 rsp를 16바이트 정렬
    - 2.pagedir 대신 4-level page table 사용
    - 3.파일 디스크립터 테이블 크기 제한
        기본적으로 최대 128개 정도
    - 4.동기화: sema와 lock으로 부모-자식/파일 접근 동기화

-----------------------------------------------------------
1. Argument Passing
: 유저 프로그램을 실행하기 위해, 커맨드 라인에 입력된 인자들을 유저 스택에 올리는 과정

- 1. 커맨드 라인을 파싱

-- set_arument_Ustack
- 2. 유저 스택에 파싱된 스트링 저장(역순, align 정렬해서)
- 3. 유저 스택에 스트링 주소도 저장(argv[])
-- set_arument_Ustack

- 4. 스택에 argc값올리고 argv 시작주소를 레지스터에 저장
_if.R.rsi, _if.R.rdi

- 5. main()에다가 인자를 넘겨주면 끝
do_iret 이 결국 커널 -> 유저 모드 

char *ptr_save;
strtok_r(file_name," ", &ptr_save);
"echo hello world"
-> "echo\0hello\0world"
--> 
file_name:	'e' 'c' 'h' 'o' '\0' 'h' 'e' 'l' 'l' 'o' '\0' 'w' 'o' 'r' 'l' 'd' '\0'
token:	"echo" (포인터)
ptr_save:	
포인터, "hello world"에서 'h' 위치

parsed = strtok_r(file_name, " ", &ptr_save);  // parsed -> "ls"
parsed = strtok_r(NULL, " ", &ptr_save);       // parsed -> "-l"
parsed = strtok_r(NULL, " ", &ptr_save);       // parsed -> "/home"


- 실행 흐름
// 유튜브 카이스트 강의랑 코드랑 차이 좀 있으니까 잘 바꾸셈
    : init.c main(argc, argv) -> run_actions-> run_task -> 
    process_create_initd -> thread_create -> initd -> process_exec -> load -> set_argument_Ustack-> do_iret 
    -> 유저프로그램의 main()

%rsi -> argv
%rdi -> argc

rsp --->  [NULL]         (argv 끝 표시)
rsp+8 ->  [&"ls"]        (argv[0])
rsp+16 -> [&"-l"]        (argv[1])
rsp+24 -> [&"/home"]     (argv[2])

initd : 최초의 유저 프로세스



@@@@@ while(1) 사용 시

[커널 부팅]
      │
      ▼
[initd 스레드 생성]
      │
      ▼
[initd: process_exec(args-single)]
      │
      ▼
[process_wait(initd) → while(1) 무한 대기]
      │  <--- 부모(initd) 종료 안 됨
      │
      ▼
[args-single 스레드 실행]
      │
      ▼
[set_argument_Ustack() → user stack 세팅]
      │
      ▼
[hex_dump 출력]
      │
      ▼
[args-single 실행 완료 → system call]


@@@@@ for 루프 사용 시

[커널 부팅]
      │
      ▼
[initd 스레드 생성]
      │
      ▼
[initd: process_exec(args-single)]
      │
      ▼
[process_wait(initd) → for loop 끝남]
      │
      ▼
[initd 종료]  
      │
      ▼
[커널 판단: 모든 initd 종료 → 전원 끄기/시뮬 종료]
      │
      ▼
[args-single 실행 전에 종료됨]
      │
      ▼
hex_dump 출력 X


| 구분       |  내용         | Pintos-KAIST 코드 맥락       | 스택/메모리                                  |
| ----------|---------------| ----------------------------- | ----------------------------------------- |
|User mode | 제한된 CPU 권한, 일반 유저 프로그램 실행 | `initd` 실행, `do_iret()` 이후  | 유저 스택 사용, 커널 스택 접근 불가 |

| Kernel mode | 모든 권한, OS 핵심 기능 수행| 스레드 생성, ELF 로딩, 시스템 콜 처리  | 커널 스택 사용, 유저 스택 접근 가능(초기화/세팅)  |

|User Stack| 유저 전용 스택, 함수 호출/argv/지역 변수 저장 | `setup_stack()`에서 초기화 → `if_->rsp = USER_STACK` | 최상단 주소에서 아래로 성장, 스택 오버플로우 시 segfault 발생 |

|Segmentation Fault| 허용되지 않은 메모리 접근 시 발생 | 유저 코드에서 Page Fault → `page_fault()` → 프로세스 종료  | User stack/허용 메모리 영역 외 접근 시, 커널 스택은 안전  |


[커널 모드]
main/init.c → run_task → process_create_initd → thread_create
        │
        └─ initd() → process_exec()
              │
              ├─ load()          : ELF 로딩
              ├─ setup_stack()   : 유저 스택 초기화, if_->rsp 세팅
              └─ do_iret(&if_)   : CPU User mode 전환, rsp = USER_STACK
                    │
            [유저 모드 실행 시작: initd ELF 실행]
                    │
            User Stack 사용 → 함수 호출, 인자(argv) 접근
                    │
            잘못된 메모리 접근 → Page Fault → Segmentation Fault
                    │
            커널 page_fault() → 프로세스 종료

-----------------------------------------------------------
2. System call

네! 학생 입장에서 **Pintos Project2 System Calls**를 구현할 때 해야 할 일만 정리해드릴게요.

---

## Pintos Project2: System Calls  
**학생이 직접 구현해야 할 핵심 항목 요약**

### 1. 시스템 콜 핸들러 구현 (userprog/syscall.c)
- `syscall_handler()` 함수 완성
  - 시스템 콜 번호(%rax)와 인자(%rdi, %rsi, %rdx, %r10, %r8, %r9) 추출
  - 각 시스템 콜 종류에 따라 분기해서 처리

### 2. 시스템 콜별 기능 직접 구현
세스템콜 함수들을 핸들러에서 분기 처리하여 직접 구현:

### 3. 사용자 메모리 접근 보호
- 시스템 콜 인자가 포인터일 때, 반드시 접근 안전성 검사
  - 커널 영역/널/미매핑 영역 접근 시 프로세스 강제 종료
- 버퍼 읽기/쓰기 함수에서 직접 구현(예: get_user, put_user 활용)

### 4. 파일 시스템 동기화(락)
- 파일 시스템 함수 호출 전/후 반드시 락으로 임계구역 보호
- 동시에 여러 프로세스가 파일 시스템에 접근해도 안전하게 만들어야 함

### 5. 자원 관리 및 예외 처리
- 자식/부모 관계 및 자원(메모리, 파일 등) 관리
- 프로세스 종료/에러/예외 상황에서 자원 누수 없이 처리
- 시스템 콜 잘못된 인자(오류, 경계, 예외) 상황도 반드시 처리
  - 에러 반환, 프로세스 종료 등 적절한 방식 선택

### 6. 확장성 고려
- 앞으로 추가될 시스템 콜(프로젝트3, 4)에 대비해 코드 구조를 확장성 있게 설계

---

## **정리**
- syscall.c에서 시스템 콜 번호에 따라 분기 처리
- 각 시스템 콜 함수의 핵심 로직 직접 구현
- 포인터 인자 접근은 반드시 안전하게
- 파일 시스템 등 공유 자원 동기화
- 예외/에러/자원 누수 없는 robust한 처리

---

## 프로세스 종료 메시지 출력
사용자 프로세스가 종료될 때마다
(직접 exit를 호출하거나 다른 이유로 종료될 때)
아래와 같은 형식으로 프로세스 이름과 종료 코드를 출력해야 합니다:

printf ("%s: exit(%d)\n", ...);

-> 출력되는 이름은 fork()에서 전달된 전체 이름이어야 합니다.
-> 커널 스레드(사용자 프로세스가 아닌 경우)가 종료될 때나, halt 시스템 콜이 호출될 때는 이 메시지를 출력하지 않아야 합니다.


## 실행 파일에 대한 쓰기 금지

1. 이미 제공된 함수 file_deny_write()를 사용하면, 열려 있는 파일에 대한 쓰기를 금지할 수 있습니다.

2. file_allow_write()를 호출하면 다시 쓰기가 허용되지만, 다른 프로세스가 이미 해당 파일에 쓰기를 금지한 상태라면 허용되지 않습니다.

3. 파일을 닫으면 쓰기 금지가 자동으로 해제됩니다.

쓰레드가 만들어지면
-파일 디스크립터 테이블 allocate
-FDT에 포인터 초기화 하고
-fd0, fd1은 stdin, stdout으로 예약

쓰레드가 없어지면
-close all files
-FDT deallocate

! Use global lock to avoid race on file
- define global lock on syscall.h(struct lock filesys_lock)
- initialize the lock on syscall_init() (use lock_init)
- protect filesystem related code by global lock

! Modify page_fault() for test
pintos needs to kill the process and print the thread name and the exit status -1 when page fault occurs
(O)

! PML4 (Page Map Level 4)
: 
- x86-64 페이징 시스템에서 최상위(4단계 중 1단계) 페이지 테이블입니다.
- 각 프로세스(스레드)는 자신의 주소 공간을 관리하기 위해 pml4를 갖고 있습니다.
- thread_current()->pml4는 현재 실행 중인 스레드의 페이지 테이블 최상위 포인터입니다.

 /** Project2: for Test Case - 직접 프로그램을 실행할 때에는 이 함수를 사용하지 않지만 make check에서
     *  이 함수를 통해 process_create를 실행하기 때문에 이 부분을 수정해주지 않으면 Test Case의 Thread_name이
     *  커맨드 라인 전체로 바뀌게 되어 Pass할 수 없다.
     */
    -> process_create_initd에서
    char *ptr_save;
    strtok_r(file_name, " ", &ptr_save);








-----------------------------------------------------------
# 최초 시도
FAIL tests/userprog/args-none
FAIL tests/userprog/args-single
FAIL tests/userprog/args-multiple
FAIL tests/userprog/args-many
FAIL tests/userprog/args-dbl-space
FAIL tests/userprog/halt
FAIL tests/userprog/exit
FAIL tests/userprog/create-normal
FAIL tests/userprog/create-empty
FAIL tests/userprog/create-null
FAIL tests/userprog/create-bad-ptr
FAIL tests/userprog/create-long
FAIL tests/userprog/create-exists
FAIL tests/userprog/create-bound
FAIL tests/userprog/open-normal
FAIL tests/userprog/open-missing
FAIL tests/userprog/open-boundary
FAIL tests/userprog/open-empty
FAIL tests/userprog/open-null
FAIL tests/userprog/open-bad-ptr
FAIL tests/userprog/open-twice
FAIL tests/userprog/close-normal
FAIL tests/userprog/close-twice
FAIL tests/userprog/close-bad-fd
FAIL tests/userprog/read-normal
FAIL tests/userprog/read-bad-ptr
FAIL tests/userprog/read-boundary
FAIL tests/userprog/read-zero
FAIL tests/userprog/read-stdout
FAIL tests/userprog/read-bad-fd
FAIL tests/userprog/write-normal
FAIL tests/userprog/write-bad-ptr
FAIL tests/userprog/write-boundary
FAIL tests/userprog/write-zero
FAIL tests/userprog/write-stdin
FAIL tests/userprog/write-bad-fd
FAIL tests/userprog/fork-once
FAIL tests/userprog/fork-multiple
FAIL tests/userprog/fork-recursive
FAIL tests/userprog/fork-read
FAIL tests/userprog/fork-close
FAIL tests/userprog/fork-boundary
FAIL tests/userprog/exec-once
FAIL tests/userprog/exec-arg
FAIL tests/userprog/exec-boundary
FAIL tests/userprog/exec-missing
FAIL tests/userprog/exec-bad-ptr
FAIL tests/userprog/exec-read
FAIL tests/userprog/wait-simple
FAIL tests/userprog/wait-twice
FAIL tests/userprog/wait-killed
FAIL tests/userprog/wait-bad-pid
FAIL tests/userprog/multi-recurse
FAIL tests/userprog/multi-child-fd
FAIL tests/userprog/rox-simple
FAIL tests/userprog/rox-child
FAIL tests/userprog/rox-multichild
FAIL tests/userprog/bad-read
FAIL tests/userprog/bad-write
FAIL tests/userprog/bad-read2
FAIL tests/userprog/bad-write2
FAIL tests/userprog/bad-jump
FAIL tests/userprog/bad-jump2
FAIL tests/filesys/base/lg-create
FAIL tests/filesys/base/lg-full
FAIL tests/filesys/base/lg-random
FAIL tests/filesys/base/lg-seq-block
FAIL tests/filesys/base/lg-seq-random
FAIL tests/filesys/base/sm-create
FAIL tests/filesys/base/sm-full
FAIL tests/filesys/base/sm-random
FAIL tests/filesys/base/sm-seq-block
FAIL tests/filesys/base/sm-seq-random
FAIL tests/filesys/base/syn-read
FAIL tests/filesys/base/syn-remove
FAIL tests/filesys/base/syn-write
FAIL tests/userprog/no-vm/multi-oom
pass tests/threads/alarm-single
pass tests/threads/alarm-multiple
pass tests/threads/alarm-simultaneous
pass tests/threads/alarm-priority
pass tests/threads/alarm-zero
pass tests/threads/alarm-negative
pass tests/threads/priority-change
pass tests/threads/priority-donate-one
pass tests/threads/priority-donate-multiple
pass tests/threads/priority-donate-multiple2
pass tests/threads/priority-donate-nest
pass tests/threads/priority-donate-sema
pass tests/threads/priority-donate-lower
pass tests/threads/priority-fifo
pass tests/threads/priority-preempt
pass tests/threads/priority-sema
pass tests/threads/priority-condvar
pass tests/threads/priority-donate-chain
77 of 95 tests failed.

make tests/userprog/args-none.result

pintos --fs-disk=10 -p tests/userprog/args-single:args-single -- -q -f run 'args-single onearg'

# Argument passing
pintos --fs-disk=10 -p tests/userprog/args-single:args-single -- -q -f run 'args-single onearg'

SeaBIOS (version 1.15.0-1)


iPXE (https://ipxe.org) 00:03.0 CA00 PCI2.10 PnP PMM+0FF8B4A0+0FECB4A0 CA00
                                                                               


Booting from Hard Disk..Kernel command line: -q -f put args-single run 'args-single onearg'
0 ~ 9fc00 1
100000 ~ ffe0000 1
Pintos booting with: 
        base_mem: 0x0 ~ 0x9fc00 (Usable: 639 kB)
        ext_mem: 0x100000 ~ 0xffe0000 (Usable: 260,992 kB)
Calibrating timer...  419,020,800 loops/s.
hd0: unexpected interrupt
hd0:0: detected 329 sector (164 kB) disk, model "QEMU HARDDISK", serial "QM00001"
hd0:1: detected 20,160 sector (9 MB) disk, model "QEMU HARDDISK", serial "QM00002"
hd1: unexpected interrupt
hd1:0: detected 118 sector (59 kB) disk, model "QEMU HARDDISK", serial "QM00003"
Formatting file system...done.
Boot complete.
Putting 'args-single' into the file system...
Executing 'args-single onearg':
000000004747ffc0                          00 00 00 00 00 00 00 00 |        ........|
000000004747ffd0  ed ff 47 47 00 00 00 00-f9 ff 47 47 00 00 00 00 |..GG......GG....|
000000004747ffe0  00 00 00 00 00 00 00 00-00 00 00 00 00 61 72 67 |.............arg|
000000004747fff0  73 2d 73 69 6e 67 6c 65-00 6f 6e 65 61 72 67 00 |s-single.onearg.|
system call!
...무한대기

# Syscall

FDT 및 fd 관리 문제임 open 까지는 됨

cd pintos
make clean
cd userprog
make clean
make
cd build

cd pintos
cd userprog
cd build

cd ..
cd .. 
make clean
cd userprog
make clean
make
cd build

pass tests/userprog/args-none
pass tests/userprog/args-single
pass tests/userprog/args-multiple
pass tests/userprog/args-many
pass tests/userprog/args-dbl-space
pass tests/userprog/halt
pass tests/userprog/exit
pass tests/userprog/create-normal
pass tests/userprog/create-empty
pass tests/userprog/create-null
pass tests/userprog/create-bad-ptr
pass tests/userprog/create-long
pass tests/userprog/create-exists
pass tests/userprog/create-bound

FAIL tests/userprog/open-normal
pass tests/userprog/open-missing
FAIL tests/userprog/open-boundary
pass tests/userprog/open-empty
pass tests/userprog/open-null
pass tests/userprog/open-bad-ptr
FAIL tests/userprog/open-twice

FAIL tests/userprog/close-normal
FAIL tests/userprog/close-twice
pass tests/userprog/close-bad-fd

FAIL tests/userprog/read-normal
FAIL tests/userprog/read-bad-ptr
FAIL tests/userprog/read-boundary
FAIL tests/userprog/read-zero
pass tests/userprog/read-stdout
pass tests/userprog/read-bad-fd

FAIL tests/userprog/write-normal
FAIL tests/userprog/write-bad-ptr
FAIL tests/userprog/write-boundary
FAIL tests/userprog/write-zero
pass tests/userprog/write-stdin
pass tests/userprog/write-bad-fd

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

pass tests/userprog/fork-once
pass tests/userprog/fork-multiple
pass tests/userprog/fork-recursive
FAIL tests/userprog/fork-read
FAIL tests/userprog/fork-close
pass tests/userprog/fork-boundary

pass tests/userprog/exec-once
pass tests/userprog/exec-arg
pass tests/userprog/exec-boundary
FAIL tests/userprog/exec-missing
pass tests/userprog/exec-bad-ptr
FAIL tests/userprog/exec-read

pass tests/userprog/wait-simple
pass tests/userprog/wait-twice
FAIL tests/userprog/wait-killed
pass tests/userprog/wait-bad-pid

pass tests/userprog/multi-recurse
FAIL tests/userprog/multi-child-fd

FAIL tests/userprog/rox-simple
FAIL tests/userprog/rox-child
FAIL tests/userprog/rox-multichild

pass tests/userprog/bad-read
pass tests/userprog/bad-write
pass tests/userprog/bad-read2
pass tests/userprog/bad-write2
pass tests/userprog/bad-jump
pass tests/userprog/bad-jump2

FAIL tests/filesys/base/lg-create
FAIL tests/filesys/base/lg-full
FAIL tests/filesys/base/lg-random
FAIL tests/filesys/base/lg-seq-block
FAIL tests/filesys/base/lg-seq-random
FAIL tests/filesys/base/sm-create
FAIL tests/filesys/base/sm-full
FAIL tests/filesys/base/sm-random
FAIL tests/filesys/base/sm-seq-block
FAIL tests/filesys/base/sm-seq-random
FAIL tests/filesys/base/syn-read
FAIL tests/filesys/base/syn-remove
FAIL tests/filesys/base/syn-write

FAIL tests/userprog/no-vm/multi-oom

pass tests/threads/alarm-single
pass tests/threads/alarm-multiple
pass tests/threads/alarm-simultaneous
pass tests/threads/alarm-priority
pass tests/threads/alarm-zero
pass tests/threads/alarm-negative
pass tests/threads/priority-change
pass tests/threads/priority-donate-one
pass tests/threads/priority-donate-multiple
pass tests/threads/priority-donate-multiple2
pass tests/threads/priority-donate-nest
pass tests/threads/priority-donate-sema
pass tests/threads/priority-donate-lower
pass tests/threads/priority-fifo
pass tests/threads/priority-preempt
pass tests/threads/priority-sema
pass tests/threads/priority-condvar
pass tests/threads/priority-donate-chain
36 of 95 tests failed.