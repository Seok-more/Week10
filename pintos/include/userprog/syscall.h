#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"
#include "threads/synch.h"

void syscall_init (void);


// User Memory Access
void check_address(void *address);

// 프로세스 기본
void halt(void); // o
void exit(int status); // o

// 여기서부터 부모/자식 관계 구현해야하네 씨
tid_t fork (const char *thread_name);
int exec (const char *cmd_line);
int wait (tid_t tid);

// 파일 시스템
bool create (const char *file, unsigned initial_size); // o
bool remove (const char *file); // o
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

extern struct lock lock_file;

#endif /* userprog/syscall.h */