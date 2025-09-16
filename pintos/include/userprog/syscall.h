#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"

void syscall_init (void);

// User Memory Access
void check_address(void *address);

void halt(void);
void exit(int status);

tid_t fork (const char *thread_name);
int exec (const char *cmd_line);
int wait (tid_t tid);

bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

extern struct lock lock_file;

#endif /* userprog/syscall.h */
