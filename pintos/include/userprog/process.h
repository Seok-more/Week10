#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

// 전방선언
struct file; 

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

// file
int process_add_file_to_fdt(struct file *file);
struct file *process_get_file(int fd); 
int process_remove_file_from_fdt(int fd);


#endif /* userprog/process.h */
