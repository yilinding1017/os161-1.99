#include <types.h>
#include <kern/errno.h>
#include <kern/unistd.h>
#include <kern/wait.h>
#include <lib.h>
#include <syscall.h>
#include <current.h>
#include <proc.h>
#include <thread.h>
#include <addrspace.h>
#include <copyinout.h>

#include "opt-A2.h"
#include <synch.h>
#include <mips/trapframe.h>



int sys_fork(struct trapframe *tf, pid_t *retval) {
  struct proc *child = proc_create_runprogram(curproc->p_name);
  if(child == NULL){
    return ENOMEM;
  }
  if(child->pid < 0) {
    proc_destroy(child);
    return EMPROC;
  }

  // Set Parent and Children
  

  // Copy address space
  struct addrspace * temp =  NULL;
  if (as_copy(curproc_getas(),&temp) != 0){
    proc_destroy(child);
    return ENOMEM;
  }
  
  spinlock_acquire(&child->p_lock);
  child->p_addrspace = temp;
  spinlock_release(&child->p_lock);

  spinlock_acquire(&curproc->p_lock);
  child->p_parent = curproc;
  array_add(curproc->p_children, child, NULL);
  spinlock_release(&curproc->p_lock);

  // Copy trapframe
  struct trapframe *childTF = kmalloc(sizeof(struct trapframe));
  if(childTF == NULL){
    proc_destroy(child);
    return ENOMEM;
  }
  memcpy(childTF, tf, sizeof(struct trapframe));

  // Fork Thread
  int fork_result = thread_fork(curthread->t_name, child, enter_forked_process, childTF, 0);
  if(fork_result != 0){
    proc_destroy(child);
    kfree(childTF);
    return fork_result;
  }

  // Set return value/error code
  *retval = child->pid;

  return 0;
}


  /* this implementation of sys__exit does not do anything with the exit code */
  /* this needs to be fixed to get exit() and waitpid() working properly */

void sys__exit(int exitcode) {
  struct addrspace *as;
  struct proc *p = curproc;

  /* for now, just include this to keep the compiler from complaining about
     an unused variable */
  //(void)exitcode;

  DEBUG(DB_SYSCALL,"Syscall: _exit(%d)\n",exitcode);

  KASSERT(curproc->p_addrspace != NULL);
  as_deactivate();
  /*
   * clear p_addrspace before calling as_destroy. Otherwise if
   * as_destroy sleeps (which is quite possible) when we
   * come back we'll be calling as_activate on a
   * half-destroyed address space. This tends to be
   * messily fatal.
   */
  as = curproc_setas(NULL);
  as_destroy(as);

  /* detach this thread from its process */
  /* note: curproc cannot be used after this call */
  proc_remthread(curthread);

#if OPT_A2
  lock_acquire(p->p_lk);
  bool isNull = (p->p_parent == NULL);
  if(isNull) {
    lock_release(p->p_lk);
    proc_destroy(p);
  } else {
    // Set fields
    p->isExit = true;
    p->exitCode = _MKWAIT_EXIT(exitcode);
    // Wake up parent
    cv_signal(p->p_cv, p->p_lk);
    lock_release(p->p_lk);
  }
#else
  /* if this is the last user process in the system, proc_destroy()
     will wake up the kernel menu thread */
  proc_destroy(p);
#endif
  thread_exit();
  /* thread_exit() does not return, so we should never get here */
  panic("return from thread_exit in sys_exit\n");
}


/* stub handler for getpid() system call                */
int
sys_getpid(pid_t *retval)
{
#if OPT_A2
  *retval = curproc->pid;
  /* for now, this is just a stub that always returns a PID of 1 */
  /* you need to fix this to make it work properly */
#else
  *retval = 1;
#endif
  return(0);
}

/* stub handler for waitpid() system call                */

int
sys_waitpid(pid_t pid,
	    userptr_t status,
	    int options,
	    pid_t *retval)
{
  int exitstatus;
  int result;

  /* this is just a stub implementation that always reports an
     exit status of 0, regardless of the actual exit status of
     the specified process.   
     In fact, this will return 0 even if the specified process
     is still running, and even if it never existed in the first place.

     Fix this!
  */
  *retval = -1;
  if (options != 0) {
    return(EINVAL);
  }
  /* for now, just pretend the exitstatus is 0 */
  exitstatus = 0;

#if OPT_A2
  struct proc *child = NULL;

  spinlock_acquire(&curproc->p_lock);
  int childrenNum = array_num(curproc->p_children);
  for(int i = 0; i<childrenNum ;i++) {
    struct proc *currChild = array_get(curproc->p_children,i);
    pid_t childPid = child->pid;
    if(childPid == pid) {
      child = currChild;
      break;
    }
  }
  spinlock_release(&curproc->p_lock);

  if(child == NULL){
    *retval = -1;
    return ECHILD;
  }

  lock_acquire(child->p_lk);
  bool dead = child->isExit;
  if(!dead) {
    cv_wait(child->p_cv, child->p_lk);
  }
  lock_release(child->p_lk);
  exitstatus = child->exitCode;
#endif

  result = copyout((void *)&exitstatus,status,sizeof(int));
  if (result) {
    return(result);
  }
  *retval = pid;
  return(0);
}







