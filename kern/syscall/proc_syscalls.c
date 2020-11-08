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

#include <copyinout.h>
#include <vfs.h>
#include <kern/fcntl.h>

#if OPT_A2
int sys_execv(const char *program, char **args) {
  // Count the number of arguments and copy them into the kernel  
  int argsNum = 0;
  for (int i = 0; args[i] != NULL; i++) {
    argsNum++;
  }

  size_t argsSize = (argsNum + 1) * sizeof(char *);
  char **argsPath = kmalloc(argsSize);
  if(argsPath == NULL) {
    return ENOMEM;
  }

  for (int i = 0; i <= argsNum; i++) {
    if (i == argsNum) argsPath[i] = NULL;
    else {
      size_t argSize = (strlen(args[i]) + 1) * sizeof(char);
      argsPath[i] = kmalloc(argSize);
      if(argsPath[i] == NULL) {
        int count = 0;
        while(argsPath[count] != NULL) {
          kfree(argsPath[count]);
          ++count;
        }
        kfree(argsPath);
        return ENOMEM;
      }
      size_t tempGot;
      int err = copyinstr((const_userptr_t)args[i], argsPath[i], argSize, &tempGot);
      if(err != 0) {
        int count = 0;
        while(argsPath[count] != NULL) {
          kfree(argsPath[count]);
          ++count;
        }
        kfree(argsPath);
        return err;
      }
    }
  }

  // Copy the program path from user space into the kernel
  size_t programNameSize = (strlen(program) + 1) * sizeof(char);
  char *programNamePath = kmalloc(programNameSize);
  if(programNamePath == NULL) {
    return ENOMEM;
  }
  size_t got;
  int err = copyinstr((const_userptr_t)program, programNamePath, programNameSize, &got);
  if(err != 0) {
    kfree(programNamePath);
    return err;
  }
  
  // Modify runprogram
  struct addrspace *as;
	struct vnode *v;
	vaddr_t entrypoint, stackptr;
	int result;

	/* Open the file. */
	result = vfs_open(programNamePath, O_RDONLY, 0, &v);
	if (result) {
		return result;
	}

	/* Create a new address space. */
	as = as_create();
	if (as ==NULL) {
		vfs_close(v);
		return ENOMEM;
	}

	/* Switch to it and activate it. */
	struct addrspace *oldas = curproc_setas(as);
	as_activate();

	/* Load the executable. */
	result = load_elf(v, &entrypoint);
	if (result) {
		/* p_addrspace will go away when curproc is destroyed */
    as_destroy(curproc_setas(oldas));
		vfs_close(v);
		return result;
	}

	/* Done with the file now. */
	vfs_close(v);

	/* Define the user stack in the address space */
	result = as_define_stack(as, &stackptr);
	if (result) {
		/* p_addrspace will go away when curproc is destroyed */
    as_destroy(curproc_setas(oldas));
		return result;
	}

  // Copy the arguments from the user space into the new address space
  vaddr_t *stackArgs = kmalloc((argsNum+1) * sizeof(vaddr_t));

  size_t totalCharsSize = 0;

  for(int i = argsNum; i >= 0; --i) {
    if(i == argsNum) {
      stackArgs[i] = (vaddr_t)NULL;
    } else {
      size_t arg_size = (strlen(argsPath[i])+1)*sizeof(char);
      stackptr -= arg_size;
      totalCharsSize += arg_size;
      int err = copyout((void *)argsPath[i],(userptr_t)stackptr, arg_size);
      if(err != 0) {
        return err;
      }
      stackArgs[i] = stackptr;
    }
  }

  size_t diff = ROUNDUP(totalCharsSize,4) - totalCharsSize;
  stackptr -= diff;
  
  for (int i = argsNum; i >= 0; --i) {
    size_t argPointer_size = sizeof(vaddr_t);
    stackptr -= argPointer_size;
    int err = copyout((void *)&stackArgs[i], (userptr_t)stackptr, argPointer_size);
    if(err != 0) {
        return err;
    }
  }

  /* Warp to user mode. */
  // Delete the old address space
  as_destroy(oldas);
  kfree(programNamePath);

  // Call enter_new_process with 
  // (1) address to the arguments on the stack 
  // (2) stack pointer (from as_define_stack) 
  // (3) program entry point (from vfs_open)
  enter_new_process(argsNum/*argc*/, (userptr_t)stackptr /*userspace addr of argv*/,
			  ROUNDUP(stackptr,8), entrypoint);

	/* enter_new_process does not return. */
	panic("enter_new_process returned\n");
	return EINVAL;
}

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
  spinlock_acquire(&curproc->p_lock);
  child->p_parent = curproc;
  array_add(curproc->p_children, child, NULL);
  spinlock_release(&curproc->p_lock);

  // Copy address space
  struct addrspace * temp =  NULL;
  if (as_copy(curproc_getas(),&temp) != 0){
    proc_destroy(child);
    return ENOMEM;
  }
  
  spinlock_acquire(&child->p_lock);
  child->p_addrspace = temp;
  spinlock_release(&child->p_lock);

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
#endif
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
  for(int i = childrenNum; i > 0; i--) {
    struct proc *currChild = array_get(curproc->p_children,i-1);
    pid_t childPid = currChild->pid;
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




