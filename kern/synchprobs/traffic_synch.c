#include <types.h>
#include <lib.h>
#include <synchprobs.h>
#include <synch.h>
#include <opt-A1.h>
#include <queue.h>

/* 
 * This simple default synchronization mechanism allows only vehicle at a time
 * into the intersection.   The intersectionSem is used as a a lock.
 * We use a semaphore rather than a lock so that this code will work even
 * before locks are implemented.
 */

/* 
 * Replace this default synchronization mechanism with your own (better) mechanism
 * needed for your solution.   Your mechanism may use any of the available synchronzation
 * primitives, e.g., semaphores, locks, condition variables.   You are also free to 
 * declare other global variables if your solution requires them.
 */

/*
 * replace this with declarations of any synchronization and other variables you need here
 */

static struct lock *intersectionLock;
// The origin directions that drivers can come from
// 0: north, 1: south, 2: east, 3: west
static struct cv* directions[4];
// Count the number of cars in the interaction right now
static int countCars = 0;
// waitQueue shows the order of entry for the waiting directions
static struct queue *waitQueue;
static int dirList[4] = {0,1,2,3};
static bool inWait[4] = {false,false,false,false};
// entry ranges from -1 to 3. -1 indicates no direction to enter
// 1-3 respectively corresponds to entry in n, s, e, and w
static int entry = -1;


/* 
 * The simulation driver will call this function once before starting
 * the simulation
 *
 * You can use it to initialize synchronization and other variables.
 * 
 */
void
intersection_sync_init(void)
{
  /* replace this default implementation with your own implementation */

  intersectionLock = lock_create("intersectionLock");
  if (intersectionLock == NULL) {
    panic("could not create intersection lock");
  }
  directions[0] = cv_create("N");
  if (directions[0] == NULL) panic("could not create cv N");
  directions[1] = cv_create("S");
  if (directions[1] == NULL) panic("could not create cv S");
  directions[2] = cv_create("E");
  if (directions[2] == NULL) panic("could not create cv E");
  directions[3] = cv_create("W");
  if (directions[3] == NULL) panic("could not create cv W");

  waitQueue = q_create(3);

  return;
}

/* 
 * The simulation driver will call this function once after
 * the simulation has finished
 *
 * You can use it to clean up any synchronization and other variables.
 *
 */
void
intersection_sync_cleanup(void)
{
  /* replace this default implementation with your own implementation */
  KASSERT(intersectionLock != NULL);
  lock_destroy(intersectionLock);

  for(int i = 0; i < 4; ++i) {
    KASSERT(directions[i] != NULL);
    cv_destroy(directions[i]);
  }

  KASSERT(waitQueue);
  q_destroy(waitQueue);
  return;
  
}


/*
 * The simulation driver will call this function each time a vehicle
 * tries to enter the intersection, before it enters.
 * This function should cause the calling simulation thread 
 * to block until it is OK for the vehicle to enter the intersection.
 *
 * parameters:
 *    * origin: the Direction from which the vehicle is arriving
 *    * destination: the Direction in which the vehicle is trying to go
 *
 * return value: none
 */

void
intersection_before_entry(Direction origin, Direction destination) 
{
  /* replace this default implementation with your own implementation */
  (void)destination; /* avoid compiler complaint about unused parameter */
  KASSERT(intersectionLock != NULL);
  
  lock_acquire(intersectionLock);
  if(entry == -1) {
    entry = origin;
  } else {
    if(entry != (signed)origin) {
      if(inWait[origin] == false) {
        q_addtail(waitQueue,&dirList[origin]);
        inWait[origin] = true;
      }
      cv_wait(directions[origin],intersectionLock);
    }
  }
  countCars++;
  lock_release(intersectionLock);
  return;
}


/*
 * The simulation driver will call this function each time a vehicle
 * leaves the intersection.
 *
 * parameters:
 *    * origin: the Direction from which the vehicle arrived
 *    * destination: the Direction in which the vehicle is going
 *
 * return value: none
 */

void
intersection_after_exit(Direction origin, Direction destination) 
{
  /* replace this default implementation with your own implementation */
  (void)origin; /* avoid compiler complaint about unused parameter */
  (void)destination; /* avoid compiler complaint about unused parameter */
  KASSERT(intersectionLock != NULL);
  lock_acquire(intersectionLock);
  countCars--;
  if(countCars == 0) {
    if(q_empty(waitQueue)) {
      entry = -1;
    } else {
      entry = *(int*)(q_peek(waitQueue));
      q_remhead(waitQueue);
      inWait[entry] = false;
      cv_broadcast(directions[entry],intersectionLock);
    }
  }
  lock_release(intersectionLock);
  return;

}
