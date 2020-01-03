#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <pthread.h>

void printids(const char *s)
{
    pid_t pid;
    pthread_t tid;
    pid = getpid();
    tid = pthread_self();
    printf("%s pid %u tid %u (0x%x)\n", s, (unsigned int) pid,
            (unsigned int) tid, (unsigned int) tid);
}

void* thr_fn1(void* arg)
{

    int* t = (int*)arg;
    *t += 1;
    printf("sub1: %d\n", *t);

    for (int i = 1; i <= 10; i++){
        usleep(100000);
        *t += 10;
        printf("hahaha!\n");
    }

    printids("new thread 1: ");
    printf("sub1: %d\n", *t);
    return NULL;
}

void* thr_fn2(void* arg)
{
    int* t = (int*)arg;
    *t += 1;
    printf("sub2: %d\n", *(int*)arg);
    return NULL;
}

int main(void)
{
    int* dp;
    int d = 4;
    dp = &d;

    int err;
    pthread_t ntid1, ntid2;

    err = pthread_create(&ntid1, NULL, thr_fn1, dp);
    err = pthread_create(&ntid2, NULL, thr_fn2, dp);

    if (err != 0)
        printf("can't create thread: %s\n", strerror(err));
    for (int i = 1; i <= 10; i++){
        d += 1;
    }
    printf("main, d = %d\n", d);
    printids("main thread:");
    pthread_join(ntid1, NULL);
    pthread_join(ntid2, NULL);

    return 0;
}

//int main()
//{
//    pthread_t a;
//    printf("%u\n", (unsigned int)a);
//    pthread_create(&a, NULL, shit, NULL);
//}
