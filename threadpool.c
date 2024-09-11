#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "threadpool.h"


// Function to initialize the threadpool
threadpool* create_threadpool(int num_threads_in_pool) {
    // Input sanity check
    if (num_threads_in_pool <= 0 || num_threads_in_pool > MAXT_IN_POOL) {
        fprintf(stderr, "Invalid number of threads in the pool\n");
        return NULL;
    }

    // Allocate memory for the threadpool structure
    threadpool *pool = (threadpool*)malloc(sizeof(threadpool));
    if (!pool) {
        perror("Failed to allocate memory for threadpool");
        return NULL;
    }

    // Initialize threadpool structure
    pool->num_threads = num_threads_in_pool;
    pool->qsize = 0;
    pool->qhead = pool->qtail = NULL;
    pool->shutdown = pool->dont_accept = 0;

    // Initialize mutex and conditional variables
    if (pthread_mutex_init(&(pool->qlock), NULL) != 0) {
        perror("Failed to initialize mutex");
        free(pool);
        return NULL;
    }
    if (pthread_cond_init(&(pool->q_empty), NULL) != 0 || pthread_cond_init(&(pool->q_not_empty), NULL) != 0) {
        perror("Failed to initialize condition variables");
        pthread_mutex_destroy(&(pool->qlock));
        free(pool);
        return NULL;
    }

    // Allocate memory for threads
    pool->threads = (pthread_t*)malloc(num_threads_in_pool * sizeof(pthread_t));
    if (!pool->threads) {
        perror("Failed to allocate memory for threads");
        pthread_mutex_destroy(&(pool->qlock));
        pthread_cond_destroy(&(pool->q_empty));
        pthread_cond_destroy(&(pool->q_not_empty));
        free(pool);
        return NULL;
    }

    // Create threads
    int i;
    for (i = 0; i < num_threads_in_pool; ++i) {
        if (pthread_create(&(pool->threads[i]), NULL, do_work, (void*)pool) != 0) {
            perror("Failed to create thread");
            // Clean up created threads
            for (int j = 0; j < i; ++j) {
                pthread_cancel(pool->threads[j]);
            }
            free(pool->threads);
            pthread_mutex_destroy(&(pool->qlock));
            pthread_cond_destroy(&(pool->q_empty));
            pthread_cond_destroy(&(pool->q_not_empty));
            free(pool);
            return NULL;
        }
    }

    return pool;
}

// Function to add a job to the threadpool's queue
void dispatch(threadpool* from_me, dispatch_fn dispatch_to_here, void *arg) {
    if (from_me == NULL || dispatch_to_here == NULL) {
        fprintf(stderr, "Invalid arguments\n");
        return;
    }

    // Create a work_t structure and initialize it
    work_t *work = (work_t*)malloc(sizeof(work_t));
    if (!work) {
        perror("Failed to allocate memory for work_t");
        return;
    }
    work->routine = dispatch_to_here;
    work->arg = arg;
    work->next = NULL;

    pthread_mutex_lock(&(from_me->qlock));

    if (from_me->dont_accept) {
        // If destroy function has begun, don't accept new item to the queue
        free(work);
        pthread_mutex_unlock(&(from_me->qlock));
        return;
    }

    // Add item to the queue
    if (from_me->qtail == NULL) {
        from_me->qhead = from_me->qtail = work;
    } else {
        from_me->qtail->next = work;
        from_me->qtail = work;
    }
    from_me->qsize++;

    pthread_cond_signal(&(from_me->q_not_empty));
    pthread_mutex_unlock(&(from_me->qlock));
}

// Function to perform the work by the threads
void* do_work(void* p) {
    threadpool *pool = (threadpool*)p;
    while (1) {
        pthread_mutex_lock(&(pool->qlock));
        while (pool->qsize == 0 && !pool->shutdown) {
            pthread_cond_wait(&(pool->q_not_empty), &(pool->qlock));
        }

        if (pool->shutdown) {
            pthread_mutex_unlock(&(pool->qlock));
            pthread_exit(NULL);
        }

        work_t *work = pool->qhead;
        if (work != NULL) {
            pool->qhead = work->next;
            if (pool->qhead == NULL) {
                pool->qtail = NULL;
            }
            pool->qsize--;
        }

        pthread_mutex_unlock(&(pool->qlock));

        if (work != NULL) {
            (*(work->routine))(work->arg);
            free(work);
        }
    }
    return NULL;
}

// Function to destroy the threadpool
void destroy_threadpool(threadpool* destroyme) {
    if (destroyme == NULL) {
        return;
    }

    pthread_mutex_lock(&(destroyme->qlock));
    destroyme->dont_accept = 1;

    while (destroyme->qsize > 0) {
        pthread_cond_wait(&(destroyme->q_empty), &(destroyme->qlock));
    }

    destroyme->shutdown = 1;

    pthread_cond_broadcast(&(destroyme->q_not_empty));
    pthread_mutex_unlock(&(destroyme->qlock));

    for (int i = 0; i < destroyme->num_threads; ++i) {
        pthread_join(destroyme->threads[i], NULL);
    }

    pthread_mutex_destroy(&(destroyme->qlock));
    pthread_cond_destroy(&(destroyme->q_not_empty));
    pthread_cond_destroy(&(destroyme->q_empty));
    free(destroyme->threads);
    free(destroyme);
}
