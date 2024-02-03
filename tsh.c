/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * Description: Implemented a tiny shell application capable of spawning child
 * processes that can run other applications in its context either in the
 * foreground or background.
 *
 * There are 4 built in functions
 * 1)   No built-in function option
 *      Spawns a child process and executes an application or task in the
 * context of the child process
 *
 * 2)quit
 *      Quitting an application
 * 3)fg
 *      Running a listed application(job) in the foreground, waiting till
 *      the application terminates to be reaped by the child signal handler
 *
 * 4)bg
 *      Running a listed application(job) in the background, not waiting
 *      till the application terminates to reap the process
 *
 * Child signal handler aids in reaping exited/signaled child processes and
 * stopping child process Interrupt signal handler sends interrupt signal to a
 * process group Stop signal handler sends stop signal to a process group
 * Application is designed to handle invalid and incomplete command and command
 * arguments. This tiny shell is mimicing the behaviour of the reference shell
 * "tshref"
 *
 * @author Abhishek Basrithaya <abasrith@andrew.cmu.edu>
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);

void ioRedirectionForNONEBuiltin(struct cmdline_tokens *inputToken);
/**
 * @brief Functionalities of the main function are as follows:-
 *          *Parcers the command line argument
 *          *Setups up a job queue and signal handlers
 *          *Setups up an infinite loop to evaluate the command line arguments
 *
 *
 * @param[in]   argc    No of arguments passed
 * @param[in]   agrv    Actual array contents of the argument passed
 *
 * @return      void
 */
int main(int argc, char **argv) {
    char c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv("MY_ENV=42") < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

/**
 * @brief Evaluates a command line argument and performs appropriate actions
 * based on the commandline argument such as spawing a child process to execute
 * an application, running a process in the foreground or background and
 * quitting an applciation. Error handling is built in to handle invalid command
 * and command arguments.
 *
 *
 * @param[in]   cmdline     Input commandline argument
 *
 * @return      void
 */
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;
    pid_t pidVar;
    int jobsPrintOutFile;
    sigset_t maskAllSignals, prevMask;
    int jobState;
    int jobID;
    // setup signal blocking and setting masks
    sigemptyset(&maskAllSignals);
    sigfillset(&maskAllSignals);

    // Parse command line
    parse_result = parseline(cmdline, &token);

    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    } else {
        if (parse_result == PARSELINE_FG)
            jobState = FG;
        else
            jobState = BG;
        if (token.builtin == BUILTIN_NONE) {
            // Block signals from interrupting process flow
            sigprocmask(SIG_BLOCK, &maskAllSignals, &prevMask);
            pidVar = fork();
            if (pidVar < 0) {
                sio_eprintf("ERROR: Failed to call fork\n");
                _exit(EXIT_FAILURE);
            } else if (pidVar == 0) {
                /* Child Process */
                /* Set group id of the child process different from the tiny
                shell ID */
                setpgid(0, 0);
                /* Redirect output and input files to standard out and standard
                in files */
                ioRedirectionForNONEBuiltin(&token);
                sigprocmask(SIG_SETMASK, &prevMask, NULL);
                // Execute application in child context
                if (execve(token.argv[0], token.argv, environ) < 0) {
                    sio_eprintf("%s: %s\n", cmdline, strerror(errno));
                    _exit(EXIT_FAILURE);
                }
            } else {
                /* Parent process */
                sigprocmask(SIG_BLOCK, &maskAllSignals, NULL);
                if ((jobID = add_job(pidVar, jobState, cmdline)) == 0) {
                    sio_eprintf("ERROR: Failed to add job\n");
                }
                if (jobState == BG) {
                    sio_printf("[%d] (%d) %s\n", jobID, pidVar, cmdline);
                }
                if (jobState == FG) {
                    // wait till foreground process ends
                    while (fg_job() != 0)
                        sigsuspend(&prevMask);
                }
                sigprocmask(SIG_SETMASK, &prevMask, NULL);
            }
        } else {
            // Quitting application
            if (token.builtin == BUILTIN_QUIT) {
                _exit(EXIT_SUCCESS);
            } else if (token.builtin == BUILTIN_JOBS) {
                sigprocmask(SIG_BLOCK, &maskAllSignals, &prevMask);
                jobsPrintOutFile = STDOUT_FILENO;
                if (token.outfile != NULL) {
                    jobsPrintOutFile =
                        open(token.outfile, O_CREAT | O_TRUNC | O_WRONLY,
                             S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
                    if (jobsPrintOutFile < 0) {
                        sio_eprintf("%s: %s\n", token.outfile, strerror(errno));
                        sigprocmask(SIG_SETMASK, &prevMask, NULL);
                        return;
                    }
                }
                // Print current jobs queued in the job list
                list_jobs(jobsPrintOutFile);
                sigprocmask(SIG_SETMASK, &prevMask, NULL);
            } else {
                // Builtin foreground or background job
                sigprocmask(SIG_BLOCK, &maskAllSignals, &prevMask);
                // Handling invalid command arguments
                if (token.argv[1] != NULL) {
                    if (!((token.argv[1][0] >= 'a' &&
                           token.argv[1][0] <= 'z') ||
                          (token.argv[1][0] >= 'A' &&
                           token.argv[1][0] <= 'Z'))) {
                        if (token.argv[1][0] == '%') {
                            jobID = atoi(&token.argv[1][1]);
                            if (job_exists(jobID))
                                pidVar = job_get_pid(jobID);
                            else {
                                sio_eprintf("%s: No such job\n", token.argv[1]);
                                sigprocmask(SIG_SETMASK, &prevMask, NULL);
                                return;
                            }
                        } else {
                            pidVar = atoi(&token.argv[1][0]);
                            if ((jobID = job_from_pid(pidVar)) == 0) {
                                sigprocmask(SIG_SETMASK, &prevMask, NULL);
                                return;
                            }
                        }
                    } else {
                        if (token.builtin == BUILTIN_FG)
                            sio_eprintf(
                                "fg: argument must be a PID or %%jobid\n");
                        else
                            sio_eprintf(
                                "bg: argument must be a PID or %%jobid\n");

                        sigprocmask(SIG_SETMASK, &prevMask, NULL);
                        return;
                    }
                    if (token.builtin == BUILTIN_FG) {
                        kill(-pidVar, SIGCONT);
                        job_set_state(jobID, FG);
                        // Wait till foreground process terminates
                        while (fg_job() != 0) {
                            sigsuspend(&prevMask);
                        }
                    } else if (token.builtin == BUILTIN_BG) {
                        sio_printf("[%d] (%d) %s\n", jobID, pidVar,
                                   job_get_cmdline(jobID));
                        kill(-pidVar, SIGCONT);
                        job_set_state(jobID, BG);
                    }
                } else {
                    if (token.builtin == BUILTIN_FG)
                        sio_eprintf(
                            "fg command requires PID or %%jobid argument\n");
                    else
                        sio_eprintf(
                            "bg command requires PID or %%jobid argument\n");
                    sigprocmask(SIG_SETMASK, &prevMask, NULL);
                    return;
                }
                sigprocmask(SIG_SETMASK, &prevMask, NULL);
            }
        }
    }
}

/**
 * @brief I/O redirection function redirects command line the input file to
 * standard input file and output file to standard output file
 *
 *
 * @param[in]   inputToken     Parced argument list containing the input and
 * output file paths to be redirected to standard output and input files
 *
 * @return      void
 */
void ioRedirectionForNONEBuiltin(struct cmdline_tokens *inputToken) {
    int redirectedOutputFd, redirectedInputFd;
    if (inputToken->outfile != NULL) {
        redirectedOutputFd =
            open(inputToken->outfile, O_CREAT | O_TRUNC | O_WRONLY,
                 S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        if (redirectedOutputFd < 0) {
            sio_eprintf("%s: %s\n", inputToken->outfile, strerror(errno));
            _exit(EXIT_FAILURE);
        } else {
            dup2(redirectedOutputFd, STDOUT_FILENO);
            if (close(redirectedOutputFd) < 0)
                sio_eprintf("Error: File close\n");
        }
    }
    if (inputToken->infile != NULL) {
        redirectedInputFd =
            open(inputToken->infile, O_RDONLY, S_IRUSR | S_IRGRP | S_IROTH);
        if (redirectedInputFd < 0) {
            sio_eprintf("%s: %s\n", inputToken->infile, strerror(errno));
            _exit(EXIT_FAILURE);
        } else {
            dup2(redirectedInputFd, STDIN_FILENO);
            if (close(redirectedInputFd) < 0)
                sio_eprintf("Error: File close\n");
        }
    }
}
/*****************
 * Signal handlers
 *****************/

/**
 * @brief Child signal handler to reap exited/signaled process and stopping a
 * currently running process
 *
 *
 * @param[in]   sig     Signal received by the signal handler
 *
 * @return      void
 */
void sigchld_handler(int sig) {
    int status;
    sigset_t maskAllSignals, prevMask;
    pid_t childPid;
    int jobID;
    int olderrno = errno;

    sigemptyset(&maskAllSignals);
    sigfillset(&maskAllSignals);
    sigprocmask(SIG_BLOCK, &maskAllSignals, &prevMask);
    while ((childPid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        if (WIFEXITED(status)) {
            jobID = job_from_pid(childPid);
            delete_job(jobID);
        } else if (WIFSIGNALED(status)) {
            jobID = job_from_pid(childPid);
            sio_printf("Job [%d] (%d) terminated by signal %d\n", jobID,
                       childPid, WTERMSIG(status));
            delete_job(jobID);
        } else if (WIFSTOPPED(status)) {
            jobID = job_from_pid(childPid);
            sio_printf("Job [%d] (%d) stopped by signal %d\n", jobID, childPid,
                       WSTOPSIG(status));
            job_set_state(jobID, ST);
        }
    }
    sigprocmask(SIG_SETMASK, &prevMask, NULL);
    errno = olderrno;
}

/**
 * @brief Interrupt signal handler to send a interrupt signal to a currently
 * running process/process group
 *
 *
 * @param[in]   sig     Signal received by the signal handler
 *
 * @return      void
 */
void sigint_handler(int sig) {
    sigset_t maskAllSignals, prevMask;
    pid_t pid;
    int olderrno = errno;

    sigemptyset(&maskAllSignals);
    sigfillset(&maskAllSignals);
    sigprocmask(SIG_BLOCK, &maskAllSignals, &prevMask);

    if (fg_job() == 0) {
        // No foreground job to Interrupt
    } else {
        pid = job_get_pid(fg_job());
        // send interrupt signal to a process group
        if (kill(-pid, SIGINT) < 0) {
            sio_eprintf("WARNING: Error interrupting process with PID=%d\n",
                        pid);
        }
    }
    sigprocmask(SIG_SETMASK, &prevMask, NULL);
    errno = olderrno;
}

/**
 * @brief Stop signal handler to send a stop signal a currently running
 * process/process group
 *
 *
 * @param[in]   sig     Signal received by the signal handler
 *
 * @return      void
 */
void sigtstp_handler(int sig) {
    sigset_t maskAllSignals, prevMask;
    pid_t pid;
    int olderrno = errno;

    sigemptyset(&maskAllSignals);
    sigfillset(&maskAllSignals);
    sigprocmask(SIG_BLOCK, &maskAllSignals, &prevMask);

    if (fg_job() == 0) {
        // No foreground job to stop
    } else {
        pid = job_get_pid(fg_job());
        // send stop signal to a process group
        if (kill(-pid, SIGTSTP) < 0) {
            sio_eprintf("WARNING: Error Stopping process with PID=%d\n", pid);
        }
    }
    sigprocmask(SIG_SETMASK, &prevMask, NULL);
    errno = olderrno;
}
/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}