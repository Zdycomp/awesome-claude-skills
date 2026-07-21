/*
 * termexec.c — minimal, hardened PTY subprocess launcher for SecureTerm.
 *
 * Security posture:
 *  - The child runs as the app's own UID inside the normal Android app
 *    sandbox (SELinux untrusted_app domain). Nothing here elevates
 *    privileges; there is no setuid, no capability manipulation.
 *  - The child gets an explicitly constructed environment (passed from
 *    Kotlin), never the parent's inherited environment, so app-process
 *    secrets can't leak into the shell.
 *  - Resource limits (no core dumps, bounded fds/processes/file size)
 *    are applied in the child before exec to blunt fork bombs and
 *    runaway output.
 *  - All fds above stderr are closed before exec so the shell cannot
 *    inherit stray app file descriptors (sockets, databases, etc.).
 *  - Every JNI string is bounds-checked; fixed-size buffers are never
 *    written past their length (lengths validated before copy).
 */

#include <jni.h>

#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define MAX_ARGS 32
#define MAX_ENV  32
#define MAX_STR  4096

/* Duplicate a Java string into a bounded, NUL-terminated malloc'd buffer.
 * Returns NULL (and sets no Java exception — caller handles) if the string
 * is missing or exceeds MAX_STR bytes in UTF-8. */
static char *dup_jstring_bounded(JNIEnv *env, jstring js) {
    if (js == NULL) return NULL;
    const char *utf = (*env)->GetStringUTFChars(env, js, NULL);
    if (utf == NULL) return NULL; /* OOM: pending Java exception */
    size_t len = strlen(utf);
    char *out = NULL;
    if (len < MAX_STR) {
        out = malloc(len + 1);
        if (out != NULL) memcpy(out, utf, len + 1);
    }
    (*env)->ReleaseStringUTFChars(env, js, utf);
    return out;
}

static void free_vec(char **vec) {
    if (vec == NULL) return;
    for (size_t i = 0; vec[i] != NULL; i++) free(vec[i]);
    free(vec);
}

/* Convert a Java String[] into a NULL-terminated char* vector with hard
 * caps on element count and element size. Returns NULL on any violation. */
static char **jarray_to_vec(JNIEnv *env, jobjectArray arr, jsize max_items) {
    jsize n = (arr == NULL) ? 0 : (*env)->GetArrayLength(env, arr);
    if (n < 0 || n > max_items) return NULL;
    char **vec = calloc((size_t)n + 1, sizeof(char *));
    if (vec == NULL) return NULL;
    for (jsize i = 0; i < n; i++) {
        jstring js = (jstring)(*env)->GetObjectArrayElement(env, arr, i);
        vec[i] = dup_jstring_bounded(env, js);
        if (js != NULL) (*env)->DeleteLocalRef(env, js);
        if (vec[i] == NULL) {
            free_vec(vec);
            return NULL;
        }
    }
    return vec;
}

static void throw_io(JNIEnv *env, const char *generic_msg) {
    jclass cls = (*env)->FindClass(env, "java/io/IOException");
    if (cls != NULL) {
        /* Deliberately generic: never surface errno text or paths to the UI. */
        (*env)->ThrowNew(env, cls, generic_msg);
    }
}

JNIEXPORT jint JNICALL
Java_com_zdycomp_secureterm_term_Pty_createSubprocess(
        JNIEnv *env, jclass clazz,
        jstring j_cmd, jstring j_cwd,
        jobjectArray j_args, jobjectArray j_env,
        jint rows, jint cols,
        jintArray j_pid_out) {
    (void)clazz;

    if (j_pid_out == NULL || (*env)->GetArrayLength(env, j_pid_out) < 1) {
        throw_io(env, "invalid launch request");
        return -1;
    }
    if (rows < 2 || rows > 1000 || cols < 2 || cols > 1000) {
        throw_io(env, "invalid terminal geometry");
        return -1;
    }

    char *cmd = dup_jstring_bounded(env, j_cmd);
    char *cwd = dup_jstring_bounded(env, j_cwd);
    char **argv = jarray_to_vec(env, j_args, MAX_ARGS);
    char **envp = jarray_to_vec(env, j_env, MAX_ENV);

    if (cmd == NULL || cwd == NULL || argv == NULL || envp == NULL) {
        free(cmd); free(cwd); free_vec(argv); free_vec(envp);
        throw_io(env, "invalid launch request");
        return -1;
    }

    struct winsize ws;
    memset(&ws, 0, sizeof(ws));
    ws.ws_row = (unsigned short)rows;
    ws.ws_col = (unsigned short)cols;

    int master_fd = -1;
    pid_t pid = forkpty(&master_fd, NULL, NULL, &ws);

    if (pid < 0) {
        free(cmd); free(cwd); free_vec(argv); free_vec(envp);
        throw_io(env, "failed to start shell");
        return -1;
    }

    if (pid == 0) {
        /* ---- child ---- */

        /* Reset signal dispositions the app runtime may have altered. */
        for (int sig = 1; sig < NSIG; sig++) signal(sig, SIG_DFL);
        sigset_t empty;
        sigemptyset(&empty);
        sigprocmask(SIG_SETMASK, &empty, NULL);

        /* Resource guard: no core dumps (could contain sensitive memory),
         * bounded descriptors, bounded process count (fork-bomb brake),
         * bounded single-file size (16 GiB cap against runaway writes). */
        struct rlimit rl;
        rl.rlim_cur = 0;            rl.rlim_max = 0;
        setrlimit(RLIMIT_CORE, &rl);
        rl.rlim_cur = 512;          rl.rlim_max = 512;
        setrlimit(RLIMIT_NOFILE, &rl);
        rl.rlim_cur = 256;          rl.rlim_max = 256;
        setrlimit(RLIMIT_NPROC, &rl);
        rl.rlim_cur = (rlim_t)16 * 1024 * 1024 * 1024;
        rl.rlim_max = rl.rlim_cur;
        setrlimit(RLIMIT_FSIZE, &rl);

        /* Close every inherited descriptor above stderr so the shell can't
         * touch the app's open sockets/files. */
        int max_fd = (int)sysconf(_SC_OPEN_MAX);
        if (max_fd <= 0 || max_fd > 4096) max_fd = 4096;
        for (int fd = 3; fd < max_fd; fd++) close(fd);

        if (chdir(cwd) != 0) {
            /* Home missing: fall back to root of app sandbox ("/" is
             * readable but the shell still has no special rights). */
            chdir("/");
        }

        execve(cmd, argv, envp);
        _exit(127); /* exec failed; exit without flushing parent's stdio */
    }

    /* ---- parent ---- */
    free(cmd); free(cwd); free_vec(argv); free_vec(envp);

    /* Never leak the master fd into future children of the app process. */
    fcntl(master_fd, F_SETFD, FD_CLOEXEC);

    jint pid_val = (jint)pid;
    (*env)->SetIntArrayRegion(env, j_pid_out, 0, 1, &pid_val);
    return master_fd;
}

JNIEXPORT void JNICALL
Java_com_zdycomp_secureterm_term_Pty_setWindowSize(
        JNIEnv *env, jclass clazz, jint fd, jint rows, jint cols) {
    (void)env; (void)clazz;
    if (fd < 0 || rows < 2 || rows > 1000 || cols < 2 || cols > 1000) return;
    struct winsize ws;
    memset(&ws, 0, sizeof(ws));
    ws.ws_row = (unsigned short)rows;
    ws.ws_col = (unsigned short)cols;
    ioctl(fd, TIOCSWINSZ, &ws);
}

JNIEXPORT jint JNICALL
Java_com_zdycomp_secureterm_term_Pty_waitFor(JNIEnv *env, jclass clazz, jint pid) {
    (void)env; (void)clazz;
    if (pid <= 0) return -1; /* refuse pid 0 / -1: would wait on arbitrary group */
    int status = 0;
    pid_t r;
    do {
        r = waitpid((pid_t)pid, &status, 0);
    } while (r < 0 && errno == EINTR);
    if (r < 0) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}

JNIEXPORT void JNICALL
Java_com_zdycomp_secureterm_term_Pty_hangup(JNIEnv *env, jclass clazz, jint pid) {
    (void)env; (void)clazz;
    /* Strictly positive pid only: kill(0,..)/kill(-1,..) would signal the
     * whole process group / every process we can reach. Never allow that. */
    if (pid <= 0) return;
    kill((pid_t)pid, SIGHUP);
}

JNIEXPORT void JNICALL
Java_com_zdycomp_secureterm_term_Pty_closeFd(JNIEnv *env, jclass clazz, jint fd) {
    (void)env; (void)clazz;
    if (fd < 3) return; /* never close stdio of the app process */
    close(fd);
}
