#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pwd.h>

/* HOSTNAME_LEN_MAX:
 *
 * Upper limit on the length of hostname
 */
#define HOSTNAME_LEN_MAX 1024

/* DIRECTORY_LEN_MAX:
 *
 * Upper limit on the length of a directory
 */
#define DIRECTORY_LEN_MAX 1024

/* COMMAND_LEN_MAX:
 *
 * Upper limit on the length of a command
 */
#define COMMAND_LEN_MAX 1024

/* INFO_LEN_MAX:
 *
 * Upper limit on the combined length of all information
 * of a process present in /proc/<pid>/stat
 */
#define INFO_LEN_MAX 1024

/* REDIRECTION_MAX:
 *
 * Upper limit on the number of redirection operators
 * in a command
 */
#define REDIRECTION_MAX 256

/* STREQ (str1, str2)
 * Return true if two strings compare equal
 */
#define STREQ(a,b) (strcmp(a,b) == 0)

/* STREQ (str1, str2)
 * Return true if two strings compare unequal
 */
#define STRNEQ(a,b) (strcmp(a,b) != 0)

enum {
    PROC_LOC_BG,                /* Bacground process */
    PROC_LOC_FG,                /* Foreground process */
} procLoc;

typedef struct _procInfo procInfo;
struct _procInfo {
    char *cmd;
    unsigned int pid;           /* pid */
    int location;               /* procLoc */
};

char *HOME = NULL;              /* Home directory */
char *EXECPATH;                 /* Curent executable path */
procInfo *PROCINFO = NULL;      /* Processes' info */
unsigned int *CMDCOUNT = NULL;  /* Number of commands till now */
int JOBID = 0;                  /* Number of JOBs */
int CURRPID = 0;                /* Process ID of current/last running process */

void printPrompt(const char *currdir);
char ** processCommand(char **commands, unsigned int *cmdCount);
char ** parseCommand(char *command, char *delim);
size_t stringListLength(char **strings);
void runCommand(char *command, unsigned int *cmdCount);
void stringListFree(char **strings);
void updateInfo(int jobID, int procLoc);
void printInfo(int pid);
void printJobs(void);
int fileExists(char *filename);
void killProc(int jobID, int signum);
void killBGProcs(void);
void cleanZombies(void);
void signalCallbackHandler(int signum);
void wakeUpBG(int jobID);

int main(int argc, char **argv) {
    char currdir[DIRECTORY_LEN_MAX];
    char homedir[DIRECTORY_LEN_MAX];
    char **commands = NULL;
    unsigned int cmdCount = 0;

    /* Current directory is home directory */
    if (getcwd(homedir, DIRECTORY_LEN_MAX) == NULL)
        perror("getcwd() error");
    HOME = homedir;
    CMDCOUNT = &cmdCount;
    EXECPATH = argv[0];

    /* Signal handlers */
    signal(SIGINT, signalCallbackHandler);
    signal(SIGTSTP, signalCallbackHandler);

    while (1) {
        /* Update current working directory */
        if (getcwd(currdir, DIRECTORY_LEN_MAX) == NULL)
            perror("getcwd() error");

        /* Clean all zombie processes */
        cleanZombies();

        /* Print the prompt */
        printPrompt(currdir);

        /* Do the Dew! */
        commands = processCommand(commands, &cmdCount);
    }
    stringListFree(commands);
    return 0;
}

/**
 * printPrompt:
 * @currdir: Pointer to the array holding the current directory
 *
 * The directory from which the shell is invoked will be the home directory
 * of the shell and should be indicated by "~". If the user executes "cd"
 * change dir then the corresponding change must be reflected in the shell
 * as well.
 *
 * E.g., ./a.out
 * <Peytr@ICS231:~>cd newdir
 * <Peytr@ICS231:~/newdir>
 */
void
printPrompt(const char *currdir) {
    char *username = NULL;
    const char *homedir = HOME;
    char hostname[HOSTNAME_LEN_MAX];
    register struct passwd *pw;
    register uid_t uid;
    int dst = 0;

    uid = geteuid();
    pw = getpwuid(uid);
    if (pw)
       username = strndup(pw->pw_name, strlen(pw->pw_name));

    gethostname(hostname, HOSTNAME_LEN_MAX - 1);

    if (strlen(homedir) <= strlen(currdir)) {
        dst = strncmp(homedir, currdir, strlen(homedir));

        printf("<%s@%s:%s%s> ", username, hostname,
               dst > 0 ? "" : "~",
               dst > 0 ? currdir : currdir + strlen(homedir));
    }
    else
        printf("<%s@%s:%s%s> ", username, hostname, "", currdir);

    free(username);
}

/**
 * processCommand:
 * @commands: pointer to an array of strings, which hold the commands
 * @cmdCount: cariable keeping track of number of commands so far
 *
 * The function scans the command from STDIN and populates @commands
 * accordingly.
 *
 * Returns the pointer @commands after updating it.
 */
char **
processCommand(char **commands,
               unsigned int *cmdCount)
{
    char cmdTemp[COMMAND_LEN_MAX];
    if (!fgets(cmdTemp, COMMAND_LEN_MAX, stdin))
        return commands;
    cmdTemp[strlen(cmdTemp) - 1] = '\0';
    if (STRNEQ(cmdTemp, "")) {
        commands = realloc(commands, sizeof(commands)*(*cmdCount + 1));
        commands[*cmdCount] = malloc(COMMAND_LEN_MAX);
        strncpy(commands[*cmdCount], cmdTemp, COMMAND_LEN_MAX);
        runCommand(commands[*cmdCount], cmdCount);
        *cmdCount += 1;
    }
    return commands;
}

/**
 * parseCommand:
 * @command: string with current command as its value.
 * @delim: delimiter according to which command has to be tokenized
 *
 * The function splits @command with the delimiter, @delim and returns
 * the allocated array of strings.
 */
char **
parseCommand(char *command,
             char *delim)
{
    char **cmd = NULL;
    char *tmpstr = NULL;
    unsigned int token = 0;
    cmd = malloc(sizeof(*cmd));
    cmd[token++] = strdup(strtok(command, delim));
    while ((tmpstr= strtok(NULL, delim)) != NULL) {
        cmd = realloc(cmd, sizeof(*cmd)*(token + 1));
        cmd[token++] = strdup(tmpstr);
    }
    cmd = realloc(cmd, sizeof(*cmd)*(token + 1));
    cmd[token++] = NULL;
    return cmd;
}

/**
 * stringListLength:
 * @strings: array of strings
 *
 * The function returns the number of elements in the array, @strings
 */
size_t
stringListLength(char **strings) {
    size_t i = 0;
    while (strings && strings[i])
        i++;
    return i;
}

/**
 * stringListFree:
 * @strings: array of strings
 *
 * The function frees all the memory occupied by @strings
 */
void
stringListFree(char **strings) {
    char **tmp = strings;
    while (tmp && *tmp) {
        free(*tmp);
        tmp++;
    }
    free(strings);
}

/**
 * runCommand:
 * @command: string holding the current command
 * @cmdCount: variable holding the current number of commands
 *
 * The function analyzes the command, categorizes as built-in, user-defined and
 * system. Performs the necessary task of creating child processes and executing
 * he command. Handles all the piping and redirection stuff.
 */
void
runCommand(char *command,
           unsigned int *cmdCount)
{
    pid_t pid;
    int status;
    size_t i, j;
    int procLoc = PROC_LOC_FG;
    int jobID = 0;
    char *commandCopy = strdup(command);
    char **cmd = parseCommand(command, " ");

    unsigned int cmdLength = stringListLength(cmd);
    if (!cmdLength) return;

    /* Is the process to be run in background? */
    for (i = 0; i < cmdLength; i++) {
        if (STREQ(cmd[i], "&")) {
            cmd[i] = NULL;
            procLoc = PROC_LOC_BG;
        }
    }
    /* Is it a built-in command? */
    if (STREQ(cmd[0], "cd")) {
        if (chdir(cmdLength > 1 && cmd[1] != NULL
                  ? cmd[1] : HOME) < 0)
            perror("chdir() error");
    }
    /* Is it a user-defined command? */
    else if (STREQ(cmd[0], "pinfo")) {
        if (cmdLength > 1)
            printInfo(atoi(cmd[1]));
        else
            printInfo(-1);
    }
    else if (STREQ(cmd[0], "jobs")) {
        printJobs();
    }
    else if (STREQ(cmd[0], "quit") || STREQ(cmd[0], "exit")) {
        killBGProcs();
        _exit(0);
    }
    else if (STREQ(cmd[0], "kjob")) {
        if (cmdLength != 3)
            printf("Correct syntax is: kjob <jobNumber> <signalNumber>\n");
        else
            killProc(atoi(cmd[1]), atoi(cmd[2]));
    }
    else if (STREQ(cmd[0], "overkill")) {
        killBGProcs();
    }
    else if (STREQ(cmd[0], "fg")) {
        if (cmdLength != 2)
            printf("Correct syntax is: fg <jobNumber>\n");
        else
            wakeUpBG(atoi(cmd[1]));
    }
    else if (cmd[0][0] == 0x0C) {
        printf("\033[2J\033[H");
    }

    else {
        /* Is it a system command? */
        if ((pid = fork()) < 0) {
            printf("ERROR: forking child process failed\n");
            _exit(1);
        }
        else if (pid == 0) {
            char **cmdChild = NULL;
            int redirection[REDIRECTION_MAX];
            int redirectCount = 0;
            unsigned int nCmds = 0;
            pid_t cpid;
            int fd[2];
            int tmp_fd;

            if (procLoc == PROC_LOC_BG)
                setpgid(0, 0);

            for (i = 0; i < strlen(commandCopy); i++) {
                switch(commandCopy[i]) {
                case '>': redirection[redirectCount++] = '>'; break;
                case '|': redirection[redirectCount++] = '|'; break;
                }
            }
            cmdChild = parseCommand(commandCopy, "|>");

            nCmds = stringListLength(cmdChild);
            if (nCmds > 2) {
                for (i = 0; i < nCmds; i++) {
                    if (pipe(fd) < 0)
                        perror("pipe error");
                    if ((cpid = fork()) < 0) {
                        perror("fork error");
                    } else if (cpid == 0) {
                        close(fd[0]);
                        char **tmpCmd = parseCommand(cmdChild[i], " ");
                        int tmpLen = stringListLength(tmpCmd);
                        for (j = 0; j < tmpLen; j++) {
                            if (STREQ(tmpCmd[j], "<")) {
                                tmpCmd[j] = tmpCmd[j + 1];
                                tmpCmd[j + 1] = NULL;
                                break;
                            } else if (STREQ(tmpCmd[j], "&"))
                                tmpCmd[j] = NULL;
                        }
                        if (redirection[i] == '>') {
                            char **path = parseCommand(cmdChild[i + 1], " ");
                            tmp_fd = open(path[0], O_CREAT | O_WRONLY | O_TRUNC, 0644);
                            dup2(tmp_fd, STDOUT_FILENO);
                            close(tmp_fd);
                        }
                        else if (i != (nCmds - 1))
                            dup2(fd[1], STDOUT_FILENO);

                        if ((redirection[i - 1] != '>') &&
                            (execvp(*tmpCmd, tmpCmd) < 0)){
                            printf("ERROR: %s: command not found\n", tmpCmd[0]);
                            _exit(1);
                        }

                        close(fd[1]);
                        _exit(0);
                    }
                    else {
                        close(fd[1]);
                        if (waitpid(cpid, NULL, 0) < 0)
                            perror("waitpid error");
                        if (i != (nCmds - 1))
                            dup2(fd[0], STDIN_FILENO);

                        close(fd[0]);
                    }
                }
            }
            else if (execvp(*cmd, cmd) < 0) {
                printf("ERROR: %s: command not found\n", cmd[0]);
                _exit(1);
            }
            _exit(0);
        }
        else{
            CURRPID = pid;
            jobID = JOBID++;
            PROCINFO = realloc(PROCINFO, sizeof(procInfo)*(jobID + 1));
            PROCINFO[jobID].cmd = commandCopy;
            PROCINFO[jobID].pid = pid;
            PROCINFO[jobID].location = procLoc;
            if(procLoc == PROC_LOC_FG) {
                waitpid(-1, &status, WUNTRACED);
            }
        }
    }
    stringListFree(cmd);
    cleanZombies();
}

/**
 * printInfo:
 * @pid: process id of the process whose information is to be printed
 *
 * The function prints the information available fot a certain process. The
 * information includes name, pid, status, virtual memory size, and executable
 * path (only for the shell)
 */
void
printInfo(int pid) {
    char statFile[DIRECTORY_LEN_MAX];
    char statInfo[INFO_LEN_MAX];
    char **info = NULL;
    sprintf(statFile, "/proc/%d/stat", pid != -1 ? pid: getpid());
    FILE *fp = fopen(statFile, "r");
    if (!fp) {
        perror("fopen() error");
        return;
    }
    fgets(statInfo, INFO_LEN_MAX, fp);
    info = parseCommand(statInfo, " ");
    printf("Process ID\t--\t%s\n"
           "Process Name\t--\t%s\n"
           "Process Status\t--\t%s\n"
           "Virtual Memory Size\t--\t%s\n",
           info[0],
           info[1],
           info[2],
           info[22]);
   if (pid == -1)
       printf("Executable Path\t--\t%s\n", EXECPATH);
   stringListFree(info);
}

/**
 * printJobs:
 *
 * The function prints the information about the processes running in
 * background
 */
void
printJobs(void) {
    size_t i;
    char statFile[DIRECTORY_LEN_MAX];
    int bgCount = 0;
    for (i = 0; i < JOBID; i++) {
        if(PROCINFO[i].location == PROC_LOC_BG) {
            sprintf(statFile, "/proc/%d/stat", PROCINFO[i].pid);
            if (fileExists(statFile)) {
                bgCount++;
                printf("[%d] %s [%d]\n", bgCount, PROCINFO[i].cmd, PROCINFO[i].pid);
            }
        }
    }
}

/**
 * fileExists:
 * @filename: path to the filename whose existence is to be tested
 *
 * Returns 1 in case of success, 0 otherwise
 */
int
fileExists(char *filename) {
    struct stat buffer;
    return stat(filename, &buffer) == 0;
}

/**
 * killProc:
 * @jobID: jobID of the background process
 * @signum: signal to be sent to that job
 *
 */
void
killProc(int jobID,
         int signum) {
    size_t i;
    int bgCount = 0;
    char statFile[DIRECTORY_LEN_MAX];
    for (i = 0; i < JOBID; i++) {
        if(PROCINFO[i].location == PROC_LOC_BG) {
            sprintf(statFile, "/proc/%d/stat", PROCINFO[i].pid);
            if (fileExists(statFile)) {
                bgCount++;
                if (bgCount == jobID) {
                    if (kill(PROCINFO[i].pid, signum) < 0)
                        perror("kill() error");
                    break;
                }
            }
        }
    }
}

/**
 * killBGProcs:
 *
 * Kills all the background processes
 */
void
killBGProcs(void) {
    size_t i;
    char statFile[DIRECTORY_LEN_MAX];
    for (i = 0; i < JOBID; i++) {
        if(PROCINFO[i].location == PROC_LOC_BG) {
            sprintf(statFile, "/proc/%d/stat", PROCINFO[i].pid);
            if (fileExists(statFile)) {
                if (kill(PROCINFO[i].pid, SIGKILL) < 0)
                    perror("kill() error");
            }
        }
    }
}

/**
 * wakeUpBG:
 * @jobID: jobID of the background process to continue
 *
 * Sends SIGCONT to the background process, so that it can
 * continue executing
 */
void
wakeUpBG(int jobID) {
    size_t i;
    int bgCount = 0;
    char statFile[DIRECTORY_LEN_MAX];
    for (i = 0; i < JOBID; i++) {
        if(PROCINFO[i].location == PROC_LOC_BG) {
            sprintf(statFile, "/proc/%d/stat", PROCINFO[i].pid);
            if (fileExists(statFile)) {
                bgCount++;
                if (bgCount == jobID) {
                    if (kill(PROCINFO[i].pid, SIGCONT) < 0)
                        perror("kill() error");
                    CURRPID = PROCINFO[i].pid;
                    break;
                }
            }
        }
    }
}

/**
 * cleanZombies:
 *
 * Kills all the background processes which have turned into zombies
 */
void
cleanZombies(void) {
    size_t i;
    for (i = 0; i < JOBID; i++) {
        if(PROCINFO[i].location == PROC_LOC_BG) {
            if (waitpid(PROCINFO[i].pid, NULL, WNOHANG) > 0)
                printf("%s with pid %d exited normally\n",
                       PROCINFO[i].cmd, PROCINFO[i].pid);
        }
    }
}

/**
 * signalCallbackHandler
 * @signum: singal to be caught
 *
 * Handles the signal caught.
 */
void
signalCallbackHandler(int signum) {
    size_t i;
    if (signum == SIGTSTP) {
        for (i = 0; i < JOBID; i++) {
            if (PROCINFO[i].pid == CURRPID) {
                kill(PROCINFO[i].pid, SIGSTOP);
                PROCINFO[i].location = PROC_LOC_BG;
                break;
            }
        }
    }
}
