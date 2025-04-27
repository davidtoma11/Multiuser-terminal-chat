#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <time.h>
#include <signal.h>

#define MAX_USERS 10
#define MAX_MESSAGES 100
#define MSG_SIZE 256
#define MAX_NAME_LEN 50
#define TIME_FORMAT "%H:%M:%S"

typedef struct {
    pid_t pid;
    uid_t uid;
    char username[MAX_NAME_LEN];
} User;

typedef struct {
    char text[MSG_SIZE];
    pid_t pid;
    uid_t uid;
    time_t timestamp;
} Message;

typedef struct {
    int num_users;
    User users[MAX_USERS];
    int num_messages;
    Message messages[MAX_MESSAGES];
} SharedData;

SharedData* data = NULL;
int fd = -1;
char* filename = NULL;
User current_user;
int last_seen = 0;


const char* format_time(time_t timestamp) {
    static char buf[20];
    strftime(buf, sizeof(buf), TIME_FORMAT, localtime(&timestamp));
    return buf;
}

void lock_file() {
    struct flock fl = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
    if (fcntl(fd, F_SETLKW, &fl)) {
        perror("lock failed");
        exit(1);
    }
}

void unlock_file() {
    struct flock fl = {.l_type = F_UNLCK, .l_whence = SEEK_SET};
    if (fcntl(fd, F_SETLKW, &fl)) {
        perror("unlock failed");
    }
}

void fill_user_info(User* user) {
    user->pid = getpid();
    user->uid = getuid();

    printf("Introduceti un nume pentru utilizator (maxim %d caractere): ", MAX_NAME_LEN-1);
    if (fgets(user->username, MAX_NAME_LEN, stdin) == NULL) {
        strcpy(user->username, "Anonim");
    }
    user->username[strcspn(user->username, "\n")] = 0;

    if (strlen(user->username) == 0) {
        struct passwd* pw = getpwuid(user->uid);
        if (pw) {
            strncpy(user->username, pw->pw_name, MAX_NAME_LEN-1);
        } else {
            strcpy(user->username, "Anonim");
        }
    }
}

void send_notification(const char* message) {
    lock_file();
    if (data->num_messages < MAX_MESSAGES) {
        Message* msg = &data->messages[data->num_messages++];
        snprintf(msg->text, MSG_SIZE, "--- %s %s ---", current_user.username, message);
        msg->pid = current_user.pid;
        msg->uid = current_user.uid;
        msg->timestamp = time(NULL);
    }
    unlock_file();
}

void connect_user() {
    lock_file();

    for (int i = 0; i < data->num_users; ++i) {
        if (data->users[i].pid == current_user.pid) {
            printf("[!] Esti deja conectat.\n");
            unlock_file();
            return;
        }
    }

    if (data->num_users >= MAX_USERS) {
        printf("[!] Grupul este plin.\n");
        unlock_file();
        exit(1);
    }

    data->users[data->num_users++] = current_user;
    printf("[*] Te-ai conectat ca %s (PID %d)\n", current_user.username, current_user.pid);

    unlock_file();

    char notification[MSG_SIZE];
    snprintf(notification, MSG_SIZE, "--- %s s-a conectat ---", current_user.username);
    send_notification(notification);
}

void disconnect_user_by_pid(pid_t pid) {
    lock_file();
    int found = 0;

    for (int i = 0; i < data->num_users; i++) {
        if (data->users[i].pid == pid) {
            kill(pid, SIGTERM);

            for (int j = i; j < data->num_users - 1; j++) {
                data->users[j] = data->users[j + 1];
            }
            data->num_users--;
            found = 1;
            break;
        }
    }

    unlock_file();

    if (found) {
        printf("[*] Utilizatorul cu PID %d a fost deconectat.\n", pid);
    } else {
        printf("[!] Nu există utilizator cu PID %d\n", pid);
    }
}

void disconnect_all_users() {
    lock_file();

    for (int i = 0; i < data->num_users; i++) {
        if (data->users[i].pid != current_user.pid) {
            kill(data->users[i].pid, SIGTERM);
        }
    }

    data->num_messages = 0;
    memset(data->messages, 0, sizeof(data->messages));

    data->num_users = 1;
    data->users[0] = current_user;

    unlock_file();

    printf("[*] Toți utilizatorii au fost deconectați și istoricul a fost șters.\n");
}

void disconnect_user() {
    lock_file();
    int found = 0;

    for (int i = 0; i < data->num_users; ++i) {
        if (data->users[i].pid == current_user.pid) {
            for (int j = i; j < data->num_users - 1; ++j) {
                data->users[j] = data->users[j + 1];
            }
            data->num_users--;
            found = 1;
            break;
        }
    }
    unlock_file();

    if (found) {
        char notification[MSG_SIZE];
        snprintf(notification, MSG_SIZE, "--- %s s-a deconectat ---", current_user.username);
        send_notification(notification);

        printf("[*] Te-ai deconectat.\n");
    }

    lock_file();
    if (data->num_users == 0) {
        printf("[*] Ultimul utilizator. Sterg fisierul...\n");
        unlock_file();
        munmap(data, sizeof(SharedData));
        close(fd);
        unlink(filename);
        exit(0);
    }
    unlock_file();
}

void print_message(const Message* msg) {
    if (msg->pid == current_user.pid) {
        return;  // Ignoră mesajele proprii
    }

    if (strstr(msg->text, "---") != NULL) {
        // Afișează notificările așa cum sunt (fără paranteze)
        printf("\033[1;33m%s\033[0m\n", msg->text);  // Galben
    } else {
        // Afișează mesajele normale cu [Nume]>
        struct passwd* pw = getpwuid(msg->uid);
        char* username = pw ? pw->pw_name : "unknown";
        printf("\033[1;34m[%s]\033[0m> %s", username, msg->text);  // Albastru
    }

    // Promptul tău (cu paranteze)
    printf("\033[1;32m[%s]\033[0m> ", current_user.username);  // Verde
    fflush(stdout);
}

void receive_messages() {
    // Afișează ultimele 10 mesaje la conectare (doar ale altora)
    lock_file();
    int start_idx = (data->num_messages > 10) ? data->num_messages - 10 : 0;
    printf("\n\033[1;35m--- Ultimele mesaje (%d) ---\033[0m\n", data->num_messages - start_idx);
    for (int i = start_idx; i < data->num_messages; i++) {
        if (data->messages[i % MAX_MESSAGES].pid != current_user.pid) {
            print_message(&data->messages[i % MAX_MESSAGES]);
        }
    }
    printf("\033[1;35m----------------------\033[0m\n\n");
    last_seen = data->num_messages;
    unlock_file();

    while (1) {
        lock_file();
        while (last_seen < data->num_messages) {
            Message* msg = &data->messages[last_seen % MAX_MESSAGES];
            // Afișează DOAR mesajele altora
            if (msg->pid != current_user.pid) {
                print_message(msg);
            }
            last_seen++;
        }
        unlock_file();
        usleep(200000);
    }
}

void send_messages() {
    char buffer[MSG_SIZE];

    while (1) {
        // Afișează promptul ÎNAINTE de a citi inputul (singurul loc unde este necesar)
        printf("\033[1;32m[%s]\033[0m> ", current_user.username);
        fflush(stdout);

        if (fgets(buffer, sizeof(buffer), stdin)) {
            // Comanda /users
            if (strcmp(buffer, "/users\n") == 0) {
                lock_file();
                printf("\n\033[1;36m--- Utilizatori conectati (%d) ---\033[0m\n", data->num_users);
                for (int i = 0; i < data->num_users; i++) {
                    printf("%d. %s (PID: \033[1;31m%d\033[0m) %s\n",
                          i+1, data->users[i].username, data->users[i].pid,
                          data->users[i].pid == current_user.pid ? "(tu)" : "");
                }
                printf("\033[1;36m----------------------------\033[0m\n");
                unlock_file();
                continue;  // Nu mai afișa promptul aici!
            }

            // Comanda /disconnect_all
            if (strcmp(buffer, "/disconnect_all\n") == 0) {
                disconnect_all_users();
                continue;
            }

            // Comanda /disconnect PID
            if (strncmp(buffer, "/disconnect ", 12) == 0) {
                pid_t pid = atoi(buffer + 12);
                disconnect_user_by_pid(pid);
                continue;
            }

            // Comanda /history
            if (strcmp(buffer, "/history\n") == 0) {
                lock_file();
                printf("\n\033[1;35m--- Istoric complet (%d mesaje) ---\033[0m\n", data->num_messages);
                for (int i = 0; i < data->num_messages; i++) {
                    Message* msg = &data->messages[i % MAX_MESSAGES];
                    if (msg->pid == current_user.pid) {
                        printf("[%s] \033[1;32mTu\033[0m: %s",
                              format_time(msg->timestamp), msg->text);
                    } else {
                        print_message(msg);
                    }
                }
                printf("\033[1;35m----------------------------\033[0m\n");
                unlock_file();
                continue;
            }

            // Comanda /search
            if (strncmp(buffer, "/search ", 8) == 0) {
                char* keyword = buffer + 8;
                keyword[strcspn(keyword, "\n")] = 0;

                lock_file();
                printf("\n\033[1;33m--- Căutare pentru \"%s\" ---\033[0m\n", keyword);
                for (int i = 0; i < data->num_messages; i++) {
                    if (strstr(data->messages[i % MAX_MESSAGES].text, keyword) != NULL) {
                        Message* msg = &data->messages[i % MAX_MESSAGES];
                        if (msg->pid == current_user.pid) {
                            printf("[%s] \033[1;32mTu\033[0m: %s",
                                  format_time(msg->timestamp), msg->text);
                        } else {
                            print_message(msg);
                        }
                    }
                }
                printf("\033[1;33m----------------------------\033[0m\n");
                unlock_file();
                continue;
            }

            // Trimite mesaj normal
            lock_file();
            if (data->num_messages < MAX_MESSAGES) {
                Message* msg = &data->messages[data->num_messages++];
                strncpy(msg->text, buffer, MSG_SIZE-1);
                msg->text[MSG_SIZE-1] = '\0';
                msg->pid = current_user.pid;
                msg->uid = current_user.uid;
                msg->timestamp = time(NULL);
            }
            unlock_file();
        }
    }
}

void cleanup() {
    disconnect_user();
    if (data) munmap(data, sizeof(SharedData));
    if (fd != -1) close(fd);
}

void handle_exit(int sig) {
    cleanup();
    exit(0);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Utilizare: %s <fisier_chat>\n", argv[0]);
        exit(1);
    }

    filename = argv[1];
    fd = open(filename, O_RDWR | O_CREAT, 0666);
    if (fd == -1) {
        perror("open failed");
        exit(1);
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        perror("fstat failed");
        close(fd);
        exit(1);
    }

    if (st.st_size < sizeof(SharedData)) {
        if (ftruncate(fd, sizeof(SharedData)) == -1) {
            perror("ftruncate failed");
            close(fd);
            exit(1);
        }
    }

    data = mmap(NULL, sizeof(SharedData), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (data == MAP_FAILED) {
        perror("mmap failed");
        close(fd);
        exit(1);
    }

    atexit(cleanup);
    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);

    fill_user_info(&current_user);
    connect_user();

    pid_t child_pid = fork();
    if (child_pid == -1) {
        perror("fork failed");
        exit(1);
    }

    if (child_pid == 0) {
        receive_messages();
    } else {
        send_messages();
        kill(child_pid, SIGTERM);
        wait(NULL);
    }

    return 0;

}