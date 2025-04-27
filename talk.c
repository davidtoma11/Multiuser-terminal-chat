/*
 * Shared Memory Chat Application
 * Allows multiple users to communicate via shared memory
 * Features: user connections, messaging, notifications, history
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
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

// Application constants
#define MAX_USERS 10            // Maximum concurrent users
#define MAX_MESSAGES 100        // Maximum stored messages
#define MSG_SIZE 256            // Max message length
#define MAX_NAME_LEN 50         // Max username length
#define TIME_FORMAT "%H:%M:%S"  // Time display format

// User structure (stores connection info)
typedef struct {
    pid_t pid;                  // Process ID
    uid_t uid;                  // User ID
    char username[MAX_NAME_LEN];// Display name
} User;

// Message structure
typedef struct {
    char text[MSG_SIZE];        // Message content
    pid_t pid;                  // Sender's process ID
    uid_t uid;                  // Sender's user ID
    time_t timestamp;           // When message was sent
} Message;

// Shared memory structure
typedef struct {
    int num_users;              // Current connected users
    User users[MAX_USERS];      // User list
    int num_messages;           // Message count
    Message messages[MAX_MESSAGES]; // Message history
} SharedData;

// Global variables
SharedData* data = NULL;        // Pointer to shared memory
int fd = -1;                    // File descriptor for shared memory
char* filename = NULL;          // Shared memory filename
User current_user;              // Current user info
int last_seen = 0;              // Last seen message index

/* Helper function to format timestamp */
const char* format_time(time_t timestamp) {
    static char buf[20];
    strftime(buf, sizeof(buf), TIME_FORMAT, localtime(&timestamp));
    return buf;
}

/* Lock the shared memory file */
void lock_file() {
    struct flock fl = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
    if (fcntl(fd, F_SETLKW, &fl)) {
        perror("lock failed");
        exit(1);
    }
}

/* Unlock the shared memory file */
void unlock_file() {
    struct flock fl = {.l_type = F_UNLCK, .l_whence = SEEK_SET};
    if (fcntl(fd, F_SETLKW, &fl)) {
        perror("unlock failed");
    }
}

/* Initialize user information */
void fill_user_info(User* user) {
    user->pid = getpid();
    user->uid = getuid();

    // Prompt for username
    printf("Enter username (max %d chars): ", MAX_NAME_LEN-1);
    if (fgets(user->username, MAX_NAME_LEN, stdin) == NULL) {
        strcpy(user->username, "Anonymous");
    }
    user->username[strcspn(user->username, "\n")] = 0;

    // Use system username if none provided
    if (strlen(user->username) == 0) {
        struct passwd* pw = getpwuid(user->uid);
        if (pw) {
            strncpy(user->username, pw->pw_name, MAX_NAME_LEN-1);
        } else {
            strcpy(user->username, "Anonymous");
        }
    }
}

/* Send a notification message to all users */
void send_notification(const char* message) {
    lock_file();
    if (data->num_messages < MAX_MESSAGES) {
        Message* msg = &data->messages[data->num_messages++];
        snprintf(msg->text, MSG_SIZE, "--- %s ---", message);
        msg->pid = current_user.pid;
        msg->uid = current_user.uid;
        msg->timestamp = time(NULL);
    }
    unlock_file();
}

/* Connect current user to the chat */
void connect_user() {
    lock_file();

    // Check if already connected
    for (int i = 0; i < data->num_users; ++i) {
        if (data->users[i].pid == current_user.pid) {
            printf("[!] Already connected.\n");
            unlock_file();
            return;
        }
    }

    // Check if room is full
    if (data->num_users >= MAX_USERS) {
        printf("[!] Chat room is full.\n");
        unlock_file();
        exit(1);
    }

    // Add user to list
    data->users[data->num_users++] = current_user;
    printf("[*] Connected as %s (PID %d)\n", current_user.username, current_user.pid);

    unlock_file();

    // Notify others
    char notification[MSG_SIZE];
    snprintf(notification, MSG_SIZE, "%s has connected", current_user.username);
    send_notification(notification);
}

/* Disconnect user by PID (admin function) */
void disconnect_user_by_pid(pid_t pid) {
    lock_file();
    int found = 0;

    for (int i = 0; i < data->num_users; i++) {
        if (data->users[i].pid == pid) {
            kill(pid, SIGTERM);

            // Send notification
            char notification[MSG_SIZE];
            snprintf(notification, MSG_SIZE, "%s was disconnected", data->users[i].username);
            send_notification(notification);

            // Remove from user list
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
        printf("[*] User with PID %d disconnected.\n", pid);
    } else {
        printf("[!] No user with PID %d\n", pid);
    }
}

/* Disconnect all users (admin function) */
void disconnect_all_users() {
    lock_file();

    // Disconnect all except current user
    for (int i = 0; i < data->num_users; i++) {
        if (data->users[i].pid != current_user.pid) {
            kill(data->users[i].pid, SIGTERM);
        }
    }

    // Clear message history
    data->num_messages = 0;
    memset(data->messages, 0, sizeof(data->messages));

    // Keep only current user
    data->num_users = 1;
    data->users[0] = current_user;

    unlock_file();

    printf("[*] All users disconnected and history cleared.\n");
}

/* Disconnect current user */
void disconnect_user() {
    static bool disconnecting = false;
    if (disconnecting) return;
    disconnecting = true;

    bool was_connected = false;
    lock_file();
    for (int i = 0; i < data->num_users; ++i) {
        if (data->users[i].pid == current_user.pid) {
            // Send disconnect notification
            char notification[MSG_SIZE];
            snprintf(notification, MSG_SIZE, "%s has disconnected", current_user.username);
            send_notification(notification);
            was_connected = true;

            // Remove from user list
            for (int j = i; j < data->num_users - 1; ++j) {
                data->users[j] = data->users[j + 1];
            }
            data->num_users--;
            break;
        }
    }
    unlock_file();

    if (was_connected) {
        printf("[*] You disconnected.\n");

        // Cleanup if last user
        lock_file();
        if (data->num_users == 0) {
            printf("[*] Last user. Cleaning up...\n");
            unlock_file();

            if (data) {
                munmap(data, sizeof(SharedData));
                data = NULL;
            }
            if (fd != -1) {
                close(fd);
                fd = -1;
            }
            if (filename) {
                unlink(filename);
            }
        } else {
            unlock_file();
        }
    }

    disconnecting = false;
}

/* Display a message from another user */
void print_message(const Message* msg) {
    if (msg->pid == current_user.pid) return;

    // Find the sender's display name
    char display_name[MAX_NAME_LEN] = "unknown";
    for (int i = 0; i < data->num_users; i++) {
        if (data->users[i].pid == msg->pid) {
            strncpy(display_name, data->users[i].username, MAX_NAME_LEN);
            break;
        }
    }

    if (strstr(msg->text, "---") != NULL) {
        // Notification message (yellow)
        printf("\033[1;33m%s\033[0m\n", msg->text);
    } else {
        // Regular message (blue)
        printf("\033[1;34m[%s]\033[0m> %s", display_name, msg->text);
    }
    fflush(stdout);
}

/* Receive messages from other users */
void receive_messages() {
    // Show last 10 messages on connect
    lock_file();
    int start_idx = (data->num_messages > 10) ? data->num_messages - 10 : 0;
    printf("\n\033[1;35m--- Recent messages (%d) ---\033[0m\n", data->num_messages - start_idx);
    for (int i = start_idx; i < data->num_messages; i++) {
        if (data->messages[i % MAX_MESSAGES].pid != current_user.pid) {
            print_message(&data->messages[i % MAX_MESSAGES]);
        }
    }
    printf("\033[1;35m----------------------\033[0m\n\n");
    last_seen = data->num_messages;
    unlock_file();

    // Continuous message reception
    while (1) {
        lock_file();
        while (last_seen < data->num_messages) {
            Message* msg = &data->messages[last_seen % MAX_MESSAGES];
            if (msg->pid != current_user.pid) {
                print_message(msg);
                // Restore prompt after message
                printf("\033[1;32m[%s]\033[0m> ", current_user.username);
                fflush(stdout);
            }
            last_seen++;
        }
        unlock_file();
        usleep(200000); // 200ms delay to reduce CPU usage
    }
}

/* Send messages to the chat */
void send_messages() {
    char buffer[MSG_SIZE];

    while (1) {
        // Display prompt
        printf("\033[1;32m[%s]\033[0m> ", current_user.username);
        fflush(stdout);

        if (fgets(buffer, sizeof(buffer), stdin)) {
            // Handle commands
            if (strcmp(buffer, "/users\n") == 0) {
                lock_file();
                printf("\n\033[1;36m--- Connected users (%d) ---\033[0m\n", data->num_users);
                for (int i = 0; i < data->num_users; i++) {
                    printf("%d. %s (PID: \033[1;31m%d\033[0m) %s\n",
                          i+1, data->users[i].username, data->users[i].pid,
                          data->users[i].pid == current_user.pid ? "(you)" : "");
                }
                printf("\033[1;36m----------------------------\033[0m\n");
                unlock_file();
                continue;
            }

            if (strcmp(buffer, "/disconnect_all\n") == 0) {
                disconnect_all_users();
                continue;
            }

            if (strncmp(buffer, "/disconnect ", 12) == 0) {
                pid_t pid = atoi(buffer + 12);
                disconnect_user_by_pid(pid);
                continue;
            }

            if (strcmp(buffer, "/history\n") == 0) {
                lock_file();
                printf("\n\033[1;35m--- Full history (%d messages) ---\033[0m\n", data->num_messages);
                for (int i = 0; i < data->num_messages; i++) {
                    Message* msg = &data->messages[i % MAX_MESSAGES];
                    if (msg->pid == current_user.pid) {
                        printf("\033[1;32m[%s]\033[0m> %s", current_user.username, msg->text);
                    } else {
                        print_message(msg);
                    }
                }
                printf("\033[1;35m----------------------------\033[0m\n");
                unlock_file();
                continue;
            }

            if (strncmp(buffer, "/search ", 8) == 0) {
                char* keyword = buffer + 8;
                keyword[strcspn(keyword, "\n")] = 0;

                lock_file();
                printf("\n\033[1;33m--- Search for \"%s\" ---\033[0m\n", keyword);
                for (int i = 0; i < data->num_messages; i++) {
                    if (strstr(data->messages[i % MAX_MESSAGES].text, keyword) != NULL) {
                        Message* msg = &data->messages[i % MAX_MESSAGES];
                        if (msg->pid == current_user.pid) {
                            printf("\033[1;32m[%s]\033[0m> %s", current_user.username, msg->text);
                        } else {
                            print_message(msg);
                        }
                    }
                }
                printf("\033[1;33m----------------------------\033[0m\n");
                unlock_file();
                continue;
            }

            // Send regular message
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

/* Signal handler for clean exit */
void handle_exit(int sig) {
    printf("\n[*] Closing connection...\n");
    disconnect_user();
    _exit(0);
}

/* Cleanup resources */
void cleanup() {
    if (data) {
        munmap(data, sizeof(SharedData));
        data = NULL;
    }
    if (fd != -1) {
        close(fd);
        fd = -1;
    }
}

/* Main function */
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <chat_file>\n", argv[0]);
        exit(1);
    }

    // Initialize shared memory
    filename = argv[1];
    fd = open(filename, O_RDWR | O_CREAT, 0666);
    if (fd == -1) {
        perror("open failed");
        exit(1);
    }

    // Configure shared memory size
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

    // Map shared memory
    data = mmap(NULL, sizeof(SharedData), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (data == MAP_FAILED) {
        perror("mmap failed");
        close(fd);
        exit(1);
    }

    // Setup cleanup handlers
    atexit(cleanup);
    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);

    // Initialize and connect user
    fill_user_info(&current_user);
    connect_user();

    // Fork for message handling
    pid_t child_pid = fork();
    if (child_pid == -1) {
        perror("fork failed");
        exit(1);
    }

    if (child_pid == 0) {
        // Child process - handles message reception
        receive_messages();
    } else {
        // Parent process - handles message sending
        send_messages();
        kill(child_pid, SIGTERM);
        wait(NULL);
    }

    return 0;
}
