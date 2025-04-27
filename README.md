# Shared Memory Chat Application
## 📝 Description
  A multi-user chat system that uses shared memory for inter-process communication (IPC). This Linux application allows multiple users to connect to the same chat room and exchange messages in real-time.

## ✨ Key Features
Shared Memory Architecture: Uses mmap for efficient IPC

- Multi-User Support: Up to 10 concurrent users
- Message History: Stores up to 100 messages
- User Notifications: Alerts for connections/disconnections
- Admin Commands: Manage users and view history
- Color-Coded Interface: Easy message differentiation

## 🛠 Installation Guide
### Prerequisites
- Linux operating system
- GCC compiler
- Basic terminal knowledge

## Step-by-Step Installation

1. Clone the repository (if available):
```bash
git clone https://github.com/username/shared-chat.git
cd shared-chat
```

2. Compile the program:
```bash
gcc talk.c -o talk
```

3. Run the application:
```bash
./talk shared_memory_file
```

Replace shared_memory_file with your preferred name for the shared memory file.

4. For multiple users:
Open new terminal windows and run the same command to connect additional users.

## 🚀 Usage Instructions
### Basic Commands
- Type your message and press Enter to send
- Special commands:
  - /users - List connected users
  - /disconnect [PID] - Disconnect specific user (admin)
  - /disconnect_all - Disconnect all users (admin)
  - /history - Show message history
  - /search [keyword] - Search messages

### Connection Process
1. When starting, you'll be prompted to enter a username
2. If no username is entered, your system username will be used
3. The chat will display recent messages upon connection

## 🧰 Technical Details
### Data Structures
- User: Contains PID, UID, and username
- Message: Contains text, sender info, and timestamp
- SharedData: Main structure holding all chat data

### Synchronization
- Uses file locking (fcntl) to prevent race conditions
- Automatic cleanup on last user disconnect
