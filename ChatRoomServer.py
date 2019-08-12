# Time Stamps
from datetime import datetime as dt
import time

# Networking / Managment
import socket
import _thread as thread
from random import randrange
from uuid import uuid4

# Misc Operations
import sys
import signal
from hashlib import blake2b

# ----------= Server Constants =----------
STRING_ENCODING = 'utf-8'

# Used so the encryption can keep track of messages
MESSAGE_MARKER = '\0'

# Message Size Options
BUFFER_SIZE = 0x1000
MAX_CHAT_SIZE = 1024
MAX_CHAT_NAME = 16

# User Configurations
MAX_USERS = 64
USER_UPDATE_TIME = 0  # Blocking Makes This unnecessary

# Default Networking Options
DEFAULT_IP = ""
DEFAULT_PORT = 8081

# Computer IP
HOSTNAME = socket.gethostname()
COMPUTER_IP = socket.gethostbyname(HOSTNAME)

# Chat Room Name
SERVER_NAME = "Sam's Chat Room"

# Hashed using blake2b. Change for your own server
ADMIN_HASH = blake2b()
ADMIN_HASH.update("PleaseGiveMeAdminIReallyWantIt".encode(STRING_ENCODING))
ADMIN_PASSWORD = ADMIN_HASH.hexdigest()


# ----------= Code =----------
# Initialize Server
chat_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
chat_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
client_list = []  # List of users who are currently connected


# Prompt User for IP information
def bind_server():
    print("[SERVER] Chat Room!\n")
    while True:
        try:
            port = str(input("Enter Port (Default = {})\n>>> "
                             .format(DEFAULT_PORT)))

            if not port.isdigit():
                port = DEFAULT_PORT
            else:
                port = int(port)

            # Create Server
            chat_server.bind((DEFAULT_IP, port))

            # Add extra space for detecting extra users
            chat_server.listen(MAX_USERS + 4)
            break

        except Exception as e:
            print("Error Connecting To " + str(DEFAULT_IP) + ':' + str(port))
            print(str(e) + "\n\n")


# Log information in server log
def log_server(message, header="SERVER", stream=sys.stderr):
    stream.write("[{} - {}] {}\n".format(
        header,
        dt.fromtimestamp(time.time()).strftime('%H:%M:%S'),
        message))

    stream.flush()


# Broadcast message to users on client list
def broadcast_message(message, user=None, log_in_server=True, admins_only=False, strip=True):
    if log_in_server:
        log_server(message, header="CHAT", stream=sys.stdout)
        sys.stdout.flush()

    for client in client_list:
        try:
            if client != user and (client.admin or not admins_only):
                client.send(message, strip=strip)
        except Exception as msg:
            client.disconnect()
            log_server(str(msg), header="Exception")


# Handles User and their info
class User:
    # Makes a user ID based on IP address
    def create_id(self, d_size=3):
        h = blake2b(digest_size=d_size)
        h.update(uuid4().bytes)
        return "Guest" + h.hexdigest().upper()

    # Setup User
    def __init__(self, conn, addr):
        try:
            self.open = True

            self.conn = conn
            self.ip_addr = addr
            self.name = self.create_id()

            if self.ip_addr == '127.0.0.1' or \
               self.ip_addr == '0.0.0.0':
                self.admin = True
            else:
                self.admin = False
            self._user_thread_var = None

            # Notify Server
            broadcast_message(
                "\n[INFO] User {} Has Connected! ({} / {} Users)\n"
                .format(self.name, len(client_list) + 1, MAX_USERS),
                user=self, log_in_server=False, strip=False
            )

            log_server(
                "User {} Has Connected! ({})".format(self.name, self.ip_addr)
            )

            # Welcome User
            self.send("Welcome to " + SERVER_NAME)
            self.send("Your user id is <{}>".format(self.name))
            self.send("Type '?help' for commands")
            self.send("")

            self.send("{} of {} Users Online:".format(len(client_list), MAX_USERS))

            # Go through list and
            user_num = 1
            for user in client_list:
                self.send(str(user_num) + " - " + user.name)
                user_num += 1

            self.send("")
        except Exception as msg:
            self.disconnect()
            log_server(str(msg), header="Exception")

    # Correctly Disconnect User
    def disconnect(self):
        if self.open:
            self.open = False

            if self in client_list:
                client_list.remove(self)

            try:
                self.conn.close()
            except Exception as msg:
                log_server(str(msg), header="Exception")

            # Notify Server
            broadcast_message(
                "\n[INFO] User {} Has Disconnected! ({} / {} Users)\n"
                .format(self.name, len(client_list), MAX_USERS),
                user=self, log_in_server=False, strip=False
            )

            log_server(
                "User {} Has Disconnected! ({} / {} Users)"
                .format(self.name, len(client_list), MAX_USERS)
            )

    # Start thread for checking user
    def start(self):
        self._user_thread_var = thread.start_new_thread(self._user_thread, ())

    # Thread used to check for user
    def _user_thread(self):
        try:
            while self.open:
                message = self.get_text()
                if message:
                    if len(message) < MAX_CHAT_SIZE:
                        messages = message.split('\n')
                        for line in messages:
                            if line: 
                                if line[0] == '?' or line[0] == '!':
                                    self.parse_command(line)
                                else:
                                    self.say(line)
                    else:
                        self.send("[SERVER] Message Too Long! ({} > {})"
                                .format(len(message), MAX_CHAT_SIZE))
                else:
                    self.disconnect()
                time.sleep(USER_UPDATE_TIME)
        except Exception as msg:
            log_server(str(msg), header="Exception")
            self.disconnect()
        return


    # Take command, parse and sort it
    def parse_command(self, command_text):
        # Parse Command
        command = command_text[1:].split(' ')

        self.send("")
        # Check for user commands
        if command_text[0] == '?':
            log_server("'{}' Executed '{}'"
                       .format(self.name, command_text),
                       header="CMD", stream=sys.stdout)
            self.run_user_command(command)

        # Check for admin commands
        elif command_text[0] == '!' and self.admin:
            log_server("'{}' Executed '{}'"
                       .format(self.name, command_text),
                       header="ADMIN-CMD", stream=sys.stderr)
            self.run_admin_command(command)
        self.send("")

    # Run user commands
    def run_user_command(self, command):
        if command[0].lower() == "help":
            self.send_cmd("?help - List Commands\n")
            self.send_cmd("- Fun Commands")
            self.send_cmd("?coin - Flips a Coin")
            self.send_cmd("?8ball [message] - Asks Magic 8 Ball")
            self.send_cmd("?roulette - Play Russian Roulette")
            self.send_cmd("?f - Pay Respect\n")
            self.send_cmd("- Useful Commands")
            self.send_cmd("?list - List Users Online")
            self.send_cmd("?leave - Disconnect From Server")
            self.send_cmd("?clear - Clears Screen With New Line")
            self.send_cmd("?name <new name> - Set Chat Name")
            self.send_cmd("?pm <name> <message> - Message Only 1 Person")

        elif command[0].lower() == "coin":
            self.say("?" + ' '.join(command))
            broadcast_message("[Coin] " + ["Heads", "Tails"][randrange(2)])
            broadcast_message("", self, strip=False, log_in_server=False)

        elif command[0].lower() == "8ball":
            self.say("?" + ' '.join(command))
            answers = ["Yes", "No", "Probably", "Probably Not", "Maybe", "Ask Again"]
            broadcast_message("[8Ball] " + answers[randrange(6)])
            broadcast_message("", self, strip=False, log_in_server=False)

        elif command[0].lower() == "roulette":
            self.say("?" + ' '.join(command))
            state = randrange(6)
            if state == 0:
                broadcast_message("[Roulette] {}!"
                                  .format(["CRACK", "Ka-BOOM", "BOOM", "POW", "BANG"][randrange(5)]))
                broadcast_message("", self, strip=False, log_in_server=False)
                self.disconnect()
            else:
                broadcast_message("[Roulette] Click...")
                broadcast_message("", self, strip=False, log_in_server=False)

        elif command[0].lower() == "f":
            self.say("Can we get an F in the chat")
            broadcast_message("[ChatBot{}] F".format(randrange(100)))
            broadcast_message("", self, strip=False, log_in_server=False)

        elif command[0].lower() == "list":
            self.send_cmd("{} of {} Users Online:"
                          .format(len(client_list), MAX_USERS))

            # Go through list and
            user_num = 1
            for user in client_list:
                self.send_cmd(str(user_num) + " - " + user.name)
                user_num += 1

        elif command[0].lower() == "leave":
            self.disconnect()

        elif command[0].lower() == "clear":
            self.send_cmd("Clearing Screen..." + "\n"*0x100)
            self.send_cmd("Screen Cleared")

        elif command[0].lower() == "name":
            # Check for valid input
            if len(command) > 1:
                # Take input and sanitize it
                new_name = "_".join(command[1:]).rstrip()
                self.change_name(new_name)
            else:
                self.send_cmd("Current Username: " + self.name)

        elif command[0].lower() == "pm":
            # Check for valid input
            if len(command) > 2:
                for user in client_list:
                    # Check for user input
                    if user.name.lower() == command[1].lower():
                        # Send pm message
                        user.send("<{} pm'd you> {}".format(
                            self.name, " ".join(command[2:])
                        ))
                        self.send("<you pm'd {}> {}".format(
                            user.name, " ".join(command[2:])
                        ))
                        return
                self.send_cmd("User '{}' Not Found!".format(command[1]))
            else:
                self.send_cmd("Invalid Input!")

        # Check if admin password is correct
        elif command[0].lower() == "admin" and len(command) > 1:
            h = blake2b()
            h.update(command[1].encode('utf-8'))
            if h.hexdigest() == ADMIN_PASSWORD and not self.admin:
                self.admin = True
                self.send_cmd("You Are Now Admin! Type '!help' for a list of Admin commands.")
                broadcast_message(
                    "[INFO] User {} is now Admin".format(self.name),
                    user=self, admins_only=True
                )
                broadcast_message("", user=self, admins_only=True, log_in_server=False)
            else:
                # Disguise output
                self.send_cmd("Unknown Command '?{}'".format(command[0]))
        else:
            self.send_cmd("Unknown Command '?{}'".format(command[0]))

    # Run admin commands
    def run_admin_command(self, command):
        if command[0].lower() == "help":
            self.send_cmd("!help - List Commands")
            self.send_cmd("!list - List Admins")
            self.send_cmd("!kick <user name> - Kick User")
            self.send_cmd("!rename <name> <new name> - Rename User Name")

        elif command[0].lower() == "list":
            self.send_cmd("Admins Online:".format())
            user_num = 1
            for user in client_list:
                if user.admin:  # Print out username if admin
                    self.send_cmd(str(user_num) + " - " + user.name)
                    user_num += 1

        elif command[0].lower() == "kick":
            # Check for valid input
            if len(command) > 1:
                for user in client_list:
                    # Check if user equals input
                    if user.name.lower() == '_'.join(command[1:]).lower():
                        if user.admin:
                            self.send_cmd("You can not kick other admins!")
                        else:
                            if len(command) > 2:
                                user.disconnect()
                            else:
                                user.disconnect()

                            self.send_cmd("User '{}' Kicked".format(user.name))
                        return
                self.send_cmd("User '{}' Not Found!".format(command[1]))
            else:
                self.send_cmd("Invalid Input!")

        elif command[0].lower() == "rename":
            # Check for valid input
            if len(command) > 2:
                for user in client_list:
                    # Check if user equals input
                    if user.name.lower() == command[1].lower():
                        user.change_name("_".join(command[2:]))
                        return
                self.send_cmd("User '{}' Not Found!".format(command[1]))
            else:
                self.send_cmd("Invalid Input!")

        else:
            self.send_cmd("Unknown Command '!{}'".format(command[0]))

    # Change name of user and log it
    def change_name(self, new_name):
        # Remove Spaces
        new_name.replace(' ', '_')

        # Make name is good
        rebuild = ""
        for i in new_name:
            if i.isalpha() or i.isdigit() or i == '_':
                rebuild += i
        new_name = rebuild

        # Check for empty name
        if len(new_name) <= 0:
            self.send_cmd("You Have To Have A Username")
            return

        # Max the length of names
        if len(new_name) > MAX_CHAT_NAME:
            new_name = new_name[0:MAX_CHAT_NAME]

        # Check for similar name
        for user in client_list:
            if user.name.lower() == new_name.lower():
                self.send_cmd("Another User Has That Name")
                return

        # Prevent Confusing Names
        if 'you' == new_name.lower():
            self.send_cmd("You can not set your name to 'You'")
            return

        # Broadcast Update to user
        self.send_cmd("Name Changed To '{}'!".format(new_name))

        # Broadcast Update to Servers
        broadcast_message(
            "\n[INFO] '{}' Changed Their Name To '{}'\n"
            .format(self.name, new_name),
            user=self, log_in_server=False, strip=False
        )

        # Update Name
        self.name = new_name

    # Get text from user
    def get_text(self):
        if self.open:
            try:
                message = self.conn.recv(BUFFER_SIZE).decode(STRING_ENCODING)
                return message.strip()
            except Exception as msg:
                self.disconnect()
                log_server(str(msg), header="Exception")
        else:
            return None

    # Send user text
    def send(self, message, strip=True):

        # Remove White Space
        if strip:
            message = message.strip()

        # Check Size of Message
        if len(message.encode(STRING_ENCODING)) < BUFFER_SIZE and self.open:
            try:
                # Add Newline to String
                message = message + '\n'

                # Send Data
                self.conn.send(message.encode(STRING_ENCODING))
            except Exception as msg:
                self.disconnect()
                log_server(str(msg), header="Exception")

    # Send user command text without sanitizing
    def send_cmd(self, message):
        self.send("[CMD] " + message, strip=False)

    # Broadcast message as this user
    def say(self, message):
        # Sanatize Message
        message.strip()

        # Check Size of Message
        if len(message) < MAX_CHAT_SIZE and self.open:
            broadcast_message(self.name + "> " + message, user=self)
            self.send("You> " + message.strip())
        else:
            self.send(
                "[WARNING] Message Too Long ({} > {})"
                .format(len(message.encode(STRING_ENCODING)), MAX_CHAT_SIZE)
            )


# Handle closing of server
def close_server(signal, frame):
    # Log Closing of Server
    log_server("Closing Server...")
    broadcast_message("Server Has Closed!", log_in_server=False)

    # Wait to disconnect users
    for client in client_list:
        client.disconnect()

    # Close Socket
    chat_server.close()

    # Exit program
    exit(0)


# Loop used to search for incoming users and connect them
def listen_to_clients():
    bind_server()
    sys.stderr.write('\n')
    sys.stderr.flush()
    log_server("Created Chat Room on " + COMPUTER_IP +
               ':' + str(chat_server.getsockname()[1]))

    # Constantly check for new users
    while True:
        try:  # Accept new users
            conn, addr = chat_server.accept()
        except Exception as msg:
            log_server(str(msg), header="Exception")
            return

        # Check for user max limit
        if len(client_list) < MAX_USERS:
            # Add user to client list
            NewUser = User(conn, addr[0])
            client_list.append(NewUser)

            # Start User Thread
            client_list[len(client_list)-1].start()

        else:
            # Reject Connection
            log_server("IP Address " + addr[0] + " Could Not Connect! Room Full!")
            conn.send("Could Not Connect! Room Full!".encode(STRING_ENCODING))
            conn.close()


# Set escape codes to close server
signal.signal(signal.SIGINT, close_server)
listen_to_clients()

