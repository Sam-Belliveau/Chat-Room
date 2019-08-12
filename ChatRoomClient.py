import socket
import tkinter as tk
import time
import _thread as thread
from hashlib import blake2b

# Server Constants
STRING_ENCODING = 'utf-8'

# Used so the encryption can keep track of messages
MESSAGE_MARKER = '\0'

BUFFER_SIZE = 0x1000
UPDATE_TIME = 0  # Blocking makes this unnecessary

DEFAULT_IP = "127.0.0.1"
DEFAULT_PORT = 8081

CONNECTION_TIMEOUT = 8

USER_FONT = ("Courier", 16)
BORDER_SIZE = 8

# Initialize Server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_connected = False


# Connect to server ip
def connect_to_server():
    global server_connected
    global server

    status_text.set("Status: Connecting")
    status_box.update()
    send_leave()

    clear_chat_log()
    clear_chat_log()

    ip = str(ip_box.get('1.0', 'end').strip())
    port = int(port_box.get('1.0', 'end').strip())

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the server
        server.settimeout(CONNECTION_TIMEOUT)
        server.connect((ip, port))
        server.settimeout(None)

        # Good Connection
        server_connected = True
        status_text.set("Status: Connected")

    except Exception as e:
        say_chat_log("Could not connect to " + str(ip) + ":" + str(port) + "!")
        say_chat_log("Exception: " + str(e))
        status_text.set("Status: Failed to Connect")


# Send Leave Command
def send_leave():
    send_to_server("?leave")


# Leave Server
def leave_server():
    global server_connected
    global server

    server_connected = False

    try:  # Catch harmless server errors
        server.close()
    except Exception as msg:
        print("Exception: " + str(msg))

    clear_chat_log()
    say_chat_log("You Left The Server!")
    status_text.set("Status: Disconnected")


# Puts Text In Chat Log
def say_chat_log(message, header="[CLIENT] ", end='\n'):
    chat_log.config(state=tk.NORMAL)
    chat_log.insert(tk.END, header + message + end)
    chat_log.update()
    chat_log.config(state=tk.DISABLED)


# Clears Chat Log
def clear_chat_log():
    chat_log.config(state=tk.NORMAL)
    chat_log.delete('1.0', 'end')
    chat_log.update()
    chat_log.config(state=tk.DISABLED)


# Send text to server encrypted
def send_to_server(message):
    if server_connected:
        try:
            # Send Data
            server.send(message.strip().encode(STRING_ENCODING))
        except Exception as msg:
            leave_server()
            print("Exception: " + str(msg))
            return ""


# Get text from server decrypted
def get_from_server():
    if server_connected:
        try:
            message = server.recv(BUFFER_SIZE)
            if message:
                message = message.decode(STRING_ENCODING)
                return message
            else:
                leave_server()
                return ""
        except Exception as msg:
            leave_server()
            print("Exception: " + str(msg))
            return ""


# Check for text from the server
def chat_update(text_box, update_time):
    global server_connected

    while True:
        if server_connected:
            message = get_from_server()
            say_chat_log(message, header='', end='')
            text_box.see(tk.END)

        time.sleep(update_time)


# Send what is in entry bar when enter is pressed
def send_message(event):
    global server_connected
    if server_connected:
        # Get text from bar
        message = str(type_bar.get("1.0", "end-1c")).strip()

        # Clear Bar
        type_bar.config(state=tk.NORMAL)
        type_bar.delete('1.0', 'end')
        type_bar.update()

        # Send Message
        send_to_server(message)


# Window
window = tk.Tk()
window.title("Chat Room Client")
window.geometry("1024x768")

# Server Frame
server_frame = tk.Frame(window, borderwidth=2)

status_text = tk.StringVar()
status_box = tk.Label(server_frame, width=24, height=1, textvariable=status_text, borderwidth=BORDER_SIZE/2.0)
status_box.config(font=USER_FONT)
status_text.set("Status: Disconnected")

ip_box = tk.Text(server_frame, width=16, height=1, borderwidth=BORDER_SIZE/2.0)
ip_box.config(font=USER_FONT)
ip_box.insert(tk.END, "127.0.0.1")

port_box = tk.Text(server_frame, width=8, height=1, borderwidth=BORDER_SIZE/2.0)
port_box.config(font=USER_FONT)
port_box.insert(tk.END, "8081")

connect_button = tk.Button(server_frame, text="Connect", height=1, borderwidth=BORDER_SIZE/2.0, command=connect_to_server)
connect_button.config(font=USER_FONT)

leave_button = tk.Button(server_frame, text="Leave", height=1, borderwidth=BORDER_SIZE/2.0, command=send_leave)
leave_button.config(font=USER_FONT)

# Pack Buttons
status_box.pack(side=tk.TOP, fill=tk.X, expand=0, padx=2, pady=2)
port_box.pack(side=tk.RIGHT, expand=0, padx=2, pady=2)
ip_box.pack(side=tk.RIGHT, expand=0, padx=2, pady=2)
connect_button.pack(side=tk.RIGHT, fill=tk.X, expand=1, padx=2, pady=2)
leave_button.pack(side=tk.LEFT, expand=0, padx=2, pady=2)
server_frame.pack(side=tk.TOP, fill=tk.X, expand=0, padx=2, pady=2)

# Message Entry
type_bar = tk.Text(window, height=2, borderwidth=BORDER_SIZE)
type_bar.config(font=USER_FONT)
type_bar.insert(tk.END, "")
window.bind('<Return>', send_message)

# Chat Log
chat_log = tk.Text(window, borderwidth=BORDER_SIZE)
chat_log.config(font=USER_FONT)

# Pack Elements
server_frame.pack(side=tk.TOP, fill=tk.X)
type_bar.pack(side=tk.BOTTOM, fill=tk.X, expand=0)
chat_log.pack(side=tk.TOP, fill=tk.BOTH, expand=1)

# Check for server updates
thread.start_new_thread(chat_update, (chat_log, UPDATE_TIME))


# Function used to scroll chat on resize
def scroll_chat(event):
    chat_log.see(tk.END)


window.bind("<Configure>", scroll_chat)
window.mainloop()

# Close socket at end of file
server.close()

