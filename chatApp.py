from tkinter import Tk, Frame, Label, Button, Entry, Text, Scrollbar, WORD, BOTH, Y, END, messagebox
import socket
import threading
import datetime
import client


class ChatApp:
    def __init__(self):
        self.root = Tk()
        self.root.title("Chat App")
        self.BG_GRAY = "#ABB2B9"
        self.BG_COLOR = "#17202A"
        self.TEXT_COLOR = "#EAECEE"
        self.FONT = "Helvetica 14"
        self.FONT_BOLD = "Helvetica 13 bold"
        self.STUN_SERVER_IP = 'localhost'
        self.STUN_SERVER_PORT = 1234

        self.peer_public_key = None
        self.shared_aes_key = None
        self.client_ip = None
        self.client_port = None
        self.peer_listener_port = None
        self.is_listening = False
        
        self.private_key, self.my_public_pem = client.generate_rsa_keys()
        self.my_aes_key = client.generate_aes_key()
        
        self.tcp_listener, self.listener_port = client.start_tcp_listener(
            self.my_public_pem, self.my_aes_key, self.private_key
        )
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.my_id = client.register_client(self.client_socket, self.listener_port)
        self.build_ui()

        

    def build_ui(self):
        self.frame_id = Frame(self.root)
        self.frame_id.pack(pady=10)

        id_label = Label(self.frame_id, text="Your ID:", font=("Arial", 12), fg="black")
        id_label.pack(side="left", padx=5)

        self.id_label_value = Label(self.frame_id, text=self.my_id, font=("Arial", 12), fg="black")
        self.id_label_value.pack(side="left", padx=5)

        copy_button = Button(self.frame_id, text="Copy", command=self.copy_id_to_clipboard, bg=self.BG_GRAY, fg=self.BG_COLOR)
        copy_button.pack(side="left", padx=5)

        self.frame_connect = Frame(self.root)
        self.frame_connect.pack(pady=10)

        user_id_label = Label(self.frame_connect, text="User ID:", font=("Arial", 12), fg=self.TEXT_COLOR, bg=self.BG_COLOR)
        user_id_label.pack(side="left", padx=5)

        self.user_id_entry = Entry(self.frame_connect, font=("Arial", 12), bg="white", fg="black")
        self.user_id_entry.pack(side="left", padx=5)

        connect_button = Button(self.frame_connect, text="Connect", command=self.connect_function, bg=self.BG_GRAY, fg=self.BG_COLOR)
        connect_button.pack(side="left", padx=5)

        self.frame_chat = Frame(self.root, bg=self.BG_COLOR)
        self.frame_chat.pack(padx=10, pady=10)

        self.txt = Text(self.frame_chat, bg=self.BG_COLOR, fg=self.TEXT_COLOR, font=self.FONT, width=60, height=20, wrap=WORD)
        self.txt.pack(side="left", fill=BOTH, expand=True)

        scrollbar = Scrollbar(self.frame_chat, command=self.txt.yview)
        scrollbar.pack(side="right", fill=Y)
        self.txt.config(yscrollcommand=scrollbar.set)

        self.frame_input = Frame(self.root)
        self.frame_input.pack(pady=10)

        self.e = Entry(self.frame_input, bg="#2C3E50", fg=self.TEXT_COLOR, font=self.FONT, width=50)
        self.e.pack(side="left", padx=5)

        send_button = Button(self.frame_input, text="Send", font=self.FONT_BOLD, bg=self.BG_GRAY, command=self.send_message_function)
        send_button.pack(side="left")

    def copy_id_to_clipboard(self):
        user_id = self.id_label_value.cget("text")
        self.root.clipboard_clear()
        self.root.clipboard_append(user_id)
        self.root.update()
        messagebox.showinfo("Copied", f"ID '{user_id}' copied to clipboard!")

    def connect_function(self):
        client_id = self.user_id_entry.get()
        if not client_id:
            messagebox.showwarning("Error", "Please enter a User ID to connect.")
            return

        try:
            result = client.request_client(self.client_socket, client_id)
            if not result:
                messagebox.showerror("Error", "Failed to find peer.")
                return

            self.client_ip, self.client_port, self.peer_listener_port = result
            
            self.peer_public_key, self.shared_aes_key = client.temporary_tcp_key_exchange(
                self.client_ip, 
                self.peer_listener_port,
                self.my_public_pem,
                self.my_aes_key,
                self.private_key
            )

            if not self.shared_aes_key:
                messagebox.showerror("Error", "Failed to establish a secure connection.")
                return

            self.start_message_listener()
            messagebox.showinfo("Connected", f"Connected to Client {client_id}.")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect: {e}")

    def start_message_listener(self):
        if not self.is_listening:
            self.is_listening = True
            listener_thread = threading.Thread(target=self.message_listener, daemon=True)
            listener_thread.start()

    def message_listener(self):
        while self.is_listening:
            try:
                message, addr = self.client_socket.recvfrom(1024)
                
                if self.shared_aes_key:
                    try:
                        decrypted_message = client.decrypt_message(message, self.shared_aes_key)
                        message_text = decrypted_message.decode()
                    except Exception as e:
                        print(f"Decryption error: {e}")
                        message_text = message.decode()
                else:
                    message_text = message.decode()

                timestamp = datetime.datetime.now().strftime("%H:%M:%S")
                self.root.after(0, lambda: self.display_message(f"Peer ({timestamp}): {message_text}"))
                
            except Exception as e:
                print(f"Error in message listener: {e}")
                if not self.is_listening:
                    break

    def display_message(self, message):
        self.txt.insert(END, message + "\n")
        self.txt.see(END)

    def send_message_function(self):
        user_input = self.e.get()
        
        if not user_input:
            messagebox.showwarning("Error", "Message cannot be empty.")
            return

        if not self.shared_aes_key:
            messagebox.showerror("Error", "No secure connection established.")
            return

        try:
            if self.shared_aes_key:
                encrypted_message = client.encrypt_message(user_input, self.my_aes_key)
                self.client_socket.sendto(encrypted_message, (self.client_ip, int(self.client_port)))
            else:
                self.client_socket.sendto(user_input.encode(), (self.client_ip, int(self.client_port)))

            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            self.display_message(f"You ({timestamp}): {user_input}")
            self.e.delete(0, END)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {e}")

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = ChatApp()
    app.run()