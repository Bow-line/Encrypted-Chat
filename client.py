import base64
from tqdm import tqdm
import os
import socket
import threading
from tkinter import *
from tkinter import font
from tkinter import ttk
from tkinter import filedialog

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

private_key, public_key = None, None
other_public_key = None

SEPARATOR = "<SEPARATOR>"


# def get_other_public_key():
#     global other_public_key
#     other_public_key = client.recv(1024)
#     other_public_key = serialization.load_pem_public_key(other_public_key)


def generate_keys():
    # Generate a 2048-bit RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Extract the public key from the private key and serialize it to PEM format
    public_key = private_key.public_key()

    # Convert the private and public keys to bytes
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Deserialize the keys from bytes
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None
    )

    public_key = serialization.load_pem_public_key(public_key_bytes)

    return private_key, public_key


PORT = 5000
SERVER = "153.19.213.190"
ADDRESS = (SERVER, PORT)
FORMAT = "utf-8"

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDRESS)


class GUI:
    def __init__(self):

        self.Window = Tk()
        self.Window.withdraw()

        self.login = Toplevel()
        self.login.title("Login")
        self.login.resizable(width=False, height=False)
        self.login.configure(width=400, height=300)

        self.pls = Label(self.login, text="Please login to continue",
                         justify=CENTER, font="Helvetica 14 bold")
        self.pls.place(relheight=0.15, relx=0.2, rely=0.07)

        self.labelName = Label(self.login, text="Name: ", font="Helvetica 12")
        self.labelName.place(relheight=0.2, relx=0.1, rely=0.2)

        self.entryName = Entry(self.login, font="Helvetica 14")
        self.entryName.place(relwidth=0.4, relheight=0.12, relx=0.35, rely=0.2)
        self.entryName.focus()

        self.go = Button(self.login, text="CONTINUE", font="Helvetica 14 bold",
                         command=lambda: self.goAhead(self.entryName.get()))
        self.go.place(relx=0.4, rely=0.55)
        self.Window.mainloop()

    def goAhead(self, name):
        self.login.destroy()
        self.layout(name)
        rcv = threading.Thread(target=self.receive)
        rcv.start()

    def layout(self, name):

        self.name = name

        self.Window.deiconify()
        self.Window.title("CHATROOM")
        self.Window.resizable(width=False, height=False)
        self.Window.configure(width=470, height=650, bg="#17202A")
        self.labelHead = Label(self.Window, bg="#17202A", fg="#EAECEE",
                               text=self.name, font="Helvetica 13 bold", pady=5)

        self.labelHead.place(relwidth=1)
        self.line = Label(self.Window, width=450, bg="#ABB2B9")

        self.line.place(relwidth=1, rely=0.07, relheight=0.012)

        self.textCons = Text(self.Window, width=20, height=2, bg="#17202A",
                             fg="#EAECEE", font="Helvetica 14", padx=5, pady=5)

        self.textCons.place(relheight=0.745, relwidth=1, rely=0.08)

        self.labelBottom = Label(self.Window, bg="#ABB2B9", height=80)

        self.labelBottom.place(relwidth=1, rely=0.825)

        self.entryMsg = Entry(self.labelBottom, bg="#2C3E50",
                              fg="#EAECEE", font="Helvetica 13")
        self.entryMsg.place(relwidth=0.74, relheight=0.06,
                            rely=0.008, relx=0.011)
        self.entryMsg.focus()

        self.buttonMsg = Button(self.labelBottom, text="Send", font="Helvetica 10 bold",
                                width=20, bg="#ABB2B9", command=lambda: self.sendMsgButton(self.entryMsg.get()))
        self.buttonMsg.place(relx=0.77, rely=0.008,
                             relheight=0.03, relwidth=0.22)
        self.buttonFile = Button(self.labelBottom, text="File", font="Helvetica 10 bold",
                                 width=20, bg="#ABB2B9", command=lambda: self.sendFileButton())
        self.buttonFile.place(relx=0.77, rely=0.04,
                              relheight=0.03, relwidth=0.22)
        self.buttonPublicKey = Button(self.labelBottom, text="Public Key", font="Helvetica 10 bold",
                                      width=20, bg="#ABB2B9", command=lambda: self.sendPublicKeyButton())
        self.buttonPublicKey.place(relx=0.77, rely=0.07,
                                   relheight=0.03, relwidth=0.22)
        self.textCons.config(cursor="arrow")

        scrollbar = Scrollbar(self.textCons)
        scrollbar.place(relheight=1, relx=0.974)
        scrollbar.config(command=self.textCons.yview)

        self.textCons.config(state=DISABLED)

    def sendFileButton(self):
        self.textCons.config(state=DISABLED)
        filename = filedialog.askopenfilename(initialdir=os.getcwd(
        ), title="Select file", filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
        filesize = os.path.getsize(filename)
        # print("Filesize: ", filesize)
        # print("Filename: ", filename)
        snd = threading.Thread(target=self.sendFile(filename, filesize))
        snd.start()

    def sendMsgButton(self, msg):
        self.textCons.config(state=DISABLED)
        self.msg = msg
        self.entryMsg.delete(0, END)
        snd = threading.Thread(target=self.sendMessage)
        snd.start()

    def sendPublicKeyButton(self):
        self.textCons.config(state=DISABLED)
        snd = threading.Thread(
            target=self.sendPublicKey(public_key=public_key))
        snd.start()

    def receive(self):
        while True:
            try:
                message = client.recv(1024).decode(FORMAT)
                if "PUBLIC KEY" in message:
                    # load public key from message
                    print("Message: ", message)
                    pubkey = message
                    b64data = '\n'.join(pubkey.splitlines()[1:-1])
                    derdata = base64.b64decode(b64data)
                    other_public_key = serialization.load_der_public_key(
                        derdata, default_backend())
                elif message == 'NAME':
                    client.send(self.name.encode(FORMAT))
                else:
                    # check if message is separated by a SEPARATOR
                    if SEPARATOR in message:
                        filename, filesize = message.split(SEPARATOR)
                        filename = os.path.basename(filename)
                        filesize = int(filesize)
                        progress = tqdm(range(
                            filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024, mininterval=0)
                        with open(filename, "wb") as f:
                            total_bytes_received = 0
                            while True:
                                bytes_read = client.recv(1024)
                                if not bytes_read:
                                    break
                                f.write(bytes_read)
                                progress.update(len(bytes_read))
                                total_bytes_received += len(bytes_read)
                                if total_bytes_received == filesize:
                                    break
                    else:
                        self.textCons.config(state=NORMAL)
                        self.textCons.insert(END, message+"\n\n")
                        self.textCons.config(state=DISABLED)
                        self.textCons.see(END)
            except:
                print("An error occurred!")
                client.close()
                break

    def sendMessage(self):
        self.textCons.config(state=DISABLED)
        while True:
            message = (f"{self.name}: {self.msg}")
            client.send(message.encode(FORMAT))
            break

    def sendFile(self, filename, filesize):
        self.textCons.config(state=DISABLED)
        client.send(f"{filename}{SEPARATOR}{filesize}".encode(FORMAT))
        progress = tqdm(range(filesize), f"Sending {filename}",
                        unit="B", unit_scale=True, unit_divisor=1024)
        with open(filename, "rb") as f:
            while True:
                bytes_read = f.read(1024)
                if not bytes_read:
                    break
                client.sendall(bytes_read)
                progress.update(len(bytes_read))

    def sendPublicKey(self, public_key):
        # convert public key to ascii

        public_key_ascii = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        self.textCons.config(state=DISABLED)
        while True:
            client.send((public_key_ascii).encode(FORMAT))
            break


private_key, public_key = generate_keys()
# public_key = public_key.public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo
# ).decode("utf-8")
print("Private key: ", private_key)
print("Public key: ", public_key)

g = GUI()
