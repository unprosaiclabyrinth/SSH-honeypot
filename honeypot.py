#
# honeypot.py
#
# Implement a honeypot server running an SSH server, which detects
# a brute force attack, communicates with the attacker's SSH client
# and provides it with shell access to a file system with the ability
# to execute a few basic commands
#
# Inline arguments:-
# -p: Argument of the port the SSH server will bind to.
#
# Homework 5
# Course: CS 468, Fall 2023, UIC
# Author: Himanshu Dongre
#
import paramiko
import socket
from fs.memoryfs import MemoryFS
from fs.errors import ResourceNotFound
from sys import exit
import argparse

# Read in permissible usernames from file
users = {}
with open("usernames.txt", "r") as usernames:
    for username in usernames:
        users[username.strip()] = 0

# Initialize a file system for all the users  
userfs = {}
for user in users:
    userfs[user] = MemoryFS()

# Populate by default
# for fs in userfs.values():
#     with fs.open("a.txt", "w") as f1:
#         f1.write("AAAAAAaaaaa\n" * 5)
#     with fs.open("b.txt", "w") as f2:
#         f2.write("BBBBBBbbbbb\n" * 5)   

banner = "CS468 SSH Honeypot server waiting for clients..."


# Define the SSH server handler class
class Honeypot468SSHServer(paramiko.ServerInterface):
    def get_allowed_auths(self, username):
        return "none"
    
    def check_auth_none(self, username):
        if username in users:
            users[username] += 1
            return paramiko.AUTH_SUCCESSFUL if users[username] > 5 else paramiko.AUTH_FAILED
            return paramiko.AUTH_SUCCESSFUL
        else:
            return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, key):
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, channelID):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, c, t, w, h, p, ph, m):
        return True

    def get_banner(self):
        return ("+--------------------------+\n| Login @ CS468 SSH server |\n+--------------------------+\n\n", "EN")

    def check_channel_exec_request(self, channel, command):
        return True


def main():
    # Parse command-line arguments for port
    argparser = argparse.ArgumentParser(description="CS468 honeypot SSH server")
    argparser.add_argument("-p", help="Port the SSH server will bind to", required=True, type=int)
    args = argparser.parse_args()

    # Create an SSH server
    host_key = paramiko.RSAKey(filename="id_rsa")
    server_sock = prepare_socket("localhost", args.p)
    print(banner)

    while True:
        try:
            client_sock, client_addr = server_sock.accept() # Accept TCP connection
        except KeyboardInterrupt:
            exit(0)

        ssh_server = paramiko.Transport(client_sock)
        ssh_server.add_server_key(host_key)
        ssh_server.start_server(server=Honeypot468SSHServer())
        try:
            channel = ssh_server.accept() # Accept SSH connection
        except KeyboardInterrupt:
            exit(0)
        if channel:
            channel.settimeout(60)
            # Initialize session information
            username = paramiko.transport.Transport.get_username(ssh_server)
            shell_prompt = f"{username}@honeypot:/$ "
            cfs = userfs[username]

            print(f"\n> Hello to {username}")

            # Shell loop
            logout = False
            while not logout:
                channel.send(shell_prompt)
                command = ""
                # Command loop
                while True:
                    try:
                        character = channel.recv(1).decode("utf-8")
                    except KeyboardInterrupt:
                        exit(0)
                    channel.send(character)
                    if character == "\r":
                        channel.send("\n")
                        print(command)
                        handle_command(command, cfs, channel)
                        break
                    elif character == "\x7f" or character == "\b":
                        command = f"{command[:-1]} "
                        channel.send(f"\r{shell_prompt}{command}")
                        command = command[:-1]
                        channel.send(f"\r{shell_prompt}{command}")
                    elif character == "\x04":
                        channel.send("logout\r\n")
                        client_sock.close()
                        logout = True
                        break
                    elif character in [chr(i) for i in range(ord(" "), ord("~") + 1)]:
                        command += character


def handle_command(command, cfs, channel):
    """
    Handle the different shell commands entered by the client.
    """
    params = command.split(" ")
    match params[0]:
        case "ls":
            for f in cfs.listdir("/"):
                print(f)
                channel.send(f"{f}\r\n")

        case "echo":
            args = command.lstrip("echo").strip().split(" > ")
            if args:
                content = args[0].strip()
                if args[1:]:
                    for arg in args[1:]:
                        with cfs.open(arg.strip(), "w") as f:
                            f.write(content)
                else:
                    channel.send(f"{content}\r\n")

        case "cat":
            newparams = match_star_glob(cfs, params[1:], channel)
            if newparams is None: return
            for param in newparams:
                try:
                    with cfs.open(param.strip(), "r") as f:
                        for row in f:
                            row = row.rstrip("\n")
                            channel.send(f"{row}\r\n")
                except ResourceNotFound:
                    channel.send(f"file {param} not found\r\n")
                    return

        case "cp":
            if len(params[1:]) < 2:
                channel.send("too few arguments\r\n")
                return
            elif len(params[1:]) > 2:
                channel.send("too many arguments\r\n")
                return
            srcparams = match_star_glob(cfs, [params[1]], channel)
            if srcparams is None: return
            content = ""
            for src in srcparams:
                try:
                    with cfs.open(src, "r") as s:
                        content += s.read()
                except ResourceNotFound:
                    channel.send(f"file {src} not found\r\n")
                    return
            destparams = match_star_glob(cfs, [params[2]], channel)
            if destparams is None: return
            for dest in destparams:
                with cfs.open(dest, "w") as d:
                    d.write(content)
        
        case _:
            channel.send(f"command {params[0]} not found\r\n")
            

def prepare_socket(host, port):
    """
    Bind the socket to given host and port.
    Let it listen for TCP connections.
    """
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    print(f"TCP socket on port {port}.")
    sock.listen(100)
    return sock


def match_star_glob(cfs, params, channel):
    """
    Modify given list of files to include those that match
    star glob pattern. In other words, "expand" starb glob.
    """
    newparams = []
    for param in params:
        if "*" in param:
            matches = []
            try:
                prefix, suffix = param.split("*")
            except ValueError:
                channel.send("at most 1 star glob permitted\r\n")
                return None
            for f in cfs.listdir("/"):
                if f.startswith(prefix) and f.endswith(suffix):
                    matches.append(f)
            if not matches:
                channel.send("unknown file extension\r\n")
                return None
            newparams.extend(matches)
        else:
            newparams.append(param)
    return newparams


if __name__ == "__main__":
    main()
