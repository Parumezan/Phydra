import threading
import requests
import base64
import sys
import signal
import argparse
from alive_progress import alive_bar, config_handler
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Phydra:
    def __init__(self):
        self.verbose = False
        self.status = threading.Event()
        self.nbThreads = 1
        self.threads = []
        self.lock = threading.Lock()
        self.passFile = ""
        self.password = ""
        self.userFile = ""
        self.username = ""
        self.headers = {}
        self.pathHeaders = ""
        self.passPattern = ""
        self.verifyCert = False
        self.optStopAfterSuccess = True
        self.url = ""
        self.goodUsers = []
        self.goodPasswords = []
        self.nbRequests = 0
        self.refreshBar = 0.1
        self.version = "0.1"
        self.Phydrascii = [
        "⠄⠄⣴⣶⣤⡤⠦⣤⣀⣤⠆⠄⠄⠄⠄⠄⣈⣭⣭⣿⣶⣿⣦⣼⣆⠄⠄⠄⠄⠄⠄⠄⠄\n"
        "⠄⠄⠄⠉⠻⢿⣿⠿⣿⣿⣶⣦⠤⠄⡠⢾⣿⣿⡿⠋⠉⠉⠻⣿⣿⡛⣦⠄⠄⠄⠄⠄⠄\n"
        "⠄⠄⠄⠄⠄⠈⠄⠄⠄⠈⢿⣿⣟⠦⠄⣾⣿⣿⣷⠄⠄⠄⠄⠻⠿⢿⣿⣧⣄⠄⠄⠄⠄\n"
        "⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⣸⣿⣿⢧⠄⢻⠻⣿⣿⣷⣄⣀⠄⠢⣀⡀⠈⠙⠿⠄⠄⠄⠄\n"
        "⠄⠄⢀⠄⠄⠄⠄⠄⠄⢠⣿⣿⣿⠈⠄⠄⠡⠌⣻⣿⣿⣿⣿⣿⣿⣿⣛⣳⣤⣀⣀⠄⠄\n"
        "⠄⠄⢠⣧⣶⣥⡤⢄⠄⣸⣿⣿⠘⠄⠄⢀⣴⣿⣿⡿⠛⣿⣿⣧⠈⢿⠿⠟⠛⠻⠿⠄⠄\n"
        "⠄⣰⣿⣿⠛⠻⣿⣿⡦⢹⣿⣷⠄⠄⠄⢊⣿⣿⡏⠄⠄⢸⣿⣿⡇⠄⢀⣠⣄⣾⠄⠄⠄\n"
        "⣠⣿⠿⠛⠄⢀⣿⣿⣷⠘⢿⣿⣦⡀⠄⢸⢿⣿⣿⣄⠄⣸⣿⣿⡇⣪⣿⡿⠿⣿⣷⡄⠄\n"
        "⠙⠃⠄⠄⠄⣼⣿⡟⠌⠄⠈⠻⣿⣿⣦⣌⡇⠻⣿⣿⣷⣿⣿⣿⠐⣿⣿⡇⠄⠛⠻⢷⣄\n"
        "⠄⠄⠄⠄⠄⢻⣿⣿⣄⠄⠄⠄⠈⠻⣿⣿⣿⣷⣿⣿⣿⣿⣿⡟⠄⠫⢿⣿⡆⠄⠄⠄⠁\n"
        "⠄⠄⠄⠄⠄⠄⠻⣿⣿⣿⣿⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⡟⢀⣀⣤⣾⡿⠃⠄⠄⠄⠄\n"]

    def printAscii(self):
        for line in self.Phydrascii:
            print(line, end="")

    def openPasswordFile(self):
        file = open(self.passFile, "r", errors="ignore")
        content = file.read()
        file.close()
        return content

    # TODO : add pattern option
    def encodePassword(self, mail, password):
        authcode = mail + ":" + password
        authcode = base64.b64encode(authcode.encode("utf-8"))
        authcode = str(authcode)[2:-1]
        return authcode

    def decodePassword(self, authcode):
        authcode = base64.b64decode(authcode)
        authcode = str(authcode)[2:-1]
        return authcode

    def doRequest(self, authcode):
        # TODO : headers = self.headers
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Basic " + authcode,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/"
        }
        return requests.get(self.url, headers=headers, verify=self.verifyCert)

    def checkPassword(self, threadId, username, password):
        # TODO : if self.passPattern is not None:
        password = self.encodePassword(username, password)
        response = self.doRequest(password)
        # TODO : add pattern response option
        self.lock.acquire()
        self.nbRequests += 1
        if self.verbose: print(str(self.nbRequests) + " : " + str(threadId)
                               + " : " + str(response.status_code) + " : "
                               + username + " : " + self.decodePassword(password))
        self.lock.release()
        if self.status == False: return True
        if response.status_code == 200:
            self.lock.acquire()
            self.goodUsers.append(username)
            self.goodPasswords.append(self.decodePassword(password))
            self.lock.release()
            if self.optStopAfterSuccess: return True
        return False

    def waitThreadsEnd(self):
        for thread in self.threads:
            if thread.is_alive():
                thread.join(2)

    def threadedUser(self, threadId, users):
        for user in users:
            if self.managerPass(threadId, user): return True
        return False

    def threadedPass(self, threadId, username, passwords):
        for password in passwords:
            if (self.checkPassword(threadId, username, password)): return True
        return False

    def managerPass(self, threadId, username):
        if self.password is not None:
            if self.checkPassword(threadId, username, self.password): return True

        if self.passFile is not None:
            print("Loading passwords from " + self.passFile + "..", end="")
            passwords = self.openPasswordFile().split("\n")
            print(".done (" + str(len(passwords)) + " passwords)")
            if self.nbThreads > 1:
                print("Splitting passwords into " + str(self.nbThreads) + " threads..", end="")
                listPasswords = [passwords[i::self.nbThreads] for i in range(self.nbThreads)]
                print(".done")
                print("Starting " + str(self.nbThreads) + " threads..", end="") 
                for i in range(self.nbThreads):
                    thread = threading.Thread(target=self.threadedPass, args=(i, username, listPasswords[i]))
                    self.threads.append(thread)
                    thread.start()
                print(".done")
                with alive_bar(len(passwords), manual=True) as bar:
                    while self.status and (self.nbRequests < len(passwords)):
                        bar(self.nbRequests / len(passwords))
                    bar(self.nbRequests / len(passwords))
            else:
                with alive_bar(len(passwords)) as bar:
                    for password in passwords:
                        if self.checkPassword(threadId, username, password): return True
                        bar()
        return False

    def managerUser(self):
        if self.username is not None:
            if self.managerPass(0, self.username): return True
        
        if self.userFile is not None:
            print("Loading users from " + self.userFile + "..", end="")
            users = self.openPasswordFile(self.userFile).split("\n")
            print(".done (" + str(len(users)) + " users)")

            if self.passFile is None and self.password is not None:
                if self.nbThreads > 1:
                    print("Splitting users into " + str(self.nbThreads) + " threads..", end="")
                    users = [users[i::self.nbThreads] for i in range(self.nbThreads)]
                    print(".done")
                    print("Starting " + str(self.nbThreads) + " threads..", end="")
                    for i in range(self.nbThreads):
                        thread = threading.Thread(target=self.threadedUser, args=(i, users[i]))
                        self.threads.append(thread)
                        thread.start()
                    print(".done")
                    with alive_bar(len(users), manual=True, refresh_secs=self.refreshBar) as bar:
                        while self.status:
                            bar(self.nbRequests / len(users))
                        bar(self.nbRequests / len(users))

            for user in users:
                print("Trying user " + user + "..", end="")
                if self.managerPass(0, user): return True
                print("..done for user " + user)
        return False

    def signal_handler(self, sig, frame):
        self.lock.acquire()
        self.status = False
        self.lock.release()
        self.waitThreadsEnd()
        self.exit()

    def settings(self):
        parser = argparse.ArgumentParser(description="Phydra is a simple python script to bruteforce HTTP basic authentification")
        parser.add_argument("-u", "--username", help="username to bruteforce")
        parser.add_argument("-U", "--user-file", help="file containing usernames to bruteforce")
        parser.add_argument("-p", "--password", help="password to bruteforce")
        parser.add_argument("-P", "--pass-file", help="file containing passwords to bruteforce")
        parser.add_argument("-t", "--threads", help="number of threads to use", type=int, default=1)
        parser.add_argument("-s", "--stop-after-success", help="stop after finding a valid password", action="store_true")
        parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
        parser.add_argument("-V", "--version", help="show version", action="store_true")
        parser.add_argument("-H", "--headers", help="add headers to the request")
        parser.add_argument("-HH", "--headers-file", help="add headers from a file to the request")
        parser.add_argument("-c", "--certificates", help="verify certificates (default: False)", action="store_false")
        parser.add_argument("-url", help="url to bruteforce")
        args = parser.parse_args()

        self.username = args.username
        self.userFile = args.user_file
        self.password = args.password
        self.passFile = args.pass_file
        self.pathHeaders = args.headers_file
        self.headers = args.headers
        self.url = args.url
        self.optStopAfterSuccess = args.stop_after_success
        self.nbThreads = args.threads
        self.verbose = args.verbose
        self.certificates = args.certificates

        if args.version:
            print("Phydra version " + self.version)
            sys.exit(0)
        if self.username is None and self.userFile is None:
            print("You must specify a username or a user file")
            sys.exit(1)
        if self.password is None and self.passFile is None:
            print("You must specify a password or a password file")
            sys.exit(1)
        if self.nbThreads < 1:
            print("You must specify a number of threads greater than 0")
            sys.exit(1)
        if self.pathHeaders is not None:
            self.headers = self.openPasswordFile(self.pathHeaders)

    def exit(self):
        if len(self.goodUsers) > 0:
            for i in range(len(self.goodUsers)):
                print("User : " + self.goodUsers[i] + " - Password : " + self.goodPasswords[i])
        else:
            print("No valid password found")
        print("Number of requests : " + str(self.nbRequests))
        print("Exiting Phydra... bye")

    def main(self):
        print("Starting Phydra...")
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        config_handler.set_global(refresh_secs=self.refreshBar, enrich_print=False)
        self.managerUser()
        self.exit()

    def start(self):
        self.printAscii()
        self.settings()
        self.main()

if __name__ == "__main__":
    Phydra().start()