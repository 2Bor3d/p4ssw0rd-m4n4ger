#!/usr/bin/python3.10
# -*- coding: utf-8 -*-
# compile with: pyinstaller --onefile main.py --add-data save.json:save
import json
import random
import string
from cryptography.fernet import Fernet
import hashlib
from getpass import getpass
import time
import sys
import os


def get_json(path):
    if not getattr(sys, 'frozen', False):  # if not in executable
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            with open(path, "x") as f:
                json.dump({"hash": "", "salt": "", "passwords": []}, f, indent=4)
            return get_json(path)
    else:  # if in executable
        try:
            '''
            DESCRIPTION OF NEXT LINE:
            
            basically it opens save.json
            
            getattr(sys, '_MEIPASS', os.getcwd()) 
            is a way to get the current working directory inside of the executable
            
            os.path.join() is a way to join two paths together
            "save/save.json" is the path of the save file inside of the executable
            
            BE CAREFUL WHEN CHANGING THIS LINE
            '''
            with open(os.path.join(os.path.join(getattr(sys, '_MEIPASS', os.getcwd()), "save/save.json")), "r") as f:
                return json.load(f)
        except FileNotFoundError:
            out("Corrupted executable, please reinstall the application.", 91)
            out("If the problem persists, contact the developer.", 91)
            out("Exiting...", 91)
            sys.exit()


def save_json(path, data):
    with open(path, "w") as f:  # open json file
        json.dump(data, f, ensure_ascii=False, indent=4)  # save json file


def create_salt(length=16, chars=string.ascii_letters + string.digits):
    salt = ""
    for i in range(length):  # for length of salt
        salt = salt + random.choice(chars)  # add random char to salt
    return salt


def create_root_password(root, salt=create_salt(), pepper=random.choice(string.ascii_letters + string.digits)):
    h = hashlib.sha3_512()  # create hash object
    salted_and_peppered = root + salt + pepper  # combine root and salt and pepper
    h.update(salted_and_peppered.encode())  # hash salted and peppered string
    return h.hexdigest(), salt  # return hash and salt


def authenticate(file, path="save.json", chars=string.ascii_letters + string.digits):
    while True:
        if file["hash"] == "":  # if no hash is set
            root = getpass("Set root password:")  # get root password from user
            file["hash"], file["salt"] = create_root_password(root)  # get hash and salt
            save_json(path, file)  # save json file
            out("Password created.", 92)
            return root
        else:
            root = getpass("Root password:")  # get root password from user
            for i in range(len(chars)):  # check all possible pepper chars
                h = hashlib.sha3_512()  # create hash object
                salted_and_peppered = root + file["salt"] + chars[i]  # combine root and salt and pepper
                h.update(salted_and_peppered.encode())  # hash salted and peppered string
                if h.hexdigest() == file["hash"]:  # if hash is correct
                    return root
            out("Wrong password, please try again.", 93)
            time.sleep(0.25)


def get_key(root):
    h = hashlib.sha3_224()  # create hash object
    h.update(root.encode())  # hash root string
    key = h.hexdigest()[:43] + "="  # get key from hash
    return key


def get_args(raw_args):  # get arguments from string
    if len(raw_args) == 0:
        return []
    args = []
    last_space = 0
    for i in range(len(raw_args)):
        if raw_args[i] == " ":  # if space
            args.append(raw_args[last_space:i])
            last_space = i + 1  # set last space to current space
    args.append(raw_args[last_space:])  # add last argument
    return args  # return arguments


def print_list(to_print):
    for i in range(len(to_print)):
        out(to_print[i], 94)


def out(text, color=38):
    print(f"\033[{color}m{text}\033[0m")


def print_help():
    out("---Help---", 94)
    out("generate [length] [number] - generate password", 94)
    out("add <site> <username> <password> - add password", 94)
    out("change_username <site> <username> - change username", 94)
    out("change_password <site> <password> - change password", 94)
    out("list - list all passwords", 94)
    out("delete <site> - delete password", 94)
    out("exit - exit program", 94)
    out("help - show help", 94)
    out("----------", 94)


def generate_password(length=10, number=10, chars=string.ascii_letters + string.digits + string.punctuation):
    password_list = []
    for a in range(int(number)):  # for number of password options
        password = ""
        for b in range(int(length)):  # for length of password
            password = password + random.choice(chars)  # add random char to password
        password_list.append(password)  # add password to list
    return password_list


def add_password(file, fernet, site, username, password, path="save.json"):
    for i in range(len(file["passwords"])):  # for all passwords
        if file["passwords"][i]["site"].lower() == site.lower():  # if site is found
            out("Site already exists.", 93)
            return  # if site is found, stop function

    encrypted_password = fernet.encrypt(password.encode()).decode()  # encrypt password
    file["passwords"].append({"site": site, "username": username, "password": encrypted_password})  # save password
    save_json(path, file)  # save json file
    out("Password added.", 92)


def list_passwords(file, fernet):
    out("---Passwords---", 94)
    for i in range(len(file["passwords"])):
        out(f"Site:     {file['passwords'][i]['site']}", 94)
        out(f"Username: {file['passwords'][i]['username']}", 94)
        out(f"Password: {fernet.decrypt(file['passwords'][i]['password'].encode()).decode()}", 94)
        out("---------------", 94)


def change_password(file, fernet, site, password, path="save.json"):
    for i in range(len(file["passwords"])):  # for all passwords
        if file["passwords"][i]["site"].lower() == site.lower():  # if site is found
            file["passwords"][i]["password"] = fernet.encrypt(password.encode()).decode()  # change password
            save_json(path, file)  # save json file
            out("Password changed.", 92)
            return  # if site is found, stop function
    out("Site not found.", 93)


def change_username(file, site, username, path="save.json"):
    for i in range(len(file["passwords"])):  # for all passwords
        if file["passwords"][i]["site"].lower() == site.lower():  # if site is found
            file["passwords"][i]["username"] = username  # change username
            save_json(path, file)  # save json file
            out("Username changed.", 92)
            return  # if site is found, stop function
    out("Site not found.", 93)


def delete_password(file, site, path="save.json"):
    for i in range(len(file["passwords"])):
        if file["passwords"][i]["site"].lower() == site.lower():
            file["passwords"].pop(i)
            save_json(path, file)
            out("Password deleted.", 92)
            return  # if site is found, stop function
    out("Site not found.", 93)


def arguments():
    args = sys.argv[1:]
    if "-h" in args or "--help" in args:
        print_help()
        exit()
    if "-g" in args or "--generate" in args:
        if "-g" in args:
            index = args.index("-g")
        else:
            index = args.index("--generate")
        if len(args) > index + 2 and args[index + 1].isdigit() and args[index + 2].isdigit():
            print_list(generate_password(int(args[index + 1]), int(args[index + 2])))
        else:
            out("Please enter a length and number of passwords.", 93)
    if "-e" in args or "--export" in args:
        try:
            file = open("export.json", "x")
            json.dump(get_json("save.json"), file)
        except FileExistsError:
            out("File already exists.", 31)


def main(path="save.json"):
    file = get_json(path)  # get json file
    root = authenticate(file, path)  # authenticate user
    fernet = Fernet(get_key(root).encode())  # create fernet object with key
    while True:
        i = input("\n> ")  # get input
        if i.lower() == "help":
            print_help()

        elif i[:8].lower() == "generate":
            args = get_args(i[9:])
            if len(args) == 0:
                print_list(generate_password())
            elif len(args) == 1:
                print_list(generate_password(args[0]))
            elif len(args) == 2:
                print_list(generate_password(args[0], args[1]))
            elif len(args) == 3:
                print_list(generate_password(args[0], args[1], args[2]))
            else:
                out("Usage: generate <length=10> <number=10> <chars=string.letters+string.digits+string.punctuation>",
                    93)

        elif i[:12].lower() == "add_password":
            args = get_args(i[4:])  # get arguments
            try:
                add_password(file, fernet, args[0], args[1], args[2], path)  # add password
            except IndexError:
                out("Usage: add_password <site> <username> <password>", 93)

        elif i.lower() == "list":
            list_passwords(file, fernet)

        elif i[:15].lower() == "change_password":
            args = get_args(i[16:])  # get arguments
            try:
                change_password(file, fernet, args[0], args[1], path)  # change password
            except IndexError:
                out("Usage: change_password <site> <password>", 93)

        elif i[:15].lower() == "change_username":
            args = get_args(i[16:])
            try:
                change_username(file, args[0], args[1], path)
            except IndexError:
                out("Usage: change_username <site> <username>", 93)

        elif i[:6].lower() == "delete":
            args = get_args(i[7:])
            try:
                delete_password(file, args[0], path)
            except IndexError:
                out("Usage: delete_password <site>", 93)

        elif i.lower() == "exit" or i.lower() == "quit":
            exit()

        else:
            out("Type 'help' for help.", 93)


if __name__ == "__main__":
    try:
        if sys.argv == 1:
            main()
        else:
            arguments()
    except KeyboardInterrupt:
        exit()
