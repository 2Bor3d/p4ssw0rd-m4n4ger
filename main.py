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
            
            IMPORTANT:
            BE CAREFUL WHEN CHANGING THIS LINE
            '''
            with open(os.path.join(os.path.join(getattr(sys, '_MEIPASS', os.getcwd()), "save/save.json")), "r") as f:
                return json.load(f)
        except FileNotFoundError:
            out("Corrupted executable, please reinstall the application.", 31)
            out("If the problem persists, contact the developer.", 31)
            out("Exiting...", 31)
            sys.exit()


def save_json(path, data):
    with open(path, "w") as f:  # open json file
        json.dump(data, f, ensure_ascii=False, indent=4)  # save json file


def create_salt(length=16, chars=string.ascii_letters + string.digits + string.punctuation):
    salt = ""
    for i in range(length):  # for length of salt
        salt = salt + random.choice(chars)  # add random char to salt
    return salt


def create_root_password(root, salt=create_salt(), pepper=random.choice(string.ascii_letters +
                                                                        string.digits +
                                                                        string.punctuation)):
    h = hashlib.sha3_512()  # create hash object
    salted_and_peppered = root + salt + pepper  # combine root and salt and pepper
    h.update(salted_and_peppered.encode())  # hash salted and peppered string
    return h.hexdigest(), salt  # return hash and salt


def authenticate(file, path="save.json", root="", chars=string.ascii_letters + string.digits + string.punctuation):
    while True:
        if file["hash"] == "":  # if no hash is set
            if root == "":  # if no root is set
                root = getpass("Set root password:")  # get root password from user
            file["hash"], file["salt"] = create_root_password(root)  # get hash and salt
            save_json(path, file)  # save json file
            out("Password created.", 32)
            return root
        else:
            if root == "":  # if no root is set
                root = getpass("Root password:")  # get root password from user
            for i in range(len(chars)):  # check all possible pepper chars
                h = hashlib.sha3_512()  # create hash object
                salted_and_peppered = root + file["salt"] + chars[i]  # combine root and salt and pepper
                h.update(salted_and_peppered.encode())  # hash salted and peppered string
                if h.hexdigest() == file["hash"]:  # if hash is correct
                    return root
            out("Wrong password, please try again.", 31)
            root = ""  # reset root
            time.sleep(0.25)


def out(output, color=38):
    output = str(output)  # convert output to string
    color = str(color)  # convert color to string
    print("\033[" + color + ";1m" + output + "\033[0m")  # print output with color


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
        out(to_print[i], 34)


def print_interactive_help():
    out("---Help---", 34)
    out("generate <length=10> <number=10> - generate password>", 34)
    out("add <site> <username> <password> - add password", 34)
    out("change_username <site> <username> - change username", 34)
    out("change_password <site> <password> - change password", 34)
    out("list - list all passwords", 34)
    out("delete <site> - delete password", 34)
    out("exit - exit program", 34)
    out("help - show help", 34)
    out("If you want help for the argument mode run the program with the argument -h or --help", 36)
    out("----------", 34)


def print_argument_help():
    out("---Help---", 34)
    out("-g/--generate <length> <number> - generate password", 34)
    out("-cu/--change_username <site> <username> - change username", 34)
    out("-l/--list - list all passwords", 34)
    out("-d/--delete <site> - delete password", 34)
    out("-h/--help - show help", 34)
    out("If you want help for the interactive mode, run the program without any arguments and type help.", 36)
    out("----------", 34)


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
            out("Site already exists.", 31)  # print error
            return  # if site is found, stop function

    encrypted_password = fernet.encrypt(password.encode()).decode()  # encrypt password
    file["passwords"].append({"site": site, "username": username, "password": encrypted_password})  # save password
    save_json(path, file)  # save json file
    out("Password added.", 32)


def list_passwords(file, fernet):
    out("---Passwords---", 34)
    for i in range(len(file["passwords"])):  # for all passwords
        out(f"Site:     {file['passwords'][i]['site']}", 34)  # print site
        out(f"Username: {file['passwords'][i]['username']}", 34)  # print username
        out(f"Password: {fernet.decrypt(file['passwords'][i]['password'].encode()).decode()}", 34)  # print password
        out("---------------", 34)


def change_password(file, fernet, site, password, path="save.json"):
    for i in range(len(file["passwords"])):  # for all passwords
        if file["passwords"][i]["site"].lower() == site.lower():  # if site is found
            file["passwords"][i]["password"] = fernet.encrypt(password.encode()).decode()  # change password
            save_json(path, file)  # save json file
            out("Password changed.", 32)
            return  # if site is found, stop function
    out("Site not found.", 31)


def change_username(file, site, username, path="save.json"):
    for i in range(len(file["passwords"])):  # for all passwords
        if file["passwords"][i]["site"].lower() == site.lower():  # if site is found
            file["passwords"][i]["username"] = username  # change username
            save_json(path, file)  # save json file
            out("Username changed.", 32)
            return  # if site is found, stop function
    out("Site not found.", 31)


def delete_password(file, site, path="save.json"):
    for i in range(len(file["passwords"])):
        if file["passwords"][i]["site"].lower() == site.lower():
            file["passwords"].pop(i)
            save_json(path, file)
            out("Password deleted.", 32)
            return  # if site is found, stop function
    out("Site not found.", 31)


def get_index(raw_args, option_1, option_2):
    try:
        return raw_args.index(option_1)  # try to get the index of the first option
    except ValueError:
        return raw_args.index(option_2)  # if first option not found, get index of second option


def argument_mode(raw_args, path="save.json"):
    root = ""
    root.encode()
    file = get_json(path)  # get json file
    if "-h" in raw_args or "--help" in raw_args:  # if help is called
        print_argument_help()  # print help
        sys.exit()  # exit program

    if "-p" in raw_args or "--path" in raw_args:  # if path is set
        try:
            path = raw_args[raw_args.index("-p") + 1]  # set path to path
        except ValueError:
            path = raw_args[raw_args.index("--path") + 1]  # set path to path
        file = get_json(path)  # get json file

    if "-g" in raw_args or "--generate" in raw_args:  # if generate is called
        index = get_index(raw_args, "-g", "--generate")  # get index of generate
        try:
            password_list = generate_password(raw_args[index + 1], raw_args[index + 2])  # get password list
            print_list(password_list)
        except IndexError:
            out("Usage: -g/--generate <length> <number>", 33)

    if "-a" in raw_args or "--add" in raw_args:  # if add is called
        out("Its not possible to add passwords using -a or --add.", 33)
        out("Command line arguments don't support all characters.", 33)
        out("Use interactive mode instead.", 33)

    if "-cu" in raw_args or "--change_username" in raw_args:  # if change username is called
        index = get_index(raw_args, "-cu", "--change_username")  # get index of change username
        change_username(file,
                        raw_args[index + 1],
                        raw_args[index + 2])  # change username

    if "-cp" in raw_args or "--change_password" in raw_args:  # if change password is called
        out("Its not possible to change passwords using -cp or --change_password.", 33)
        out("Command line arguments don't support all characters.", 33)
        out("Use interactive mode instead.", 33)

    if "-l" in raw_args or "--list" in raw_args:  # if list is called
        fernet = Fernet(get_key(authenticate(file)).encode())
        list_passwords(file, fernet)  # list passwords

    if "-d" in raw_args or "--delete" in raw_args:  # if delete is called
        delete_password(file, raw_args[raw_args.index("-d") + 1])  # delete password


def interactive_mode(path="save.json"):
    file = get_json(path)  # get json file
    root = authenticate(file, path)  # authenticate user
    fernet = Fernet(get_key(root).encode())  # create fernet object with key
    while True:
        i = input("\n> ")  # get input
        if i.lower() == "help":
            print_interactive_help()

        elif i[:8].lower() == "generate":
            args = get_args(i[9:])
            if len(args) == 0:  # if no arguments are given
                print_list(generate_password())  # generate password
            elif len(args) == 1:  # if one argument is given
                print_list(generate_password(args[0]))  # generate password with length
            elif len(args) == 2:  # if two arguments are given
                print_list(generate_password(args[0], args[1]))  # generate password with length and number
            elif len(args) == 3:  # if three arguments are given
                # generate password with length, number and special characters
                print_list(generate_password(args[0], args[1], args[2]))
            else:
                out("Usage: generate <length=10> <number=10>", 33)

        elif i[:3].lower() == "add":
            args = get_args(i[4:])  # get arguments
            try:
                add_password(file, fernet, args[0], args[1], args[2], path)  # add password
            except IndexError:
                out("Usage: add <site> <username> <password>", 33)

        elif i.lower() == "list":
            list_passwords(file, fernet)

        elif i[:15].lower() == "change_password":
            args = get_args(i[16:])  # get arguments
            try:
                change_password(file, fernet, args[0], args[1], path)  # change password
            except IndexError:
                out("Usage: change_password <site> <password>", 33)

        elif i[:15].lower() == "change_username":
            args = get_args(i[16:])
            try:
                change_username(file, args[0], args[1], path)
            except IndexError:
                out("Usage: change_username <site> <username>", 33)

        elif i[:6].lower() == "delete":
            args = get_args(i[7:])
            try:
                delete_password(file, args[0], path)
            except IndexError:
                out("Usage: delete_password <site>", 33)

        elif i.lower() == "exit" or i.lower() == "quit":
            exit()

        else:
            out("Type 'help' for help.", 33)


def main(path="save.json"):
    if len(sys.argv) == 1:  # if no arguments are given
        interactive_mode(path)  # run interactive mode
    else:  # if arguments are given
        argument_mode(sys.argv[1:], path)  # run one command mode


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit()
