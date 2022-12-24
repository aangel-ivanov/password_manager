#!/usr/bin/env python

import random
import string
import argparse
from getpass import getpass
import hashlib
import pyperclip

from rich import print

import utils.add
import utils.retrieve
from config import establish_connection

def generatePassword(length):
	return ''.join([random.choice(string.ascii_letters + string.digits + string.punctuation ) for i in range(length)])

parser = argparse.ArgumentParser(description="Password Manager")
parser.add_argument('option', help='(Add) a new password / (Get) a password / (Make) a password')
parser.add_argument("-s", "--name", help="Site name")
parser.add_argument("-u", "--url", help="Site URL")
parser.add_argument("-e", "--email", help="Email")
parser.add_argument("-l", "--login", help="Username")
parser.add_argument("--length", help="Length of the password to generate",type=int)
parser.add_argument("-c", "--copy", action='store_true', help='Copy password to clipboard')
args = parser.parse_args()


def authorize():
	'''
	Validate the master password
	'''
	mp = getpass("MASTER PASSWORD: ")
	hashed_mp = hashlib.sha256(mp.encode()).hexdigest()

	connection = establish_connection()
	query = "SELECT * FROM passwords_db.key"
	cursor = connection.cursor()
	cursor.execute(query)
	result = cursor.fetchall()[0]
	if hashed_mp != result[0]:
		print("[red][!] ACCESS DENIED [/red]")
		return None
	
	print("[green][+] ACCESS GRANTED [/green]")
	return [mp, result[1]]


def main():
	if args.option in ["Add","ADD","add","a"]:
		if args.name == None:
			print("[red][!][/red] Site Name (-s) required ")
		if args.url == None:
			print("[red][!][/red] Site URL (-u) required ")
		if args.login == None:
			print("[red][!][/red] Site Login (-l) required ")

		if args.name == None or args.url == None or args.login == None:
			return

		if args.email == None:
			args.email = ""

		results = authorize()
		if results is not None:
			utils.add.addEntry(results[0], results[1], args.name, args.url, args.email, args.login)

		print("[green][+][/green] Added entry")


	if args.option in ["Get","GET","get","g"]:
		results = authorize()

		if args.name == None and args.url == None and args.email == None and args.login == None:
			if results is not None:
				utils.retrieve.retrieveEntries(results[0], results[1], decrypt = args.copy)

		search = {}
		if args.name is not None:
			search["sitename"] = args.name
		if args.url is not None:
			search["siteurl"] = args.url
		if args.email is not None:
			search["email"] = args.email
		if args.login is not None:
			search["username"] = args.login

		if results is not None:
			utils.retrieve.retrieveEntries(results[0], results[1], search, decrypt = args.copy)


	if args.option in ["Make","MAKE","make","m"]:
		if args.length == None:
			print("[red][+][/red] Specify length of the password to generate (--length)")
			return
		password = generatePassword(args.length)
		pyperclip.copy(password)
		print("[green][+][/green] Password generated and copied to clipboard")

if __name__ == '__main__':
	main()