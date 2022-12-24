import os
import sys
import string
import random
import hashlib
import pyperclip
from rich import print
from rich.prompt import Prompt

import mysql.connector
from mysql.connector import errorcode

def generatePassword(length):
	return ''.join([random.choice(string.ascii_letters + string.digits + string.punctuation ) for i in range(length)])

def establish_connection():
	'''
	Establish connection with MySQL server.
	'''
	cnx = None
	try:
		cnx = mysql.connector.connect(
			user=os.environ.get('DB_username'),
			passwd=os.environ.get('DB_password'),
			host ="localhost"
		)
		# print("[green][+][/green] Connected to database")

  # catch any errors
	except mysql.connector.Error as err:
		if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
			print("[red][!] Something is wrong with your user name or password [/red]")
		elif err.errno == errorcode.ER_BAD_DB_ERROR:
			print("[red][!] Database does not exist [/red]")
		else:
			print(err)
	# else:
	# 	connection.close()

	return cnx

def isConfig():
	connection = establish_connection()
	query = "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = 'passwords_db'"
	with connection.cursor(buffered=True) as cursor:
		cursor.execute(query)
	results = cursor.fetchall()
	connection.close()
	if len(results)!=0:
		return True
	return False

def config():
	if isConfig():
		print("[red][!] A database already exists! [/red]")
		while 1:
			option = Prompt.ask("[yellow][-] Are you sure you want to overwrite existing database? This action cannot be undone. (y/n) [/yellow]")
			if option.upper() == "Y":
				break
			if option.upper() == "N" or option.upper == "":
					sys.exit(0)
			else:
				continue

		connection = establish_connection()
		query = "DROP DATABASE passwords_db"
		with connection.cursor() as cursor:
			cursor.execute(query)
		connection.commit()
		connection.close()
		print("[green][+][/green] Database deleted! ")

	print("[green][+] Establishing a server connection [/green]")

	# Create database
	connection = establish_connection()
	query = "CREATE DATABASE passwords_db"
	with connection.cursor() as cursor:
		try:
			cursor.execute(query)
		except Exception as e:
			print("[red][!] An error occurred while creating a database. Check if a database with the name 'passwords_db' already exists by executing the SHOW DATABASES statement.")
			print(e)
			sys.exit(0)

	print("[green][+][/green] Database 'passwords_db' created")

	# Create tables to store master key and password entries
	query = "CREATE TABLE passwords_db.key (mk_hash TEXT NOT NULL, salt TEXT NOT NULL)"
	with connection.cursor() as cursor:
		cursor.execute(query)

	query = "CREATE TABLE passwords_db.passwords (sitename TEXT NOT NULL, siteurl TEXT NOT NULL, email TEXT, username TEXT, password TEXT NOT NULL)"
	with connection.cursor() as cursor:
		cursor.execute(query)


	# Generate master password
	mp = ""
	length = int(input("How many charactors long do you want your master password to be? (Recommended at least 15). "))
	mp = generatePassword(length)
	pyperclip.copy(mp)
	print("[green][+][/green] Your master password has been copied to your clipboard. Immediatly store it somewhere safe. If you misplace it, you will lose access to the database! ")

	# Hash the master password
	mp_hash = hashlib.sha256(mp.encode()).hexdigest()
	print("[green][+][/green] Generated hash of master password")

	# Generate salt
	salt = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 10))

	# Add to the table
	query = "INSERT INTO passwords_db.key (mk_hash, salt) values (%s, %s)"
	vals = (mp_hash, salt)
	with connection.cursor() as cursor:
		cursor.execute(query, vals)
	connection.commit()

	print("[green][+][/green] Added to the database")
	print("[green][+] Configuration done![/green]")

	connection.close()

def destroy():
	if not isConfig():
		print("[yellow][-] No configuration exists. [/yellow]")
		return
	
	print("[yellow][-] Erasing an existing configuration will destroy all data stored in the password manager. This action cannot be undone. [/yellow]")

	while 1:
		op = input("Are you sure you want to proceed? (y/n): ")
		if op.upper() == "Y":
			break
		if op.upper() == "N" or op.upper == "":
			sys.exit(0)
		else:
			continue

	connection = establish_connection()
	query = "DROP DATABASE passwords_db"
	with connection.cursor() as cursor:
		cursor.execute(query)
	connection.commit()
	connection.close()
	print("[green][+] Configuration deleted [/green]")


if __name__ == "__main__":

	if len(sys.argv)!=2:
		print("Usage: python config.py <config/destroy>")
		sys.exit(0)

	if sys.argv[1] == "config":
		config()
	elif sys.argv[1] == "destroy":
		destroy()
	else:
		print("Usage: python config.py <config/destroy>")