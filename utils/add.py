from config import establish_connection
import utils.aes
from getpass import getpass
from rich import print

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512

def getMasterKey(mp, salt):
	mp = mp.encode()
	salt = salt.encode()
	mk = PBKDF2(mp, salt, 32, count=1_000_000, hmac_hash_module=SHA512)
	return mk

def checkEntry(sitename, siteurl, email, username):
	connection = establish_connection()
	query = f"SELECT * FROM passwords_db.passwords WHERE sitename = '{sitename}' AND siteurl = '{siteurl}' AND email = '{email}' AND username = '{username}'"
	with connection.cursor(buffered=True) as cursor:
		cursor.execute(query)
	results = cursor.fetchall()

	if len(results)!=0:
		return True
	return False


def addEntry(mp, ds, sitename, siteurl, email, username):

	if checkEntry(sitename, siteurl, email, username):
		print("[yellow][-][/yellow] This entry already exists")
		return

	# Also get the password
	password = getpass("Site password: ")

	# Encrypt the password using mk
	mk = getMasterKey(mp,ds)
	encryption = utils.aes.encrypt(key=mk, source=password, keyType="bytes")

	# Add to database
	connection = establish_connection()
	query = "INSERT INTO passwords_db.passwords (sitename, siteurl, email, username, password) values (%s, %s, %s, %s, %s)" 
	vals = (sitename, siteurl, email, username, encryption)
	with connection.cursor() as cursor:
		cursor.execute(query, vals)
	connection.commit()
