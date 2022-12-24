from config import establish_connection
import utils.aes
import pyperclip

from rich import print
from rich.console import Console
from rich.table import Table

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512

def getMasterKey(mp, salt):
	mp = mp.encode()
	salt = salt.encode()
	mk = PBKDF2(mp, salt, 32, count=1_000_000, hmac_hash_module=SHA512)
	return mk

def retrieveEntries(mp, salt, search_fields='', decrypt=False):
	connection = establish_connection()
	
	query = ""

	# If no search fields specified, return all entries
	if len(search_fields) == 0:
		query = "SELECT * FROM passwords_db.passwords"
	else:
		query = "SELECT * FROM passwords_db.passwords WHERE "
		for i in search_fields:
			query += f"{i} = '{search_fields[i]}' AND "
		query = query[:-5] # remove the extraneous "  AND"

	cursor = connection.cursor()
	cursor.execute(query)
	results = cursor.fetchall()

	if len(results) == 0:
		print("[yellow][-] Search returned no results [/yellow]")
		return

	# Case where we are not decrypting the password
	if not decrypt or (decrypt and len(results) > 1):
		if decrypt:
			print("[yellow][-][/yellow] More than one result returned, therefore can't retrieve password")
		table = Table()

		table.add_column("Site Name")
		table.add_column("URL",)
		table.add_column("Email")
		table.add_column("Username")
		table.add_column("Password")

		for i in results:
			table.add_row(i[0], i[1], i[2], i[3], "{hidden}")
		console = Console()
		console.print(table)
		return 

	# Case where we are decrypting the password
	if decrypt and len(results) == 1:
		# Decrypt password
		mk = getMasterKey(mp, salt)
		decryption = utils.aes.decrypt(key=mk, source=results[0][4], keyType="bytes")

		print("[green][+][/green] Password copied to clipboard")
		pyperclip.copy(decryption.decode())

	connection.close()
