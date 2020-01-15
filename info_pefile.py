import pefile
import sys
import pprint

menu = '''
-----------------------------------------
  #  Desenvolvido por Adriel Freud!
  #  Contato: businessc0rp2k17@gmail.com 
  #  FB: http://www.facebook.com/xrn401
  #   =>DebutySecTeamSecurity<=
-----------------------------------------
\n\n'''

def open_file(name, out):
	with open(name, 'w') as w:
		w.write(out)
	w.close()

if len(sys.argv) < 2:
	print("\tModo de Uso:\n")
	print("./pe file.exe\n ==> \t:)\n")
	sys.exit(0)
else:
	file = sys.argv[1]
	pe = pefile.PE(file)
	info_pe= """\n\t\t\t=== Is PE file ;) ===\n
		\t\t============== DOS_HEADER ==============\n%s\n\t============== FILE_HEADER ==============\n%s\n\t\t\tCheckSum is: %s\n\t\t\t Warnings: %s\nVersion info: \n\n%s
		"""%(pe.DOS_HEADER, pe.FILE_HEADER, pe.verify_checksum, pe.show_warnings, pe.VS_VERSIONINFO)
	if pe.is_exe() == True:
		print(info_pe)
		open_file('info_pe.txt', info_pe)
		pe.close()
		#pprint.pprint(dir(pe))
	else:
		print('\n\t === Nao e um PE :c === \n')
