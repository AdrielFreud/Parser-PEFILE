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

def open_file(name, pe, file):
	with open(name, 'w') as w:
		w.write(menu)
		w.write('\n\t\t 	=== Is PE file ;) ===')
		w.write('\n')
		w.write("\n\t\t============== DOS_HEADER ==============\n")
		w.write("%s"%pe.DOS_HEADER)
		w.write('\n')
		w.write("\n\t============== FILE_HEADER ==============\n")
		w.write("%s"%pe.FILE_HEADER)
		w.write('\n')
		w.write("\n\t     ============== SECTIONS OF PEFILE ==============\n")
		for sections in pe.sections:
			w.write('\n')
			w.write('\t\t\t==  \t%s\t=='%sections.Name)
			if sections.Name == '.data' or '.gfids' or '.reloc':
				w.write('\t\t\t==    \t%s\t\t=='%sections.SizeOfRawData)
			else:
				w.write('\t\t==    \t%s\t=='%sections.SizeOfRawData)
		w.write('\n')
		w.write("\n\t     ============== VERIFY PEFILE ==============\n")
		w.write("\t\t\t CheckSum is: %s"%pe.verify_checksum())
		w.write("\t\t\t Warnings: %s"%pe.show_warnings())
		w.write("Version info: \n\n%s"%pe.VS_VERSIONINFO)
	w.close()

if len(sys.argv) < 2:
	print('Modo de Uso:')
	print("./pe file.exe\n ==> \t:)\n")
	sys.exit(0)
else:
	global file, pe
	file = sys.argv[1]
	pe = pefile.PE(file)
	if pe.is_exe() == True:
		print(menu)
		print('\n\t\t 	=== Is PE file ;) ===')
		print('\n')
		print("\t\t============== DOS_HEADER ==============\n")
		print(pe.DOS_HEADER)
		print('\n')
		print("\t============== FILE_HEADER ==============\n")
		print(pe.FILE_HEADER)
		print('\n')
		print("\t     ============== SECTIONS OF PEFILE ==============\n")
		for sections in pe.sections:
			print('\t\t\t==  \t%s\t=='%sections.Name)
			if sections.Name == '.data' or '.gfids' or '.reloc':
				print('\t\t\t==    \t%s\t\t=='%sections.SizeOfRawData)
			else:
				print('\t\t==    \t%s\t=='%sections.SizeOfRawData)
			print('\t\t\t==========================')
		print("\n\t     ============== VERIFY PEFILE ==============\n")
		print("\t\t\t CheckSum is: %s"%pe.verify_checksum())
		print("\t\t\t Warnings: %s"%pe.show_warnings())
		print("Version info: \n\n%s"%pe.VS_VERSIONINFO)
		open_file('info_pe.txt', pe, file)
		pe.close()
		#pprint.pprint(dir(pe))
	else:
		print('\n\t === Nao e um PE :c === \n')
