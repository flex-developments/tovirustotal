#!/usr/bin/python
# -*- coding: utf-8 -*-

# Script para verificación de hash contra VirusTotal

#Globales---------------------------------------------------------------
VT_URL_REPORT="https://www.virustotal.com/vtapi/v2/file/report"
VT_API_KEY="LALALALALALALALALALALALALALALALALALALALALA"
VERBOSE_ENABLED = False

#Strings----------------------------------------------------------------
STR_NO_HASHES = "No se encontraron hashes en el archivo"
STR_USAGE= "Modo de uso:\n \
			\t-hf HASH_FILE_PATH\n \
			\t\t Archivo con lista de hash\n \
			\t-sf SYSMON_FILE_PATH\n \
			\t\t Archivo de log generado por sysmon\n \
			\t-ak VT_API_KEY\n \
			\t\t Valor de la API KEY de VirusTotal\n \
			\t-v\n \
			\t\t Verbose\n \
			\t-h\n \
			\t\t Imprime esta ayuda"

#Imports----------------------------------------------------------------
import sys
import urllib.request
import urllib.parse
import json
import time

#Defts------------------------------------------------------------------
def __main__():
	#os.system("clear")
	#import pdb
	#pdb.set_trace()
	
	#Lista de hashes
	HASH_FILE_PATH = ""
	#log de sysmon
	SYSMON_FILE_PATH = ""

	##Leer parametros de consola
	for i in range(len(sys.argv)):
		if (sys.argv[i] == '-hf'):
			HASH_FILE_PATH = sys.argv[int(i)+1]
		
		if (sys.argv[i] == '-sf'):
			SYSMON_FILE_PATH = sys.argv[int(i)+1]
		
		if (sys.argv[i] == '-ak'):
			VT_API_KEY = sys.argv[int(i)+1]
		
		if (sys.argv[i] == '-v'):
			VERBOSE_ENABLED = True
			
		if (sys.argv[i] == '-h'):
			printUsage()
		
	##Leer archivo de hashes
	lista=[]
	source=""
	
	if not HASH_FILE_PATH=="":
		try:
			source = open(HASH_FILE_PATH, 'r')
			printLog("Reading Hash File...")
			for current in source:
				current = current.split('\n')[0]
				printLog("Add hash: " + current)
				lista.append(current)
		except Exception as err:
			traceback.print_exc()
			print('Hash File not found')
			sys.exit()
	
	elif not SYSMON_FILE_PATH=="":
		try:
			source = open(SYSMON_FILE_PATH, 'r')
			printLog("Reading Sysmon Log File...")
			for current in source:
				hashes = getHashesFromSysmonLog(current, "<Data Name='Hash'>", 32)
				lista.extend(hashes)
		except Exception as err:
			traceback.print_exc()
			print('Sysmon Log File not found')
			sys.exit()
	else:
		printUsage()
		
	source.close()
	
	lista = purgueList(lista)
	
	for i in lista:
		printLog("\nIterating with " + i + " -------------------------------")
		
		##Obtener reporte VT
		VTreport = getVTReport(i)
		##Interpretar reporte VT
		processVTJsonReport(i, VTreport)
		time.sleep(2)
		
	##Fin
	sys.exit()

def printUsage():
	print(STR_USAGE)
	sys.exit()

def getVTReport(VTresources):
	printLog("Getting VT report...")
	requestParams = {'resource': VTresources, 'apikey': VT_API_KEY}
	data = urllib.parse.urlencode(requestParams)
	data = data.encode('utf-8')
	req = urllib.request.Request(VT_URL_REPORT, data)
	response = urllib.request.urlopen(req)
	VTjsonReport = response.read().decode()
	return VTjsonReport
	#obj = json.load(response)
	#VTjsonReport = response.readall().decode('utf-8')
	#return VTjsonReport

def processVTJsonReport(VTresources, VTjsonReport):
	printLog("Processing VT report...")
	printLog(VTjsonReport)
	try:
		dataJson = json.loads(VTjsonReport)
		positive = dataJson["positives"]
		print('ID>: ',VTresources,'\n\t Positives>: ',positive)
	except Exception as err:
		print('ID>: ',VTresources,'\n\t Positives>: No answer or Error in answer')
	return

def getHashesFromSysmonLog(line, tag, chars):
	result = []
	while True:
		pos = line.find(tag)
		if pos==-1:
			break
		else:
			posHash = pos+len(tag)
			h = line[posHash:(posHash+chars)]
			printLog("Add hash: " + h)
			result.append(h)
			line = line[(posHash+chars):(len(line)-1)]
	return result

def purgueList(hashes):
	printLog("Purging hash list...")
	result = []
	for i in hashes:
		if i not in result:
			result.append(i)
	return result

def printLog(message):
	if VERBOSE_ENABLED:
		print(message)
	
#Execute----------------------------------------------------------------
__main__()
