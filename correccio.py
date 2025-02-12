import paramiko
import bcolors as b
import os
import subprocess

'''
Cal tenir instal·lat la llibreria dels colors
# COLORS WARN, ERR, OK, ENDC
# pip install bcolors==1.0.2

'''

#INCLOURE EL VOSTRE NOM D'USUARI
USER_IOC = "jobellaga"


def crida(command, host, username, password, resposta_ok, retorn_terminal, res_txt):
	try:
		ssh_client =paramiko.SSHClient()
		ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		ssh_client.connect(hostname=host,port='22',username=username,password=password)
		stdin, stdout, stderr = ssh_client.exec_command(command)

		resposta = stdout.read().decode()
	except:
		resposta = " [!] NOT connect SSH"
		retorn_terminal = retorn_terminal + resposta
		punts_terminal = '.' * (70-len(retorn_terminal))
		print_term = retorn_terminal + punts_terminal + '.' + b.ERR + "[ERR]" + b.ENDC
		return (print_term)

	if resposta_ok in resposta:
		punts_terminal = '.' * (70-len(retorn_terminal))
		print_term = retorn_terminal + punts_terminal + ".." + b.OK + "[OK]" + b.ENDC
#		sortida_txt = retorn_terminal + "::::" + "[OK]" + "::::" + resposta + "\n"
#		res_txt.write(sortida_txt)
		res_txt.write(print_term + '\n')
		return (print_term)
	else:
		punts_terminal = '.' * (70-len(retorn_terminal))
		print_term = retorn_terminal + punts_terminal + b.WARN + "[FAIL]" + b.ENDC
#		sortida_txt = retorn_terminal + "::::" + "[FAIL]" + "::::" + resposta + "\n"
		res_txt.write(print_term + '\n')
		print(stdout.read().decode())
		print(stderr.read().decode())
		return (print_term)

def almalinuxServer_1(res_txt):
	command = "sudo -l | grep  '(ALL) NOPASSWD: ALL'"
	host = '172.20.120.100'
	username = 'isard'
	password = 'studentIOC'
	resposta_ok = '(ALL) NOPASSWD: ALL'
	retorn_terminal = '1.AlmaLinux SERVER: user isard NOPASSWD'
	return (crida(command, host, username, password, resposta_ok, retorn_terminal, res_txt))

def almalinuxServer_2(res_txt):
	command = "sudo cat /etc/shadow | grep root"
	host = '172.20.120.100'
	username = 'isard'
	password = 'studentIOC'
	resposta_ok = 'root:!'
	retorn_terminal = '1.AlmaLinux SERVER: Disabled ROOT'
	return (crida(command, host, username, password, resposta_ok, retorn_terminal, res_txt))

def almalinuxServer_3(res_txt):
	command ="sudo cat /etc/ssh/sshd_config | grep \"AllowUsers isard\""
	host = '172.20.120.100'
	username = 'isard'
	password = 'studentIOC'
	resposta_ok = 'AllowUsers isard'
	retorn_terminal = '2.AlmaLinux SERVER: SSH Configuration'
	return (crida(command, host, username, password, resposta_ok, retorn_terminal, res_txt))

def almalinuxServer_4(res_txt):
	command ="sudo cat /etc/ssh/sshd_config | grep \"AuthenticationMethods publickey keyboard-interactive\""
	host = '172.20.120.100'
	username = 'isard'
	password = 'studentIOC'
	resposta_ok = 'AuthenticationMethods publickey keyboard-interactive'
	retorn_terminal = '2.AlmaLinux SERVER: SSH Configuration'
	return (crida(command, host, username, password, resposta_ok, retorn_terminal, res_txt))


def almalinuxServer_5(res_txt):
	command = "cat .ssh/authorized_keys"
	host = '172.20.120.100'
	username = 'isard'
	password = 'studentIOC'
	resultat = subprocess.run(["cat" , "/home/isard/.ssh/id_ed25519.pub"], capture_output=True, text=True)
	resposta_ok = resultat.stdout
	retorn_terminal = '3.AlmaLinux SERVER: SSH Configuration to Ubuntu '
	return (crida(command, host, username, password, resposta_ok, retorn_terminal, res_txt))





def UbuntuServer_1(res_txt):
	command = "sudo cat /etc/shadow | grep root"
	host = '172.20.120.150'
	username = 'isard'
	password = 'studentIOC'
	resposta_ok = 'root:!'
	retorn_terminal = '1.UbuntuServer SERVER: Disabled ROOT'
	return (crida(command, host, username, password, resposta_ok, retorn_terminal, res_txt))

def UbuntuServer_2(res_txt):
	command = "sudo -l | grep  '(ALL) NOPASSWD: ALL'"
	host = '172.20.120.150'
	username = 'isard'
	password = 'studentIOC'
	resposta_ok = '(ALL) NOPASSWD: ALL'
	retorn_terminal = '2.UbuntuServer SERVER: user isard NOPASSWD'
	return (crida(command, host, username, password, resposta_ok, retorn_terminal, res_txt))

def UbuntuServer_3(res_txt):
	command = "cat /etc/passwd | grep " + USER_IOC
	host = '172.20.120.150'
	username = 'isard'
	password = 'studentIOC'
	resposta_ok = USER_IOC
	retorn_terminal = '3.UbuntuServer SERVER: user ' + USER_IOC
	return (crida(command, host, username, password, resposta_ok, retorn_terminal, res_txt))

def UbuntuServer_4(res_txt):
	command = "sudo ls -al /var/www/html/ | grep index.html"
	host = '172.20.120.150'
	username = 'isard'
	password = 'studentIOC'
	resposta_ok = '-rwxr----- 1 root www-data'
	retorn_terminal = '4.UbuntuServer SERVER: permisions web '
	return (crida(command, host, username, password, resposta_ok, retorn_terminal, res_txt))

def UbuntuServer_5(res_txt):
	command = "sudo ls -al /var/www/html/ | grep lib"
	host = '172.20.120.150'
	username = 'isard'
	password = 'studentIOC'
	resposta_ok = 'drwxr-x--- 6 root www-data'
	retorn_terminal = '4.UbuntuServer SERVER: directories web '
	return (crida(command, host, username, password, resposta_ok, retorn_terminal, res_txt))

def UbuntuServer_6(res_txt):
	command = "id " + USER_IOC
	host = '172.20.120.150'
	username = 'isard'
	password = 'studentIOC'
	resposta_ok = 'www-data'
	retorn_terminal = '5.UbuntuServer SERVER: group www-data'
	return (crida(command, host, username, password, resposta_ok, retorn_terminal, res_txt))

def UbuntuServer_7( res_txt):
	command ="echo \"$(sudo cat /etc/ssh/sshd_config | grep -A 6 \"Match User isard\" | grep 'PasswordAuthentication yes')\""
	host = '172.20.120.150'
	username = 'isard'
	password = 'studentIOC'
	resposta_ok = 'PasswordAuthentication yes'
	retorn_terminal = '6.UbuntuServer SERVER: isard password'
	return (crida(command, host, username, password, resposta_ok, retorn_terminal, res_txt))

def UbuntuServer_8( res_txt):
	command ="echo \"$(sudo cat /etc/ssh/sshd_config | grep -A 6 \"Match User " + USER_IOC + "\" | grep 'AuthenticationMethods publickey')\""
	host = '172.20.120.150'
	username = 'isard'
	password = 'studentIOC'
	resposta_ok = 'AuthenticationMethods publickey'
	retorn_terminal = '7.UbuntuServer SERVER: ssh user publickey'
	return (crida(command, host, username, password, resposta_ok, retorn_terminal, res_txt))

def UbuntuServer_9( res_txt):
	command ="echo \"$(sudo cat /etc/ssh/sshd_config | grep -A 6 \"Match User " + USER_IOC + "\" | grep 'PasswordAuthentication no')\""
	username = 'isard'
	host = '172.20.120.150'
	password = 'studentIOC'
	resposta_ok = 'PasswordAuthentication no'
	retorn_terminal = '7.UbuntuServer SERVER: no password'
	return (crida(command, host, username, password, resposta_ok, retorn_terminal, res_txt))

def UbuntuServer_10(res_txt):
	command = "cat /home/isard/check.log"
	host = '172.20.120.150'
	username = 'isard'
	password = 'studentIOC'
	resposta_ok = '@172.20.120.150/24 apple'
	retorn_terminal = '8.UbuntuServer SERVER: check.log'
	return (crida(command, host, username, password, resposta_ok, retorn_terminal, res_txt))

def UbuntuServer_11(res_txt):
	command = "cat /etc/pam.d/common-auth | grep 'pam_exec.so expose_authtok /usr/local/bin/check_password.sh'"
	host = '172.20.120.150'
	username = 'isard'
	password = 'studentIOC'
	resposta_ok = 'pam_exec.so expose_authtok /usr/local/bin/check_password.sh'
	retorn_terminal = '8.UbuntuServer SERVER: pam exec edit'
	return (crida(command, host, username, password, resposta_ok, retorn_terminal, res_txt))



def main():
    #Tota la sortida es guarda com script
    avaluacio_retorn = ""

    #En aquest punt, preparem les dades amb les que treballarem

    #############-----------DO IT-----------#############
    #### PREPAREM LES DADES PER CRIDAR LES FUNCIONS  ####
    #####################################################
    '''
    Exemple:
    documents = get_documents()
    sistema = get_ips()
    ip_host1 = sistema[0]
    '''
    hostname = os.uname()[1]
#    print (hostname)
    res_txt = open("/home/isard/avaluacio.txt", "w")
    res_txt.write("*******************************\n")
    res_txt.write("*******************************\n")
    #############-----------FINISH----------#############
    #####################################################


    #############-----------DO IT-----------#############
    #### CRIDEM LES FUNCIONS QUE VOLEM I GUARDEM     ####
    #####################################################
    puntuacio = 0

    alServer1 = almalinuxServer_1(res_txt)
    alServer2 = almalinuxServer_2(res_txt)
    if '[OK]' in alServer1 and '[OK]' in alServer2:
        puntuacio = puntuacio + 1
    avaluacio_retorn = avaluacio_retorn + alServer1 + ('\n') + alServer2 + ('\n')

    alServer3 = almalinuxServer_3(res_txt)
    alServer4 = almalinuxServer_4(res_txt)
    if '[OK]' in alServer3 and '[OK]' in alServer3:
        puntuacio = puntuacio + 1
    avaluacio_retorn = avaluacio_retorn + alServer3 + ('\n') + alServer4 + ('\n')


    alServer5 = almalinuxServer_5(res_txt)
    if '[OK]' in alServer5:
        puntuacio = puntuacio + 1
    avaluacio_retorn = avaluacio_retorn + alServer5 + ('\n')

    ubServer1 = UbuntuServer_1(res_txt)

    ubServer2 = UbuntuServer_2(res_txt)

    if '[OK]' in ubServer1 and '[OK]' in ubServer2:
        puntuacio = puntuacio + 1
    avaluacio_retorn = avaluacio_retorn + ubServer1 + ('\n') + ubServer2 + ('\n')
    ubServer3 = UbuntuServer_3(res_txt)
    if '[OK]' in ubServer3:
        puntuacio = puntuacio + 1
    avaluacio_retorn = avaluacio_retorn + ubServer3 + ('\n')

    ubServer4 = UbuntuServer_4(res_txt)
    ubServer5 = UbuntuServer_5(res_txt)
    if '[OK]' in ubServer4 and '[OK]' in ubServer5:
        puntuacio = puntuacio + 1
    avaluacio_retorn = avaluacio_retorn + ubServer4 + ('\n') + ubServer5 + ('\n')

#Punt 5
    ubServer6 = UbuntuServer_6(res_txt)
    if '[OK]' in ubServer6:
        puntuacio = puntuacio + 1
    avaluacio_retorn = avaluacio_retorn + ubServer6 + ('\n')

#Punt 6
    ubServer7 = UbuntuServer_7(res_txt)
    if '[OK]' in ubServer7:
        puntuacio = puntuacio + 1
    avaluacio_retorn = avaluacio_retorn + ubServer7 + ('\n')

#Punt 7

    ubServer8 = UbuntuServer_8(res_txt)
    ubServer9 = UbuntuServer_9(res_txt)
    if '[OK]' in ubServer8 and '[OK]' in ubServer9:
        puntuacio = puntuacio + 1
    avaluacio_retorn = avaluacio_retorn + ubServer8 + ('\n') + ubServer9 + ('\n')

#Punt 8
    ubServer10 = UbuntuServer_10(res_txt)
    ubServer11 = UbuntuServer_11(res_txt)
    if '[OK]' in ubServer10 and '[OK]' in ubServer11:
        puntuacio = puntuacio + 1
    avaluacio_retorn = avaluacio_retorn + ubServer10 + ('\n') + ubServer11 + ('\n')

    #############-----------FINISH----------#############
    #####################################################
    avaluacio_retorn = avaluacio_retorn + ('\n') + "Puntuació: " + str(puntuacio) + ('\n')
    res_txt.write("puntuació: " + str(puntuacio) + ('\n'))
    res_txt.close()

    print (avaluacio_retorn)
    print ('***********FINISH***********')



if __name__ == "__main__":
    main()
