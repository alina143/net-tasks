
import urllib.request
import time

from sleekxmpp import ClientXMPP

username = 'ns_com@jabber.ru'
passwd = '55gefest'
to = 'ppaa123@xabber.org'
client = ClientXMPP(username, passwd)
client.connect()
client.process()




while True:

	req = urllib.request.Request('http://weather.nsu.ru/weather.xml')
	response = urllib.request.urlopen(req)
	page = response.read()
	str_page = str(page)
	index1 = str_page.find('current')
	index2 = str_page.find('/current')
	data = str_page[index1+8:index2-1]
	client.send_message(to, 'Current temperature: ' + data + '°C')
	time.sleep(1)

client.disconnect()
