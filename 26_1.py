
from scapy.all import sniff
from scapy.layers.inet import TCP, IP
import time


class TCPstream:
    def __init__(self, src, dport, data):
        self.src = src
        self.dport = dport
        self.data = data


streams = []  # array of TCPstream objects


def saveImage(src, format_name, image):
    file_name = str(time.time()) + '.' + format_name
    with open(file_name, 'wb') as file:
        print('File ', file_name, 'created!')
        file.write(image)
        file.close()


def handleStream(stream):
    while True:
        data = stream.data
        content_ptr = data.find(b'\r\n\r\n')
        if content_ptr == -1:
            return  # РїР°РєРµС‚ РµС‰Рµ РЅРµ РїРѕР»РЅС‹Р№
        content_ptr += len(b'\r\n\r\n')

        ### РѕРїСЂРµРґРµР»СЏРµРј СЂР°Р·РјРµСЂ РґР°РЅС‹С…
        ptr = data.find(b'Content-Length: ')
        if ptr == -1:
            stream.data = data[content_ptr:]  # РІС‹СЂРµР·Р°РµРј РїР°РєРµС‚ Р±РµР· РєРѕРЅС‚РµРЅС‚Р°
            continue  # РЅР°С‡РёРЅР°РµРј Р·Р°РЅРѕРІРѕ
        string = data[ptr: ptr + 35]
        ptr += len(b'Content-Length: ')
        end = data.find(b'\r\n', ptr)
        content_length = int(data[ptr: end])

        ### РѕРїСЂРµРґРµР»СЏРµРј С„РѕСЂРјР°С‚ РёР·РѕР±СЂР°Р¶РµРЅРёСЏ
        ptr = data.find(b'Content-Type: image/')
        if ptr == -1:
            stream.data = data[content_ptr + content_length + 1:]  # РІС‹СЂРµР·Р°РµРј РїР°РєРµС‚ Р±РµР· РєР°СЂС‚РёРЅРєРё
            continue  # РЅР°С‡РёРЅР°РµРј Р·Р°РЅРѕРІРѕ
        ptr += len(b'Content-Type: image/')
        end = data.find(b'\r\n', ptr)
        format_bytes = data[ptr: end]
        format_name = ''
        for c in format_bytes:
            format_name += chr(c)

        ### СЃРѕС…СЂР°РЅСЏРµРј РёР·РѕР±СЂР°Р¶РµРЅРёРµ
        image = data[content_ptr: content_ptr + content_length]
        if len(image) < content_length:
            return  # РїР°РєРµС‚ РµС‰Рµ РЅРµ РїРѕР»РЅС‹Р№
        # print('\'Content-dispodition search:', data.find(b'Content-Disposition'))
        saveImage(stream.src, format_name, image)
        stream.data = data[content_ptr + content_length:]  # РІС‹СЂРµР·Р°РµРј РѕР±СЂР°Р±РѕС‚Р°РЅРЅС‹Р№ РїР°РєРµС‚


def handlePacket(packet):
    src = packet[IP].src
    dport = packet[TCP].dport
    data = bytes(packet[TCP].payload)
    flag = False
    for stream in streams:
        if src == stream.src and dport == stream.dport:
            stream.data += data
            handleStream(stream)
            flag = True
            break
    if flag == False:
        stream = TCPstream(src, dport, data)
        streams.append(stream)
        handleStream(stream)


print('Sniffing...')
sniff(prn=handlePacket, filter='tcp')
