import socket
import time
import binascii 

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("", 8080))

covert = "TAJNA PORUKA " + "EOF"
msg = "Obična poruka"
print("Tajna poruka: " + covert)
covert_bin = ""
for i in covert:
    covert_bin += bin(int(binascii.hexlify(i.encode()), 16))[2:].zfill(8)

s.listen(0)
c,addr = s.accept()

print("Šalju se paketi")
n = 0
count = 0
while(count < len(covert_bin)):
    for i in msg:
        c.send(i.encode())
        if (covert_bin[n] == "0"):
            time.sleep(0.025)
        else:
            time.sleep(0.1)
        n = (n + 1) % len(covert_bin)
        count += 1
        
c.send("EOF".encode())
c.close()

