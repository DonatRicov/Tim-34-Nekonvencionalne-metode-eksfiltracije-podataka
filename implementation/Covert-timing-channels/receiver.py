import socket
import sys
import time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 8080))

paket = s.recv(4096).decode()

covert_bin = ""
while (paket.rstrip("\n") != "EOF"):
    sys.stdout.write(paket)
    sys.stdout.flush()
    t0 = time.time()
    paket = s.recv(4096).decode()
    t1 = time.time()
    delta = round(t1 - t0, 3)
    
    sys.stdout.write("\tTime: \t" + str(delta) + "\n")
    sys.stdout.flush()
        
    if (delta >= 0.1):
        covert_bin += "1"
    else:
        covert_bin += "0"
    
s.close()

print("Binary received: " + str(covert_bin))
print("\nConvert 8 byte binary to character:")

covert = ""
i = 0
while (i < len(covert_bin)):
    
    b = covert_bin[i:i+8]

    n = int("0b{}".format(b), 2)
    try:
        print("byte:\t" + str(b))
        print("int conversion: " + str(n))
        print("char conversion:\t" + chr(n) + "\n")
        
        covert += chr(n)
        
    except:
        covert += "?"
        
    i += 8

print("\nCovert message: " + covert)