from challenge_patched import *

# sooo attack.go did it's job and printed the two correct keys, now let's import the decryption function that works for more than one block and finally get the flag

aeskey1= [227, 146, 128, 233, 227, 146, 128, 233]
aeskey2= [243, 165, 158, 229, 243, 165, 158, 229]

cp = '98f157bc54ca49a998f191a565c40bd0035004d917bd45d03fc9c9e465b9978a49f140a222f3f04e492c2d1e1cb94017db4fa85883f8b4c95229a8d7f8b9248adb4fc9bc3ed9f0c98867a87ace659265a4123a11070037a7'
cp = bytes.fromhex(cp)
key1 = bytes(aeskey1)
key2 = bytes(aeskey2)

res = decrypt(decrypt(cp, key2), key1)
print(res)