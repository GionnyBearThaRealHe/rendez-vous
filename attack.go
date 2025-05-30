package main

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
)

// permutation and substitution boxes to use for encryption/decryption, taken directly from the provided boxes.py file
var pbox = []int{3, 1, 5, 2, 0, 6, 7, 4}
var sbox = []byte{66, 53, 242, 150, 205, 0, 206, 192, 77, 200, 7, 130, 81, 193, 198, 249, 122, 56, 74, 21, 190, 175, 245, 174, 243, 126, 101, 118, 114, 10, 59, 102, 65, 103, 12, 189, 159, 98, 251, 177, 241, 35, 240, 25, 17, 248, 85, 171, 247, 155, 20, 196, 254, 168, 121, 158, 37, 228, 24, 169, 63, 224, 164, 33, 238, 67, 163, 96, 45, 47, 72, 43, 90, 27, 212, 86, 41, 215, 123, 16, 195, 182, 14, 246, 93, 46, 237, 172, 134, 131, 154, 88, 44, 185, 28, 146, 127, 34, 100, 1, 55, 202, 111, 132, 125, 139, 13, 143, 71, 87, 148, 219, 178, 99, 217, 30, 62, 140, 32, 227, 92, 226, 214, 6, 176, 135, 78, 170, 5, 255, 179, 133, 19, 230, 15, 36, 113, 26, 186, 58, 141, 42, 84, 104, 60, 239, 3, 52, 49, 117, 234, 39, 61, 116, 204, 157, 181, 64, 48, 79, 70, 110, 250, 75, 82, 50, 229, 105, 162, 191, 124, 207, 210, 156, 197, 231, 252, 68, 216, 173, 218, 23, 144, 31, 69, 89, 188, 161, 199, 54, 38, 57, 142, 137, 8, 108, 115, 97, 194, 223, 147, 73, 152, 51, 4, 9, 183, 221, 253, 187, 128, 112, 153, 167, 208, 184, 209, 236, 233, 160, 18, 91, 213, 107, 29, 151, 136, 2, 106, 119, 109, 80, 138, 235, 165, 120, 129, 201, 11, 83, 222, 211, 166, 203, 22, 225, 232, 94, 220, 149, 95, 76, 40, 244, 145, 180}

// the first 8 bytes (the first block), of both the plaintext (called cyphertext) and the cyphertext (called encrypted), those names make sense later in the code trust me
var encrypted = []byte{0x98, 0xf1, 0x57, 0xbc, 0x54, 0xca, 0x49, 0xa9}
var cyphertext = []byte("I think ")

// these two slices contain fixed bytes to put in the second position of encryption and decrypiton keys to test, they have to be tested pair by pair, using the same index for both slices
// these values are obtained through a smaller meet in the middle attack performed only on the the second byte of the plaintext/chipertext, see findFixedBytes.py for details
var secondByteEncKeys = []byte{16, 201, 139, 162, 143, 164, 183, 75, 7, 203, 150, 146, 154, 28, 83, 178, 238, 219, 159, 158, 139, 197, 199, 185, 103, 142, 79, 158, 161, 33, 171, 216, 151, 66, 254, 104, 200, 175, 142, 70, 206, 184, 158, 176, 53, 1, 115, 70, 208, 100, 124, 141, 152, 216, 248, 253, 209, 161, 28, 242, 139, 234, 168, 175, 161, 216, 165, 240, 79, 233, 249, 139, 253, 208, 72, 0, 81, 86, 150, 89, 234, 203, 45, 37, 53, 45, 89, 113, 246, 28, 237, 146, 116, 171, 174, 136, 79, 209, 58, 156, 75, 72, 171, 248, 120, 166, 158, 76, 109, 1, 69, 244, 249, 53, 91, 53, 82, 207, 145, 168, 103, 9, 247, 9, 158, 217, 141, 243, 217, 231, 88, 6, 219, 154, 55, 28, 72, 36, 138, 86, 231, 104, 91, 243, 208}
var secondByteDecKeys = []byte{0, 2, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17, 19, 22, 26, 27, 29, 31, 32, 33, 34, 38, 40, 41, 43, 45, 46, 49, 50, 52, 53, 56, 60, 62, 63, 66, 70, 77, 78, 82, 83, 84, 85, 86, 87, 91, 92, 93, 96, 97, 98, 100, 101, 103, 104, 106, 107, 108, 109, 112, 113, 116, 117, 120, 121, 123, 124, 127, 129, 131, 132, 133, 135, 136, 137, 138, 140, 142, 143, 145, 146, 147, 152, 153, 154, 157, 158, 159, 160, 161, 165, 166, 167, 168, 172, 173, 175, 176, 177, 181, 182, 183, 185, 188, 189, 191, 192, 196, 197, 199, 200, 203, 204, 205, 206, 207, 210, 212, 213, 214, 216, 217, 219, 220, 223, 224, 225, 226, 227, 231, 233, 234, 235, 236, 239, 241, 243, 245, 247, 248, 249, 250, 252, 253}

// this function takes in a 32 bit integer and turns it into a 8 byte slice that is the pythons equivalent of  bytes(integer) + bytes(integer),
// thus obtaining a valid key format that is easily iterable for bruteforcing
func intToDoubleSlice(x uint32) []byte {
	// Allocate a 4-byte slice and write x in big-endian format.
	b4 := make([]byte, 4)
	binary.BigEndian.PutUint32(b4, x)

	// Allocate an 8-byte slice.
	b8 := make([]byte, 8)
	// Copy the 4-byte slice into the first half.
	copy(b8, b4)
	// Copy it again into the second half.
	copy(b8[4:], b4)
	return b8
}

// go implementation of the encryption function made to encrypt only one block, which is enough for the mitm attack
func encryptBlock(pt, key []byte) []byte {
	// Copy the plaintext into a working block
	block := make([]byte, 8)
	copy(block, pt)

	// Perform 7 rounds of encryption
	for r := 0; r < 7; r++ {
		// Round: XOR the block with the key
		for i := 0; i < 8; i++ {
			block[i] ^= key[i]
		}

		// Round: Substitute bytes using the sbox
		for i := 0; i < 8; i++ {
			block[i] = sbox[block[i]]
		}

		// Round: Permute bytes using the pbox
		ptNew := make([]byte, 8)
		for i := 0; i < 8; i++ {
			// pbox[i] should be in the range [0,7]
			ptNew[i] = block[pbox[i]]
		}

		// Update block for the next round
		block = ptNew
	}

	// Return the final block as the ciphertext
	return block
}

// go implementation of the decryption function, again only one block
func decryptBlock(ct, key []byte) []byte {
	// Copy the ciphertext into a working block.
	block := make([]byte, 8)
	copy(block, ct)

	// Perform 7 rounds of decryption.
	for r := 0; r < 7; r++ {
		// 1. Reverse the permutation using pboxInv.
		ptNew := make([]byte, 8)
		for i := 0; i < 8; i++ {
			ptNew[pbox[i]] = block[i]
		}
		block = ptNew

		// 2. Reverse the substitution using invSbox.
		for i := 0; i < 8; i++ {
			block[i] = findIndex(sbox, block[i])
		}

		// 3. Reverse the XOR with the key (XOR is its own inverse).
		for i := 0; i < 8; i++ {
			block[i] ^= key[i]
		}
	}

	// Return the recovered plaintext.
	return block
}

// go implementation of python's list.index() method, needed for decryption
func findIndex(sbox []byte, value byte) byte {
	for i, v := range sbox {
		if v == value {
			return byte(i)
		}
	}
	return 0 // Or handle error appropriately if not found
}

// this is part of an earlier approach the bruteforce, the idea was to make two separate maps for encryption and decryption and only after filling them both, start comparing them. 
// Turned out to be very inefficient despite the performance gains on workers creation and key generation.
func worker(keystart int, keyend int, resultsenc *sync.Map, resultsdec *sync.Map, wg *sync.WaitGroup) {
	defer wg.Done()
	for i := keystart; i < keyend; i++ {
		if i%1000000 == 0 {
			fmt.Printf("Worker %d: %d\n", keystart, i)
		}
		key := intToDoubleSlice(uint32(i))
		enc := encryptBlock(cyphertext, key)
		//fmt.Printf("Key: %x\n", key)
		//fmt.Printf("Encrypted: %x\n", enc)
		resultsenc.Store(string(enc), key)
		dec := decryptBlock(encrypted, key)
		resultsdec.Store(string(dec), key)
		//fmt.Printf("Decrypted: %x\n", dec)
	}
}

// each worker will iterate from keystart to keyend making valid keys from each integer, encrypt int and put it in the shared map.
// All the keys that do not contain the fixed byte needed at key[1] will be discarded before encryption, this is inefficient but better than rewriting the whole key assignment process after finding out aboud the fixed byte vulnerability.
func workerEnc(id int, keystart int, keyend int, resultsenc *sync.Map, wg *sync.WaitGroup, fixedEncKey byte) {
	defer wg.Done()
	for i := keystart; i < keyend; i++ {
		if i%200000000 == 0 {
			//fmt.Printf("Worker %d: %d / %d\n", id, i, keyend)
		}
		key := intToDoubleSlice(uint32(i))
		if key[1] != fixedEncKey {
			continue
		}
		enc := encryptBlock(cyphertext, key)
		//fmt.Printf("Key: %x\n", key)
		//fmt.Printf("Encrypted: %x\n", enc)
		resultsenc.Store(string(enc), key)
	}
}

// much like the encryption function, each worker will iterate through it's assigned keys and discard those that don't contain the correct fixed byte at key[1].
// after that, each decrypted value will be compared with the whole shared enctyption map and discarded if no match is found.
// if a match is found, it means the attack was successfull and both the needed keys will be printed.
// the process will still continue after a match is found, it will be on the user to interrupt it after noticing the printed values on the terminal.
func workerDec(id int, keystart int, keyend int, resultsenc *sync.Map, wg *sync.WaitGroup, fixedDecKey byte) {
	defer wg.Done()
	for i := keystart; i < keyend; i++ {
		if i%200000000 == 0 {
			//fmt.Printf("Worker %d: %d / %d\n", id, i, keyend)
		}
		key := intToDoubleSlice(uint32(i))
		if key[1] != fixedDecKey {
			continue
		}
		dec := decryptBlock(encrypted, key)
		//fmt.Printf("key: %x\n decrypted: %x\n", key, dec)
		//resultsdec.Store(string(dec), key)
		if value, found := resultsenc.Load(string(dec)); found {
			// If key is found, print the value.
			fmt.Printf("enc/dec: %v, aeskey1: %v, aeskey2: %v\n", dec, value, key)
		}
		//fmt.Printf("Decrypted: %x\n", dec)
	}
}
func main() {
	numWorkers := runtime.NumCPU()  // adapt the maximum number of workers to each cpu capability for maxumum efficiency
	keysnum := 4294967296 // total number of keys to bruteforce, it wil be split between each worker
	var wg sync.WaitGroup

	// 145 is the total number of fixed keys pair you need to check.
	// if you interrupt execution after checking say the first 35 pairs, you can resume the execution from there by changing the starting value in the for loop to 36
	for i := 0; i < 145; i++ {
		fmt.Printf("INIZIO RUN CON FIXEDKEY INDICE = %v\n", i)
		fixedEncKey := secondByteEncKeys[i]
		fixedDecKey := secondByteDecKeys[i]
		resultsEnc := sync.Map{} // Concurrent map to store results
		//resultsDec := sync.Map{} // Concurrent map to store results

		// Start workers
		for j := 0; j < numWorkers; j++ {
			//fmt.Printf("Starting worker %d\n", j)
			wg.Add(1)
			go workerEnc(j, j*keysnum/numWorkers, (j+1)*keysnum/numWorkers, &resultsEnc, &wg, fixedEncKey)
		}
		//fmt.Println("Waiting for workers to finish...")
		wg.Wait()
		fmt.Println("Workers finished encryption, starting decryption")

		for j := 0; j < numWorkers; j++ {
			//fmt.Printf("Starting worker %d for decryption\n", j)
			wg.Add(1)
			go workerDec(j, j*keysnum/numWorkers, (j+1)*keysnum/numWorkers, &resultsEnc, &wg, fixedDecKey)
		}

		//fmt.Println("Waiting for workers to finish...")
		wg.Wait()
		fmt.Printf("its ovaaa\n")

	}

}
