### Assignment 3 README

The program implements encryption using the **PRESENT-80 block cipher** with a **bitsliced implementation**.
It reads plaintext blocks from a file, encrypts them using a provided 80-bit key (from a file), and writes the ciphertext blocks to an output file.

* Block size: **64 bits**
* Key size: **80 bits**
* Cipher: **PRESENT-80**
* Input format: **hexadecimal text**

---

# Build

Compile with a standard C compiler.

Example:

```bash
gcc -O2 -std=c11 main.c -o present80
```

---

# Usage

```bash
./present80 <key_file> <plaintext_file> <ciphertext_file>
```

Example:

```bash
./present80 key.txt plaintext.txt ciphertext.txt
```

---

# Key File Format

The key file must contain **exactly one line** with **20 hexadecimal characters** (80 bits).

Example:

```
00000000000000000000
```

---

# Plaintext File Format

The plaintext file must contain **one 64-bit block per line**, written as **16 hexadecimal characters**.

Example:

```
FFFFFFFFFFFFFFFF
0000000000000000
0000000000000000
0000000000000000
```

Each line represents one 64-bit block.

---

# Output Ciphertext Format

The output file uses the **same format as the plaintext file**:

* One block per line
* 16 hexadecimal characters

Example:

```
5579C1387B228445
E72C46C0F5945049
...
```

---

# Sample Data

Example plaintext input:

[https://xiaoluhou.github.io/Teaching_material/CRAESS//Assignments//sampleplaintext.txt](https://xiaoluhou.github.io/Teaching_material/CRAESS//Assignments//sampleplaintext.txt)

Expected ciphertext output:

[https://xiaoluhou.github.io/Teaching_material/CRAESS//Assignments//sampleciphertext.txt](https://xiaoluhou.github.io/Teaching_material/CRAESS//Assignments//sampleciphertext.txt)