# TLS(SSL) Message System

An **_encrypted_** client & server message system.  

Team member (ordered alphabetically by last name):
- Shengkai Li (sl4685@columbia.edu)
- Yuanming Wang (yw3472@columbia.edu)  

## Enviornment Requirements & Set up
Please make sure you have followed the following steps to set up enviornment requirements:
1. sudo apt install build-essential
2. sudo apt install libssl-dev
3. sudo apt install openssl
4. sudo apt install firejail (for sanboxing)

## Build
We Provided a bash script 'install.sh', which helps users to generate all the excutables, private/public key pairs, certificate, etc.

## File Layout

After successfully runing "bash install.sh", a directory called 'project' will be generated under the current directory.

There are four sub-directories in 'project':
### ca:  
- CA directory contains all the clients' certificates and private key.
### input:
- This directory contains four test text files.
### mailbox:
- This directory can only be read/write by our 'server'. Every clients has its own subdirectories.
- Those subdirectories are used to store intermediate messages pending to read.
### bin:
- This directory contains three excutables: `sendmsg`, `recvmsg`, `server`. 
- Excutables must be called under project/bin directory. Also, `sendmsg`, `recvmsg` and `server` should be called on the same machine but two sperate windows.

## How to RUN/TEST

### server
-  The `server` takes only one argument, port Number  
   Example: "./server 8888"
-  Our server is able to handle both 'sendmsg' and 'recvmsg' requests.  
   Just make sure you fire up the server (call "./server portNum") before "sendmsg" or "recvmsg"

### sendmsg
-  The `sengmsg` read messages from stdin and takes at least four arguments
    -   Argument_1: Hostname
    -   Argument_2: Port Number
    -   Argument_3: Sender's Name
    -   {Argument_4...Argument_n): List of recipient name
-  Two Examples  
    -  `./sendmsg localhost 8888 unminced forfend exilic addleness`
    -  `./sendmsg localhost 8888 unminced forfend < ../input/00001`

### recvmsg
- The 'recvmsg' takes three arguments:
    -  Argument_1: Hostname
    -  Argument_2: Port Number
    -  Argument_3: Recipient Name
- Example
    -  `./recvmsg localhost 8866 exilic`

## Sandbox and Security Decision

we put the `sendmsg` and `recvmsg` into the sandboxed sections and leave the server unsandboxed. This means that the `server` has the **_highest privilege_**. We believe the `server` should be able to access all certificates and the mailbox, which means basically everything in our project. Therefore, there is no reason to put the server into the sandbox section

### Sandbox
We use **_[firejail](https://firejail.wordpress.com/)_** to create the sandboxing. We do not use specific file permission because we believe we have everything covered in the sandboxed sections.   

In the `sandbox.sh`, we set up `blacklist` for both sendmsg and recvmsg. Elements in `blacklist` are thoes files/directories cannot be access by client side. To put these two excutables into sandbox, all you have to do is to call `sendmsg` or `recvmsg` with 'firejail`

Two Examples:
-  `firejail ./sendmsg localhost 8888 forfend repine`
-  `firejail ./recvmsg localhost 8888 repine`

