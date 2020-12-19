Group Name: Lee & Wang
Team Member1: Shengkai Li (sl4685)
Team Member2: Yuanming Wang (yw3472)

Clarification:
    Since our group only has two group members, Professor Steven has given us the permission to totally drop the functionalities of 
    `getcert` and `changepw`. Therefore, in this project, we only implemented `sendmsg`, `recvmsg`, and `server`. Also, we wrote a 
    bash script to generate all the clients' certificates.

Enviornment Requirments:
    Before testing our program, please make sure you have install the following requirments:
        1. sudo apt install build-essential
        2. sudo apt install libssl-dev
        3. sudo apt install openssl

Set up:
===============================================================================================================================
     RUN "bash install.sh" or "./install.sh" will set up everything for you.
===============================================================================================================================

File Layout:
    After successfully runing "bash install.sh", a directory called 'project' will be generated under the current directory.
    There are four sub-directories in 'project':
        1. ca:
                Just Like HW2, this ca directory contains all the clients' certificates and private key.
        2. input:
                This directory contains three test text files.
        3. mailbox:
                This directory can only be read/write by our 'server'. Every clients has its own subdirectories.
                Those subdirectories are used to store intermediate messages pending to read.
        4. bin:
                This directory contains three excutables: `sendmsg`, `recvmsg`, `server`.

How to RUN/TEST:
    Those three excutables must be called under project/bin directory. Also, `sendmsg`&`recvmsg` and `server` should be called
    on the same machine but two sperate windows.
===============================================================================================================================
server:
    1. The `server` takes only one argument, port Number.
       Example: "./server 8888"
    2. Our server is able to handle both 'sendmsg' and 'recvmsg' requests.
       Just make sure you call "./server portNum" before "sendmsg" or "recvmsg".
    3. After `server` successfully handle one 'sendmsg'&'recvmsg' request,
       or some error occurs, `server` will exit. You need to restart `server`
       each time when you want to `sendmsg` or `recvmsg`.
================================================================================================================================
sendmsg:
    1. The `sengmsg` read messages from stdin and takes at least four arguments.
       argument1:hostName, argument2:portNum, argument3:sender's name(who is sending msg)
       {argument4...argumentN}:list of recipient name
       Two examples of running `sendmsg`:
       a. `./sendmsg localhost 8888 unminced forfend exilic addleness`
       b. `./sendmsg localhost 8888 unminced forfend < ../input/00001`

================================================================================================================================
recvmsg:
    1. The 'recvmsg' takes three arguments:
       argument1:hostName, argument2:portNum, argument3:recipient name
       Example: "./recvmsg localhost 8866 exilic".