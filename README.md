# Security Exercise (GOT Injection on running process)



https://github.com/user-attachments/assets/6213e335-43cf-46d5-9d81-e45b9756dee5


## Disclaimer:
This program was built in a ubuntu vm running on mac. Therefore was compiled on aarch64 and will not run on x86_64 computers.
To fix this issue i'd need to use the relevant X86_64 libraries but due to time restrictions and me not having a x86_64 device at reach to run a vm on to make a cross-compatable machine, this exec will only work on aarch64 machines :/


# Build Instructions:

## Process
```
cd ./process/cmake-build-debug
```
### Payload compilation
Run `ninja -v payload`. Output will be `/tmp/inject.so`

### Process compilation
Run `ninja -v process`. Output will be `./process`


## Web Server
```
cd ../../web-server/cmake-build-debug
```
### Web Server compilation
Run `ninja -v web_server`. Output will be `./web_server`

## Client mock
```
cd ../../client-mock/cmake-build-debug
```
### Client mock compilation
Run `ninja -v client_mock`. Output will be `./client_mock`

# Run Instructions:
Follow steps:

1. Compile all code
2. run `web-server/cmake-build-debug/web_server`
3. run `sudo process/cmake-build-debug/process`    <-- Malicous payload. Must be run with ROOT!
4. run `client-mock/cmake-build-debug/client_mock`

Enjoy!





