# Exercise Requirements

## The Assignment:
I have root on a linux device & it has a running web server on port 443.
My goal is to open and maintain a session over TCP port 443 without it being suspicious to the device owner or the web server's clients.

## Assignment Boundaries (Requirments/Restrictions):

### Secrecy/Network traffic must be legit!
 - Full TCP 3 way handshake (No partial handshakes)
 - No RST or closing connections
 - All packets must look legit (No Header/Flag/Id/Token Injection)

### Linux Kernel has basic functionality
 - Kernel is pretty old (2.6.x)
 - Can't use Iptables, EBPF or any kernel routing/modification/dropping techniques to network traffic (Later clarified solutions in this space would be very hard to implement in a generic way)
 - Use of Raw sockets isn't allowed (They are a readonly solution, all session traffic will still be visible to web server)

## Solution Requirements
- Must be generic (should work on varios kernal versions)
- Device source port traffic must be 443
- Device cannot initiate connection (No Reverse proxies..) (added later)
- The client's IP that initiates a session over port 443 is unknown ahead of time (added later)


# Thinking Process

I Started by understanding what the task paramaters allow/disallow and made a list:

## Facts
- A single socket can connection to a tuple `<Protocol, IP, PORT> (TCP, IP, 443)`
    - Even with root access.
    - Each Protocol has it's own "Stack" (TCP Stack, UDP Stack..). Each Stack has it's own `IP:PORT` tuple.  
- In **linux kernel 2.6.x a single socket tuple** exists.
    - on **linux kernel 3.9+** SO_REUSEPORT exists (basically a load balancer for the port. Doesn't solve the problem since some of the traffic will still go to the web server but it's a foot in the right direction).
- A process can listen on `PORT < 1024` if it has root privledges or CAP_NET_BIND_SERVICE capabilities. **Good for us as we have root access!**
- Even root can't modify a socket's data (write, delete, skip, route..) to a specific process.
    - The kernel owns the TCP stack in kernel space (each socket has private receive/transmit queues protected in kernel memory).
    - The socket is owned by the process in user space.
- A Long lived session (like requested) can be closed by network intercepts (Such as FWs) if their isn't any traffic in the session (Keep-alives needed).
    - For protocols that aren't TCP based, usually some sort of ping needs to be sent to keep the connection alive. But this ofcourse doesn't help too much since we must only use TCP..

## Possible Solutions

After scouring the internet for almost a day, I started look for solution posibilities, some could be legit (by Assignment boundaries) and some were borderline.

### Solution #1
Using a protocol that isn't TCP, maintain a session over port 443 (Each protocal has a different network stack).
**Relevant protocols would be:**
- QUIC (UDP Based) - Encrypted, Long lived sessions, very reliable (Used by HTTP/3) - my preffered choice.
- SCTP (Stream control transmission protocol) - Similar to TCP, can support Ordered delivery, Long lived sessions. No built in encryption. Poor real world adaption, most network devices will reject it.

**I Dropped this solution** because after asking about the solution legitimacy, additional Assignment boundaries were added (TCP only traffic).

### Solution #2
Similar to solution 2, what if i were to add another virtual network adapter creating another ip for the device and traffic my session over that? 
- Would be over TCP
- Would allow legit traffic

**I Dropped this solution** because after asking about the solution legitimacy, was hinted this wasn't in assignment boundaries..

### Solution #3
This solution would be legal but initially i had no clue how to pull it off. A few evolutions later this solution would be my final solution.

#### What i know at this point:
- I can't somehow manipulate the traffic
- All assignment boundaries lead to legit, plain old TCP over port 443. No weird stuff..
- Any kernel modifications/updates/rules.. weren't relevant

So the only possible idea i had at this point was something in user space..
maybe a processs that acts like a proxy, passing legit requests to the web server, keeping session connections to itself.

#### But this idea has many problems to solve:
- How would my process get access to the socket on port 443?
- How would i prevent the currently running web server from receiving connections?
- Proxied traffic from my process to the server would have a source ip of localhost


Then i got hinted:
- The proxy solution "was interesting"
- Learn about FDs, procfs.

**And 3 hours later.. i had my first legit & almost in assignment boundaries solution!**
After learning about both FDs & Procfs and experimenting live on a linux computer, i quickly found out a few very relevant facts:
- procfs was a virtual file system that contained info about running processes. It's basically an interace to kernel data structures.
- With root, you can get access to the procfs /proc directory - **Very good as we have root access**
- FD (File descriptor) is a file in procfs representing an open file, socket or other I/O resource withing a specific process. This file is represented as int (File name in procfs).
    - Listed under /proc/{PID}/fd/{FD} as symlinks (for debug purposes)

- INode is a data structure used by the filesystem to store metadata about a file
- Socket FD's work like so:
    - Process -> FD -> Open file object -> Inode -> Socket (Network state)
So basically i could find out 
### Solution #4



Hinted:
- Learn about Ptrace, Syscalls, 