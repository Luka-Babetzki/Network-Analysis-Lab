# Network Analysis Lab

_**Source:** https://blueteamlabs.online/home/challenge/network-analysis-malware-compromise-e882f32908_

## Objective

The objective of this lab is to investigate a suspected malware compromise by analysing a network capture (PCAP) file. The scenario involves identifying how an infection occurred, tracing the command-and-control communication, and uncovering the delivery and payload mechanisms used in the attack. This exercise simulates a real-world Security Operations Center (SOC) workflow in responding to malware-related alerts, with a focus on network forensics and threat hunting.

### Skills Learned

- <...>
- <...>
- <...>
- <...>
- <...>

### Tools Used

- Wireshark
- VirtusTotal
- Zui

---
## Steps

### Scenario

A SOC Analyst at Umbrella Corporation is going through SIEM alerts and sees the alert for connections to a known malicious domain. The traffic is coming from Sara’s computer, an Accountant who receives a large volume of emails from customers daily. Looking at the email gateway logs for Sara’s mailbox there is nothing immediately suspicious, with emails coming from customers. Sara is contacted via her phone and she states a customer sent her an invoice that had a document with a macro, she opened the email and the program crashed. The SOC Team retrieved a PCAP for further analysis.

---

### 1. Wireshark

#### 1.1 Preliminary Analysis

I began the analysis by opening the provided PCAP file in Wireshark and navigating to **Statistics > Capture File Properties**. This gave me an overview of the capture timeline. 

- First packet: 2018-11-27 08:30:12 UTC
- Last packet: 2018-11-27 09:12:16 UTC
- Total capture duration: ~42 minutes

_(Note: Verifying the timeframe early in the investigation is best practise when confirming that the PCAP was relevant to the suspected activity window)_

Next, I examined the protocol hierarchy via **Statistics > Protocol Hierarchy**. This view allowed me to identify which network protocols were present and their proportional usage across the capture. It’s a useful step to identify unexpected or suspicious protocols that might indicate malicious behavior.

To better understand the key communication flows in the traffic, I looked at **Statistics > Conversations > IPv4**, sorting the results by byte count in descending order. This revealed that the internal host 10.11.27.101 was communicating primarily with three external IP addresses: 

- 95.181.198.231
- 176.32.33.108
- 83.166.247.211

These addresses became the focus of my subsequent investigation.

#### 1.2 Investigation

First, I focused on IP address `95.181.198.231`. On the Packet List Pane, I noticed that packet 1 contained a DNS request to a domain called: klychenogg.com, followed by a DNS response in packet 2 that refers to the same IP address and domain name. Next, I searched VirtusTotal for this domain name, revealing that 10 vendors had flagged this domain as malicious. By using a follow up search using the IP address, I found no malicious indicators however revealing that the IP is registered in Russia. _(Note. This can be an indicator of suspicious activity if the client, who this PCAP file belongs to, does not do business with Russia)_

I decided to dig deeper and search for the first HTTP GET request from the `95.181.198.231` IP address by **Right-clicking Packet 6 > Follow > HTTP Stream**. This revealed a HTTP GET request for the file: `spet10.spr` which contained a `MZ header` displaying: "This program cannot be run in DOS mode". This is a clear indication of a portable executable, most likely a .exe, and could suggest potential malware delivery. _(Note. MZ marks a file as a DOS-compatible executable. Despite modern .exe files being portable executables, they still use MZ headers for backward compatability)_

To narrow the scope, I applied a HTTP filter associated with `95.181.198.231`, displayed as: `(_ws.col.protocol=="HTTP")&&(ip==95.181.198.231)`. This results in only two packets, with packet 911 showing another GET request; this time for a `.rar file`. While the packet contained no damning activity, I made note of the timestamp in case it was required later.


Next, I shifted my focus to the second external IP address: `176.32.33.108`. I applied the filter `ip.addr==176.32.33.108`. In initial packets displayed the expected TCP handshake (SYn, SYN-ACK, ACK), followed by a GET request for a resource under `/images`. Following the HTTP stream revealed that the host domain was `cochrimato.com`. A VirusTotal showed this domain had been flagged as malicious by 7 vendors. _(Note. Although the IP itself was clean, it was also registered in Russia)_

Finally, I investigated the third IP address of `83.166.247.211`, using the same `ip.addr` filter. This IP also showed a clean TCP handshake, followed immediately by a TLS Client Hello in packet 757. Within this handshake, I extracted the Server Name Indication `(SNI) field`, which revealed the domain `mautergase.com`. I reviewed this domain and IP on VirusTotal; both were flagged by 2 vendors each and also appeared to be hosted in Russia. To broaden my view, I right-clicked the handshake field in packet 757 and prepared a display filter to view all Client Hello messages throughout the capture.

#### 1.3 Event Timeline and Observations

Below is a timeline of key events observed during the investigation. The "Tag" column uses emojis to distinguish activity between the three suspicious IP addresses for easier visual correlation.

| Tag                |  Time (UTC)   | Packet No.  | IP Address | Domain / Host | Description |
|--------------------|---------------|-------------|------------|---------------|-------------|
| 🔴 | 2018-11-27 16:30:12 | 1, 2 | 95.181.198.231 | klychenogg.com | DNS query and response |
| 🔴 | 2018-11-27 16:30:15 | 6 | 95.181.198.231 | — | GET request for spet10.spr (.exe) |
| 🟡 | 2018-11-27 16:30:37 | 288 | 176.32.33.108 | cochrimato.com | Get request for /images |
| 🔵 | 2018-11-27 16:31:52 | 754-756 | 83.166.247.211 | — | TCP handshake |
| 🔵 | 2018-11-27 16:31:52 | 757-758 | 83.166.247.211 | mautergase.com | TLS handshake (SNI: mautergase.com) |
| 🔴 | 2018-11-27 16:38:39 | 911 | 95.181.198.231 | — | GET request for .rar file |


### 2. Zui

#### 2.1 Investigation

<...>

#### 2.2 Observations

<...>

---
## Lab Answers

1). **What’s the private IP of the infected host?** _Answer_

2). **What’s the malware binary that the macro document is trying to retrieve?** _Answer_

3). **From what domain HTTP requests with GET /images/ are coming from?** _Answer_

4). **The SOC Team found Dridex, a follow-up malware from Ursnif infection, to be the culprit. The customer who sent her the macro file is compromised. What’s the full URL ending in .rar where Ursnif retrieves the follow-up malware from?** _Answer_

5). **What is the Dridex post-infection traffic IP addresses beginning with 185.?** _Answer_

---
## Lessons Learned

- 
- 
- 
- 
- 
