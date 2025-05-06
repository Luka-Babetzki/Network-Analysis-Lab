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

<...>

#### 1.3 Event Timeline and Observations

<...>

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
