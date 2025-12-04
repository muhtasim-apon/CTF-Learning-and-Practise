# 🚩 CTF Learning Journey - Capture The Flag

Welcome to my CTF (Capture The Flag) learning repository!  This repo documents my journey from a complete beginner to becoming proficient in cybersecurity challenges.

## 📚 Table of Contents

- [What is CTF?](#what-is-ctf)
- [CTF Categories](#ctf-categories)
- [Learning Platforms](#learning-platforms)
- [Essential Tools](#essential-tools)
- [Learning Roadmap](#learning-roadmap)
- [Resources](#resources)
- [Practice Challenges](#practice-challenges)
- [Writeups](#writeups)
- [Community](#community)

---

## 🎯 What is CTF? 

Capture The Flag (CTF) is a cybersecurity competition where participants solve security-related challenges to find hidden "flags" (usually strings of text). CTFs help develop practical hacking skills in a legal, ethical environment.

### Types of CTF Competitions:
- **Jeopardy-style**: Solve independent challenges across different categories
- **Attack-Defense**: Teams defend their own systems while attacking others
- **Mixed**: Combination of both styles

---

## 🔍 CTF Categories

### 1. **Web Exploitation**
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Directory Traversal
- Authentication Bypass

### 2. **Binary Exploitation (Pwn)**
- Buffer Overflow
- Return-Oriented Programming (ROP)
- Format String Vulnerabilities
- Heap Exploitation

### 3. **Reverse Engineering**
- Assembly Analysis
- Binary Decompilation
- Malware Analysis
- Android/iOS App Analysis

### 4. **Cryptography**
- Classical Ciphers
- Modern Encryption
- Hash Functions
- RSA Attacks
- Encoding/Decoding

### 5. **Forensics**
- File Analysis
- Memory Forensics
- Network Packet Analysis
- Steganography
- Metadata Extraction

### 6. **OSINT (Open Source Intelligence)**
- Social Media Investigation
- Google Dorking
- Image Analysis
- Geolocation
- Public Records Research

### 7. **Miscellaneous**
- Programming Challenges
- Logic Puzzles
- Trivia

---

## 🌐 Learning Platforms

### For Absolute Beginners

| Platform | Description | Cost | Best For |
|----------|-------------|------|----------|
| [**OverTheWire (Bandit)**](https://overthewire.org/wargames/bandit/) | Linux command-line basics via SSH | Free | Learning Linux basics |
| [**PicoCTF**](https://picoctf.org/) | Educational CTF by Carnegie Mellon | Free | Complete beginners |
| [**TryHackMe**](https://tryhackme.com/) | Guided, browser-based labs | Free/Paid | Structured learning paths |

### Intermediate to Advanced

| Platform | Description | Cost | Best For |
|----------|-------------|------|----------|
| [**Hack The Box**](https://www.hackthebox.com/) | Realistic vulnerable machines | Free/Paid | Hands-on practice |
| [**CTFlearn**](https://ctflearn. com/) | Wide variety of challenges | Free | All skill levels |
| [**Root Me**](https://www.root-me.org/) | 400+ challenges in multiple languages | Free | Diverse challenges |
| [**CryptoHack**](https://cryptohack.org/) | Cryptography-focused challenges | Free | Learning cryptography |
| [**pwn. college**](https://pwn. college/) | Binary exploitation course | Free | Binary exploitation |

### Practice \u0026 Competition Platforms

- [**CTFtime**](https://ctftime.org/) - Calendar of upcoming CTF competitions
- [**HackTheBox CTF**](https://ctf.hackthebox.com/)
- [**Pwnable.kr**](http://pwnable.kr/) - Binary exploitation challenges
- [**Pwnable.tw**](https://pwnable.tw/) - Advanced pwn challenges
- [**RingZer0 CTF**](https://ringzer0ctf.com/)
- [**VulnHub**](https://www.vulnhub.com/) - Downloadable vulnerable VMs
- [**Crack The Lab**](https://crackthelab.org/) - Advanced simulations

---

## 🛠️ Essential Tools

### General Tools

#### Operating System
- **Kali Linux** - Penetration testing distro (recommended for beginners)
- **Parrot Security OS** - Alternative to Kali
- **BlackArch Linux** - Extensive tool collection
- **WSL (Windows Subsystem for Linux)** - For Windows users

#### Text Editors & IDEs
- **VS Code** - General-purpose editor
- **Vim/Neovim** - Terminal text editor
- **Sublime Text** - Lightweight editor

---

### Tools by Category

#### 🌐 Web Exploitation
```bash
# Browser Extensions
- Wappalyzer - Technology detection
- FoxyProxy - Proxy management
- Cookie-Editor - Cookie manipulation

# Command-Line Tools
- Burp Suite - Web vulnerability scanner
- OWASP ZAP - Open-source web app scanner
- sqlmap - SQL injection tool
- nikto - Web server scanner
- dirb/dirbuster - Directory brute-forcing
- ffuf - Fast web fuzzer
- gobuster - Directory/DNS enumeration
- wfuzz - Web application fuzzer
```

#### 🔓 Binary Exploitation & Reverse Engineering
```bash
- gdb (with pwndbg/gef/peda) - Debugger
- ghidra - NSA's reverse engineering tool
- IDA Pro/IDA Free - Disassembler
- radare2/rizin - Reverse engineering framework
- Binary Ninja - Interactive disassembler
- objdump - Binary analysis
- strings - Extract strings from binaries
- ltrace/strace - Trace library/system calls
- pwntools - Python exploit development library
- ROPgadget - ROP chain builder
```

#### 🔐 Cryptography
```bash
- CyberChef - Web-based crypto/encoding tool
- hashcat - Password cracking
- John the Ripper - Password cracker
- OpenSSL - Cryptography toolkit
- RsaCtfTool - RSA attack tool
- xortool - XOR analysis
- fcrackzip - ZIP password cracker
- hash-identifier - Hash type identification
```

#### 🔬 Forensics
```bash
- Wireshark - Network packet analyzer
- Volatility - Memory forensics
- Autopsy - Digital forensics
- Binwalk - Firmware analysis
- Foremost - File carving
- ExifTool - Metadata extraction
- Steghide - Steganography tool
- Stegsolve - Image analysis
- zsteg - PNG/BMP steganography
- file - File type identification
- xxd/hexdump - Hex viewers
- strings - Extract readable strings
```

#### 🕵️ OSINT
```bash
- Maltego - Link analysis
- theHarvester - Email/subdomain gathering
- Sherlock - Username search across platforms
- ExifTool - Image metadata
- Google Dorking techniques
- Wayback Machine - Historical website data
- Shodan - IoT device search engine
- Have I Been Pwned - Breach checking
```

#### 🌍 Network Analysis
```bash
- nmap - Network scanner
- netcat (nc) - Network utility
- tcpdump - Packet analyzer
- masscan - Fast port scanner
- Aircrack-ng - WiFi security
```

#### 🐍 Scripting & Programming
```python
# Python (most important for CTF)
- pwntools - Exploit development
- requests - HTTP library
- pycryptodome - Cryptography
- scapy - Packet manipulation
- z3-solver - Constraint solver

# Other Languages
- Bash/Shell scripting
- C/C++ - Understanding low-level code
- JavaScript - Web challenges
- Assembly - Binary exploitation
```

---

## 🗺️ Learning Roadmap

### Phase 1: Foundations (Weeks 1-4)

#### Week 1-2: Linux Basics
- [ ] Complete OverTheWire Bandit (Levels 0-20)
- [ ] Learn basic bash commands
- [ ] Understand file permissions
- [ ] Practice SSH and remote connections

#### Week 3-4: Networking Basics
- [ ] Learn TCP/IP fundamentals
- [ ] Understand HTTP/HTTPS protocols
- [ ] Study DNS, ports, and services
- [ ] Complete TryHackMe "Introductory Networking"

### Phase 2: CTF Fundamentals (Weeks 5-12)

#### Week 5-7: Web Exploitation
- [ ] TryHackMe: "OWASP Top 10"
- [ ] PicoCTF web challenges (easy)
- [ ] Learn SQL injection basics
- [ ] Understand XSS attacks
- [ ] Practice with Burp Suite

#### Week 8-10: Cryptography
- [ ] Classic ciphers (Caesar, Vigenère, substitution)
- [ ] Base64, Hex, Binary encoding
- [ ] CryptoHack intro challenges
- [ ] Learn RSA basics
- [ ] Hash identification and cracking

#### Week 11-12: Forensics
- [ ] File analysis with `file`, `strings`, `binwalk`
- [ ] Image steganography
- [ ] PicoCTF forensics challenges
- [ ] Basic Wireshark usage
- [ ] Metadata extraction

### Phase 3: Intermediate Skills (Weeks 13-24)

#### Binary Exploitation
- [ ] Learn C programming basics
- [ ] Understand memory layout (stack, heap)
- [ ] pwn.college modules
- [ ] Buffer overflow basics
- [ ] Practice with pwntools

#### Reverse Engineering
- [ ] Learn x86/x64 assembly
- [ ] Practice with Ghidra
- [ ] Crackmes. one challenges
- [ ] Analyze simple binaries
- [ ] Understand common protections (NX, PIE, ASLR)

#### OSINT
- [ ] Google Dorking techniques
- [ ] Social media investigation
- [ ] Image geolocation
- [ ] Username enumeration
- [ ] TryHackMe OSINT room

### Phase 4: Advanced Practice (Weeks 25+)

- [ ] Complete Hack The Box Starting Point
- [ ] Participate in weekly CTF competitions (CTFtime)
- [ ] Join a CTF team
- [ ] Solve retired HTB machines
- [ ] Create writeups for solved challenges
- [ ] Contribute to CTF community

---

## 📖 Resources

### YouTube Channels
- [John Hammond](https://www.youtube. com/c/JohnHammond010) - CTF walkthroughs
- [IppSec](https://www. youtube.com/c/ippsec) - Hack The Box walkthroughs
- [LiveOverflow](https://www.youtube.com/c/LiveOverflow) - Binary exploitation
- [PwnFunction](https://www.youtube.com/c/PwnFunction) - Security concepts
- [Hackersploit](https://www. youtube.com/c/HackerSploit) - Penetration testing

### Books
- **"The Web Application Hacker's Handbook"** - Web security bible
- **"Hacking: The Art of Exploitation"** - Binary exploitation
- **"Practical Malware Analysis"** - Reverse engineering
- **"The Hacker Playbook 3"** - Penetration testing
- **"Cryptography Engineering"** - Cryptography fundamentals

### Cheatsheets
- [CTF Cheatsheet by Neerajlovecyber](https://neerajlovecyber.com/ctf-cheatsheet)
- [HackTricks](https://book.hacktricks.xyz/) - Comprehensive pentesting guide
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [GTFOBins](https://gtfobins.github.io/) - Unix binaries exploitation

### Blogs & Writeups
- [CTFtime Writeups](https://ctftime. org/writeups)
- [0x00sec](https://0x00sec.org/) - Security forum
- [Reddit r/securityCTF](https://www.reddit.com/r/securityCTF/)
- [PentesterLab Blog](https://blog.pentesterlab.com/)

---

## 🏆 Practice Challenges

### Beginner-Friendly Challenges

**TryHackMe Rooms:**
- Pickle Rick
- RootMe
- Simple CTF
- Basic Pentesting
- Vulnversity

**PicoCTF Categories:**
- General Skills
- Cryptography (easy)
- Web Exploitation (easy)
- Forensics (easy)

**Hack The Box Starting Point:**
- Tier 0 machines (all)
- Tier 1 machines (selected)

### Challenge Sites
- [**Crackmes.one**](https://crackmes.one/) - Reverse engineering
- [**Cryptopals**](https://cryptopals.com/) - Cryptography
- [**Exploit. Education**](https://exploit.education/) - Binary exploitation
- [**Damn Vulnerable Web Application (DVWA)**](https://dvwa.co.uk/)

---

## 📝 Writeups

I'll document my solutions and learning process here:

```
writeups/
├── picoctf/
├── tryhackme/
├── hackthebox/
├── ctftime-competitions/
└── challenges/
    ├── web/
    ├── crypto/
    ├── forensics/
    ├── pwn/
    └── reversing/
```

### Writeup Template

```markdown
# Challenge Name

**Category:** Web/Crypto/Forensics/etc. 
**Difficulty:** Easy/Medium/Hard
**Points:** X
**Platform:** TryHackMe/HTB/etc.

## Description
[Challenge description here]

## Solution
[Step-by-step solution]

## Tools Used
- Tool 1
- Tool 2

## Flag
`flag{example_flag_here}`

## Lessons Learned
[What you learned from this challenge]
```

---

## 👥 Community

### Discord Servers
- TryHackMe Official Discord
- Hack The Box Discord
- CTF Community Servers

### Forums & Communities
- [**CTFtime Forums**](https://ctftime.org/)
- [**Reddit r/netsec**](https://www. reddit.com/r/netsec/)
- [**Reddit r/hacking**](https://www.reddit.com/r/hacking/)
- [**Stack Exchange Security**](https://security.stackexchange.com/)

### Finding CTF Teams
- CTFtime.org team finder
- University cybersecurity clubs
- Discord community servers
- Twitter #CTF hashtag

---

## 🎯 Goals \u0026 Progress

### Short-term Goals (3 months)
- [ ] Complete OverTheWire Bandit
- [ ] Solve 50 PicoCTF challenges
- [ ] Complete 10 TryHackMe rooms
- [ ] Participate in 3 live CTF competitions
- [ ] Write 20 challenge writeups

### Medium-term Goals (6 months)
- [ ] Complete TryHackMe "Offensive Pentesting" path
- [ ] Solve 20 Hack The Box machines
- [ ] Rank in top 50% in a CTF competition
- [ ] Learn one new tool category deeply

### Long-term Goals (1 year)
- [ ] Join a competitive CTF team
- [ ] Obtain a cybersecurity certification (CEH/OSCP)
- [ ] Contribute tools/scripts to CTF community
- [ ] Rank in top 10% on a major platform

---

## 📅 Study Schedule

**Daily (1-2 hours):**
- 30 minutes: Platform challenges (TryHackMe/HTB)
- 30 minutes: Tool practice or reading
- 30 minutes: Writeup documentation (optional)

**Weekly:**
- 1 live CTF competition (if available)
- 1 detailed writeup
- Review and learn from other writeups

**Monthly:**
- Assess progress and adjust learning path
- Deep dive into one new category
- Contribute to community (share knowledge)

---

## 🔗 Useful Links

### Tool Collections
- [Kali Linux Tools](https://www.kali. org/tools/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [SecLists](https://github.com/danielmiessler/SecLists) - Security wordlists

### Installation Guides
```bash
# Install common tools on Ubuntu/Debian
sudo apt update
sudo apt install -y nmap netcat wireshark burpsuite \
  python3-pip git curl wget john hashcat \
  binwalk foremost steghide exiftool

# Install pwntools (Python)
pip3 install pwntools

# Install GDB with pwndbg
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

---

## 📊 Statistics

Track your progress here:

- **Challenges Solved:** 0
- **Writeups Published:** 0
- **CTF Competitions Participated:** 0
- **Rank on TryHackMe:** N/A
- **Rank on Hack The Box:** N/A
- **Days Streak:** 0

---

## 🤝 Contributing

This is my personal learning repository, but I welcome:
- Suggestions for resources
- Tool recommendations
- Challenge recommendations
- Feedback on writeups

Feel free to open an issue or reach out! 

---

## ⚠️ Legal Disclaimer

All activities documented in this repository are for **educational purposes only** and performed in **legal, authorized environments** (CTF platforms, personal labs, authorized systems). 

**Never:**
- Attack systems without permission
- Use these skills for illegal activities
- Access unauthorized networks or data

Always practice **ethical hacking** and follow responsible disclosure. 

---

## 📜 License

This repository is licensed under the MIT License - feel free to use this as a template for your own learning journey!

---

## 🙏 Acknowledgments

Thanks to the cybersecurity community, CTF platform creators, and all the amazing people who share knowledge freely! 

**Happy Hacking!  🚩**

---

*Last Updated: December 2025*
