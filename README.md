# Awesome Hacking Tools
A collective selection of hacking tools for hackers, pentesters and researchers.

## Table Of Contents
* [Android Security](#Android-Security)
* [Application Security](#Application-Security)
* [Asset Discovery](#Asset-Discovery)
* Bug Bounty
* CTF
* Cyber Skills
* DevSecOps
* Embedded and IoT Security
* Exploit Development
* Fuzzing
* Hacking
* Hacking RESOURCES
* Honeypots
* Incident Response
* IoT Hacks
* Mainframe Hacking
* Malware Analysis
* OSINT
* OSX And iOS Security
* Pcaptools
* Pentest
* PHP Security
* Red Teaming
* Reversing
* Sec Talks
* Sec LIsts
* Security
* Serverless Security
* Social Engineering
* Static Analysis
* Threat Intelligence
* Vehicle Security
* Vulnerability Research
* Website Hacking
* Windows Exploitation
* WiFi Arsenal
* YARA
* Hacker Roadmaps

## Android Security
A collection of Android Security related Resources.

### Online Analyzers
* [Appknox](https://www.appknox.com/) - A platform to help you build safe and secure mobile systems **(PAID)**
* [AVC UnDroid](https://undroid.av-comparatives.org/) - Select an APK to be analysed using AVC unDroid. **(FREE)**
* [Virus Total](https://www.virustotal.com/gui/home/upload) - Analyse a file, URL or search using the tool online. **(FREE)**
* [App Ray](https://app-ray.co/) - An automated mobile application security testing. Identifying vulnerabilities and more.  **(PAID)**
* [AppCritique](https://www.boozallen.com/expertise/products/appcritique.html) - Upload your Android APKs & iOS Apps and receive comprehensive free security assessments. **(FREE & PAID)**
* [NowSecure Lab Automated](https://www.nowsecure.com/blog/2016/09/19/announcing-nowsecure-lab-automated/) - Enterprise tool for mobile app security testing both Android and iOS mobile apps. Lab Automated features dynamic and static analysis on real devices in the cloud to return results in minutes. **(6 MONTHS FREE)**
* [AMAaaS](https://amaaas.com/) - Free Android Malware Analysis Service. A baremetal service features static and dynamic analysis for Android applications. A product of MalwarePot. **(FREE)**
* [App Detonator](https://appdetonator.run/) - Detonate APK binary to provide source code level details including app author, signature, build and manifest information. **3 Analysis/day free quota**.
* [BitBann](https://malab.bitbaan.com/en/home) - Analyse files or via URL, maximum upload is 20 MB - You can login to maximise size **(FREE)**

### Static Analysis Tools

* [Androwarn](https://github.com/maaaaz/androwarn/) - detect and warn the user about potential malicious behaviours developed by an Android application.
* [Android Decompiler](https://www.pnfsoftware.com/) - Decompile and debug, breakdown and analyse files. **Demo Available**
* [PSCout](http://pscout.csl.toronto.edu/) - A tool that extracts the permission specification from the Android OS source code using static analysis
* [SmaliSCA](https://github.com/dorneanu/smalisca) - Smali Static Code Analysis
* [CFGScanDroid](https://github.com/douggard/CFGScanDroid) - Scans and compares CFG against CFG of malicious applications
* [Madrolyzer](https://github.com/maldroid/maldrolyzer) - Extracts actionable data like C&C, phone number etc.
* [SPARTA](https://www.cs.washington.edu/sparta) - Verifies (proves) that an app satisfies an information-flow security policy; built on the [Checker Framework](https://types.cs.washington.edu/checker-framework/)
* [RiskInDroid](https://github.com/ClaudiuGeorgiu/RiskInDroid) - A tool for calculating the risk of Android apps based on their permissions, with online demo available.
* [SUPER](https://github.com/SUPERAndroidAnalyzer/super) - Secure, Unified, Powerful and Extensible Rust Android Analyzer
* [ClassyShark](https://github.com/google/android-classyshark) - Standalone binary inspection tool which can browse any Android executable and show important infos.
* [StaCoAn](https://github.com/vincentcox/StaCoAn) - Crossplatform tool which aids developers, bugbounty hunters and ethical hackers performing static code analysis on mobile applications. This tool was created with a big focus on usability and graphical guidance in the user interface.
* [JAADAS](https://github.com/flankerhqd/JAADAS) - Joint intraprocedure and interprocedure program analysis tool to find vulnerabilities in Android apps, built on Soot and Scala
 
### Application Vulnerability Scanners
*  [QARK](https://github.com/linkedin/qark/) - QARK by LinkedIn is for app developers to scan app for security issues (Updated 17 months ago)
*  [AndroBugs](https://github.com/AndroBugs/AndroBugs_Framework) - A Framework for Android vulnerability anslysis to find potential security vulernabilities. (Updated 5 years ago)
*  [Nogotofail](https://github.com/google/nogotofail) - Network security testing tool for developers and security researchers (Updated 5 months ago)

### Dynamic Analysis Tools
* [Androidl4b](https://github.com/sh4hin/Androl4b) - A Virtual Machine For Assessing Android applications, Reverse Engineering and Malware Analysis
* [Mobile-Security-Framework MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) - Mobile Security Framework is an intelligent, all-in-one open source mobile application (Android/iOS) automated pen-testing framework capable of performing static, dynamic analysis and web API testing
* [AppUse](https://appsec-labs.com/AppUse/) - Custom build platform for security testing ($200 1 year License)
* [Xposed](https://forum.xda-developers.com/xposed/xposed-installer-versions-changelog-t2714053) - equivalent of doing Stub based code injection but without any modifications to the binary
* [Inspeckage](https://github.com/ac-pm/Inspeckage) - Android Package Inspector - dynamic analysis with api hooks, start unexported activities and more. (Xposed Module)
* [Android Hooker](https://github.com/AndroidHooker/hooker) - Dynamic Java code instrumentation (requires the Substrate Framework)
* [ProbeDroid](https://github.com/ZSShen/ProbeDroid) - Dynamic Java code instrumentation
* [Android Tamer](https://androidtamer.com/) - Virtual / Live Platform for Android Security Professionals
* [DECAF](https://github.com/sycurelab/DECAF) - Dynamic Executable Code Analysis Framework based on QEMU (DroidScope is now an extension to DECAF)
* [CuckooDroid](https://github.com/idanr1986/cuckoo-droid) - Android extension for Cuckoo sandbox
* [Mem](https://github.com/MobileForensicsResearch/mem) - Memory analysis of Android (root required)
* [AuditdAndroid](https://github.com/nwhusted/AuditdAndroid) – Android port of auditd, not under active development anymore
* [Android Security Evaluation Framework](https://code.google.com/p/asef/) - not under active development anymore
* [Aurasium](https://github.com/xurubin/aurasium) – Practical security policy enforcement for Android apps via bytecode rewriting and in-place reference monitor.
* [Appie](https://manifestsecurity.com/appie/) - Appie is a software package that has been pre-configured to function as an Android Pentesting Environment. It is completely portable and can be carried on USB stick or smartphone. This is a one stop answer for all the tools needed in Android Application Security Assessment and an awesome alternative to existing virtual machines.
* [StaDynA](https://github.com/zyrikby/StaDynA) - A system supporting security app analysis in the presence of dynamic code update features (dynamic class loading and reflection). This tool combines static and dynamic analysis of Android applications in order to reveal the hidden/updated behavior and extend static analysis results with this information.
* [Vezir Project](https://github.com/oguzhantopgul/Vezir-Project) - Virtual Machine for Mobile Application Pentesting and Mobile Malware Analysis
* [MARA](https://github.com/xtiankisutsa/MARA_Framework) - Mobile Application Reverse engineering and Analysis Framework
* [Taintdroid](http://appanalysis.org) - requires AOSP compilation
* [ARTist](https://artist.cispa.saarland) - A flexible open source instrumentation and hybrid analysis framework for Android apps and Android's java middleware. It is based on the Android Runtime's (ART) compiler and modifies code during on-device compilation.
* [AndroPyTool](https://github.com/alexMyG/AndroPyTool) - A tool for extracting static and dynamic features from Android APKs. It combines different well-known Android apps analysis tools such as DroidBox, FlowDroid, Strace, AndroGuard or VirusTotal analysis.
* [Runtime Mobile Security (RMS)](https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security) - A powerful web interface that helps you to manipulate Android and iOS Apps at Runtime

### Reverse Engineering
* [Smali/Baksmali](https://github.com/JesusFreke/smali) – Apk decompilation
* [Emacs syntax coloring for smali files](https://github.com/strazzere/Emacs-Smali)
* [Vim syntax coloring for smali files](http://codetastrophe.com/smali.vim)
* [Androguard](https://github.com/androguard/androguard) – Powerful, integrates well with other tools
* [Apktool](https://ibotpeaches.github.io/Apktool/) – Really useful for compilation/decompilation (uses smali)
* [Android Framework for Exploitation](https://github.com/appknox/AFE)
* [Bypass signature and permission checks for IPCs](https://github.com/iSECPartners/Android-KillPermAndSigChecks)
* [Android OpenDebug](https://github.com/iSECPartners/Android-OpenDebug) – Make any application on device debuggable (using cydia substrate).
* [Dex2Jar](https://github.com/pxb1988/dex2jar) - Dex to jar converter
* [Enjarify](https://github.com/google/enjarify) - Dex to jar converter from Google
* [Frida](https://www.frida.re/) - Inject javascript to explore applications and a [GUI tool](https://github.com/antojoseph/diff-gui) for it
* [Indroid](https://bitbucket.org/aseemjakhar/indroid) – Thread injection kit
* [Jad]( https://varaneckas.com/jad/) - Java decompiler
* [JD-GUI](https://github.com/java-decompiler/jd-gui) - Java decompiler

### Fuzz Testing
* [Radamsa Fuzzer](https://github.com/anestisb/radamsa-android) - Android port of [Radamsa](https://gitlab.com/akihe/radamsa)
* [Honggfuzz](https://github.com/google/honggfuzz) - A security oriented, feedback-driven, evolutionary, easy-to-use fuzzer with interesting analysis options.
* [An Android port of the melkor ELF fuzzer](https://github.com/anestisb/melkor-android) - An ELF File Format Fuzzer
* [MMFA](https://github.com/fuzzing/MFFA) - Media Fuzzing Framework for Android
* [AndroFuzz](https://github.com/jonmetz/AndroFuzz) - A simple file format fuzzer for android. Used by me to fuzz pdf readers, but should work for any file format.
 
### Application Repackaging Detectors
* [FSquaDRA](https://github.com/zyrikby/FSquaDRA) - A tool for detection of repackaged Android applications based on app resources hash comparison.

### Market Crawlers
* [Google play crawler (Java)](https://github.com/Akdeniz/google-play-crawler)
* [Google play crawler (Python)](https://github.com/alessandrodd/googleplay_api)
* [Google play crawler (Node)](https://github.com/dweinstein/node-google-play) - get app details and download apps from official Google Play Store.
* [Aptoide downloader (Node)](https://github.com/dweinstein/node-aptoide) - download apps from Aptoide third-party Android market
* [Appland downloader (Node)](https://github.com/dweinstein/node-appland) - download apps from Appland third-party Android market
* [Apkpure](https://apkpure.com/) - Online apk downloader. Provides also an own app for downloading.


### Misc Tools
* [AXMLPrinter2](http://code.google.com/p/android4me/downloads/detail?name=AXMLPrinter2.jar) - To convert binary XML files to human-readable XML files
* [adb autocomplete](https://github.com/mbrubeck/android-completion) - This is a Bash completion script
* [Dalvik opcodes](http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html)
* [ExploitMe Android Labs](http://securitycompass.github.io/AndroidLabs/setup.html) - For practice
* [Android InsecureBank](https://github.com/dineshshetty/Android-InsecureBankv2) - For practice
* [mitmproxy](https://github.com/mitmproxy/mitmproxy) - This repository contains the mitmproxy and pathod projects
* [dockerfile/androguard](https://github.com/dweinstein/dockerfile-androguard) - Docker file for building androguard dependencies w/ an optional interactive shell environment.
* [Android Vulnerability Test Suite](https://github.com/AndroidVTS/android-vts) - Android-vts scans a device for set of vulnerabilities
* [AppMon](https://github.com/dpnishant/appmon)- AppMon is an automated framework for monitoring and tampering system API calls of native macOS, iOS and android apps. It is based on Frida.
* [Internal Blue](https://github.com/seemoo-lab/internalblue) - Bluetooth experimentation framework based on Reverse Engineering of Broadcom Bluetooth Controllers
* [Android Device Security Database](https://www.android-device-security.org/client/datatable) - Database of security features of Android devices

### Research Papers
* [Exploit Database](https://www.exploit-db.com/papers/)
* [Android security related presentations](https://github.com/jacobsoo/AndroidSlides)
* [A good collection of static analysis papers](https://tthtlc.wordpress.com/2011/09/01/static-analysis-of-android-applications/)

### Books
* [SEI CERT Android Secure Coding Standard](https://www.securecoding.cert.org/confluence/display/android/Android+Secure+Coding+Standard)
### Others
* [OWASP Mobile Security Testing Guide Manual](https://github.com/OWASP/owasp-mstg)
* [Doridori/Android-Security-Reference](https://github.com/doridori/Android-Security-Reference)
* [Android app security checklist](https://github.com/b-mueller/android_app_security_checklist)
* [Mobile App Pentest Cheat Sheet](https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet)
* [Android Reverse Engineering 101 by Daniele Altomare (Web Archive link)](http://web.archive.org/web/20180721134044/http://www.fasteque.com:80/android-reverse-engineering-101-part-1/)

### Vulnerabilities
#### List
* [Android Security Bulletins](https://source.android.com/security/bulletin/)
* [Android's reported security vulnerabilities](https://www.cvedetails.com/vulnerability-list/vendor_id-1224/product_id-19997/Google-Android.html)
* [Android Devices Security Patch Status](https://kb.androidtamer.com/Device_Security_Patch_tracker/)
* [AOSP - Issue tracker](https://code.google.com/p/android/issues/list?can=2&q=priority=Critical&sort=-opened)
* [OWASP Mobile Top 10 2016](https://www.owasp.org/index.php/Mobile_Top_10_2016-Top_10)
* [Exploit Database](https://www.exploit-db.com/search/?action=search&q=android) - click search
* [Vulnerability Google Doc](https://docs.google.com/spreadsheet/pub?key=0Am5hHW4ATym7dGhFU1A4X2lqbUJtRm1QSWNRc3E0UlE&single=true&gid=0&output=html)
* [Google Android Security Team’s Classifications for Potentially Harmful Applications (Malware)](https://source.android.com/security/reports/Google_Android_Security_PHA_classifications.pdf)

#### Malware
* [Androguard - Database Android Malwares wiki](https://code.google.com/p/androguard/wiki/DatabaseAndroidMalwares)
* [Android Malware Github repo](https://github.com/ashishb/android-malware)
* [Android Malware Genome Project](http://www.malgenomeproject.org/policy.html) - contains 1260 malware samples categorized into 49 different malware families, free for research purpose.
* [Contagio Mobile Malware Mini Dump](http://contagiominidump.blogspot.com)
* [VirusTotal Malware Intelligence Service](https://www.virustotal.com/en/about/contact/) - powered by VirusTotal, not free
* [Drebin](https://www.sec.cs.tu-bs.de/~danarp/drebin/)
* [Kharon Malware Dataset](http://kharon.gforge.inria.fr/dataset/) - 7 malwares which have been reverse engineered and documented
* [Android Adware and General Malware Dataset](https://www.unb.ca/cic/datasets/android-adware.html)
* [Android PRAGuard Dataset](http://pralab.diee.unica.it/en/AndroidPRAGuardDataset) - The dataset contains 10479 samples, obtained by obfuscating the MalGenome and the Contagio Minidump datasets with seven different obfuscation techniques.
* [AndroZoo](https://androzoo.uni.lu/) - AndroZoo is a growing collection of Android Applications collected from several sources, including the official Google Play app market.

#### Bounty Programs
* [Android Security Reward Program](https://www.google.com/about/appsecurity/android-rewards/)

#### How to report Security Issues
* [Android - reporting security issues](https://source.android.com/security/overview/updates-resources.html#report-issues) - Reporting issues via Android
* [Android Reports and Resources](https://github.com/B3nac/Android-Reports-and-Resources) - List of Android Hackerone disclosed reports and other resources

## Application Security

### Application Security Learning Resources

  * [How to Safely Generate a Random Number](#how-to-safely-generate-a-random-number-2014) (2014)
  * [Salted Password Hashing - Doing it Right](#salted-password-hashing-doing-it-right-2014) (2014)
  * [A good idea with bad usage: /dev/urandom](#a-good-idea-with-bad-usage-devurandom-2014) (2014)
  * [Why Invest in Application Security?](#why-invest-in-application-security-2015) (2015)
  * [Be wary of one-time pads and other crypto unicorns](#be-wary-of-one-time-pads-and-other-crypto-unicorns-2015) (2015)
  * [Web Application Hacker's Handbook](https://github.com/paragonie/awesome-appsec/blob/master/#-web-application-hackers-handbook-2011) (2011) 
  * [Cryptography Engineering](https://github.com/paragonie/awesome-appsec/blob/master/#-cryptography-engineering-2010) (2010) 
  * [Securing DevOps](https://github.com/paragonie/awesome-appsec/blob/master/#-securing-devops-2018) (2018) 
  * [Gray Hat Python: Programming for Hackers and Reverse Engineers](https://github.com/paragonie/awesome-appsec/blob/master/#-gray-hat-python-programming-for-hackers-and-reverse-engineers-2009) (2009) 
  * [The Art of Software Security Assessment: Identifying and Preventing Software Vulnerabilities](https://github.com/paragonie/awesome-appsec/blob/master/#-the-art-of-software-security-assessment-identifying-and-preventing-software-vulnerabilities-2006) (2006) 
  * [C Interfaces and Implementations: Techniques for Creating Reusable Software](https://github.com/paragonie/awesome-appsec/blob/master/#-c-interfaces-and-implementations-techniques-for-creating-reusable-software-1996) (1996) 
  * [Reversing: Secrets of Reverse Engineering](https://github.com/paragonie/awesome-appsec/blob/master/#-reversing-secrets-of-reverse-engineering-2005) (2005) 
  * [JavaScript: The Good parts](https://github.com/paragonie/awesome-appsec/blob/master/#-javascript-the-good-parts-2008) (2008) 
  * [Windows Internals: Including Windows Server 2008 and Windows Vista, Fifth Edition ](https://github.com/paragonie/awesome-appsec/blob/master/#-windows-internals-including-windows-server-2008-and-windows-vista-fifth-edition-2007) (2007) 
  * [The Mac Hacker's Handbook](https://github.com/paragonie/awesome-appsec/blob/master/#-the-mac-hackers-handbook-2009) (2009) 
  * [The IDA Pro Book: The Unofficial Guide to the World's Most Popular Disassembler](https://github.com/paragonie/awesome-appsec/blob/master/#-the-ida-pro-book-the-unofficial-guide-to-the-worlds-most-popular-disassembler-2008) (2008) 
  * [Internetworking with TCP/IP Vol. II: ANSI C Version: Design, Implementation, and Internals (3rd Edition)](https://github.com/paragonie/awesome-appsec/blob/master/#-internetworking-with-tcpip-vol-ii-ansi-c-version-design-implementation-and-internals-3rd-edition-1998) (1998) 
  * [Network Algorithmics,: An Interdisciplinary Approach to Designing Fast Networked Devices](https://github.com/paragonie/awesome-appsec/blob/master/#-network-algorithmics-an-interdisciplinary-approach-to-designing-fast-networked-devices-2004) (2004) 
  * [Computation Structures (MIT Electrical Engineering and Computer Science)](https://github.com/paragonie/awesome-appsec/blob/master/#-computation-structures-mit-electrical-engineering-and-computer-science-1989) (1989) 
  * [Surreptitious Software: Obfuscation, Watermarking, and Tamperproofing for Software Protection](https://github.com/paragonie/awesome-appsec/blob/master/#-surreptitious-software-obfuscation-watermarking-and-tamperproofing-for-software-protection-2009) (2009)
  * [Secure Programming HOWTO](#secure-programming-howto-2015) (2015)
  * [Security Engineering - Second Edition](#security-engineering-second-edition-2008) (2008)
  * [Bulletproof SSL and TLS](https://github.com/paragonie/awesome-appsec/blob/master/#-bulletproof-ssl-and-tls-2014) (2014)
  * [Holistic Info-Sec for Web Developers (Fascicle 0)](#holistic-info-sec-for-web-developers-fascicle-0-2016) (2016)
    * [Cossack Labs blog](#cossack-labs-blog-2018) (2018)
  * [SEI CERT Android Secure Coding Standard](#sei-cert-android-secure-coding-standard-2015) (2015)
  * [SEI CERT C Coding Standard](#sei-cert-c-coding-standard-2006) (2006)
  * [Defensive Coding: A Guide to Improving Software Security by the Fedora Security Team](#defensive-coding-a-guide-to-improving-software-security-by-the-fedora-security-team-2018) (2018)
  * [SEI CERT C++ Coding Standard](#sei-cert-c-coding-standard-2006-1) (2006)
  * [Security Driven .NET](https://github.com/paragonie/awesome-appsec/blob/master/#-security-driven-net-2015) (2015) 
  * [Memory Security in Go - cryptolosophy.io](#memory-security-in-go-cryptolosophy-io-2017) (2017)
  * [SEI CERT Java Coding Standard](#sei-cert-java-coding-standard-2007) (2007)
  * [Secure Coding Guidelines for Java SE](#secure-coding-guidelines-for-java-se-2014) (2014)
  * [Node.js Security Checklist - Rising Stack Blog](#node-js-security-checklist-rising-stack-blog-2015) (2015)
  * [Essential Node.js Security](https://github.com/paragonie/awesome-appsec/blob/master/#-essential-node-js-security-2017) (2017) 
  * [Security Training by ^Lift Security](https://github.com/paragonie/awesome-appsec/blob/master/#-security-training-by-lift-security) 
  * [Security Training from BinaryMist](https://github.com/paragonie/awesome-appsec/blob/master/#-security-training-from-binarymist) 
  * [It's All About Time](#its-all-about-time-2014) (2014)
  * [Secure Authentication in PHP with Long-Term Persistence](#secure-authentication-in-php-with-long-term-persistence-2015) (2015)
  * [20 Point List For Preventing Cross-Site Scripting In PHP](#20-point-list-for-preventing-cross-site-scripting-in-php-2013) (2013)
  * [25 PHP Security Best Practices For Sys Admins](#25-php-security-best-practices-for-sys-admins-2011) (2011)
  * [PHP data encryption primer](#php-data-encryption-primer-2014) (2014)
  * [Preventing SQL Injection in PHP Applications - the Easy and Definitive Guide](#preventing-sql-injection-in-php-applications-the-easy-and-definitive-guide-2014) (2014)
  * [You Wouldn't Base64 a Password - Cryptography Decoded](#you-wouldnt-base64-a-password-cryptography-decoded-2015) (2015)
  * [A Guide to Secure Data Encryption in PHP Applications](#a-guide-to-secure-data-encryption-in-php-applications-2015) (2015)
  * [The 2018 Guide to Building Secure PHP Software](#the-2018-guide-to-building-secure-php-software-2017) (2017)
  * [Securing PHP: Core Concepts](https://github.com/paragonie/awesome-appsec/blob/master/#-securing-php-core-concepts) 
  * [SEI CERT Perl Coding Standard](#sei-cert-perl-coding-standard-2011) (2011)
  * [Black Hat Python: Python Programming for Hackers and Pentesters](https://github.com/paragonie/awesome-appsec/blob/master/#-black-hat-python-python-programming-for-hackers-and-pentesters) 
  * [Violent Python](https://github.com/paragonie/awesome-appsec/blob/master/#-violent-python) 
  * [OWASP Python Security Wiki](#owasp-python-security-wiki-2014) (2014)
  * [Secure Ruby Development Guide](#secure-ruby-development-guide-2014) (2014)

### Websites
* [Hack This Site!](http://www.hackthissite.org) - Learn about application security by attempting to hack this website.
* [Enigma Group](http://www.enigmagroup.org) - Where hackers and security experts come to train.
* [Web App Sec Quiz](https://timoh6.github.io/WebAppSecQuiz/) - Self-assessment quiz for web application security
* [SecurePasswords.info](https://securepasswords.info) - Secure passwords in several languages/frameworks.
* [Security News Feeds Cheat-Sheet](http://lzone.de/cheat-sheet/Security-News-Feeds) - A list of security news sources.
* [Open Security Training](http://opensecuritytraining.info/) - Video courses on low-level x86 programming, hacking, and forensics.
* [MicroCorruption](https://microcorruption.com/login) - Capture The Flag - Learn Assembly and Embedded Device Security
* [The Matasano Crypto Challenges](http://cryptopals.com) - A series of programming exercises for teaching oneself cryptography by [Matasano Security](http://matasano.com). [The introduction](https://blog.pinboard.in/2013/04/the_matasano_crypto_challenges) by Maciej Ceglowski explains it well.
* [PentesterLab](https://pentesterlab.com) - PentesterLab provides [free Hands-On exercises](https://pentesterlab.com/exercises/) and a [bootcamp](https://pentesterlab.com/bootcamp/) to get started.
* [Juice Shop](https://bkimminich.github.io/juice-shop) - An intentionally insecure Javascript Web Application.
* [Supercar Showdown](http://hackyourselffirst.troyhunt.com/) - How to go on the offence before online attackers do.
* [OWASP NodeGoat](https://github.com/owasp/nodegoat) - Purposly vulnerable to the OWASP Top 10 Node.JS web application, with [tutorials](https://nodegoat.herokuapp.com/tutorial), [security regression testing with the OWASP Zap API](https://github.com/OWASP/NodeGoat/wiki/NodeGoat-Security-Regression-tests-with-ZAP-API), [docker image](https://github.com/owasp/nodegoat#option-3---run-nodegoat-on-docker). With several options to get up and running fast.

### Blogs

* [Crypto Fails](http://cryptofails.com) - Showcasing bad cryptography
* [NCC Group - Blog](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/) - The blog of NCC Group, formerly Matasano, iSEC Partners, and NGS Secure.
* [Scott Helme](https://scotthelme.co.uk) - Learn about security and performance.
* [Cossack Labs blog](https://www.cossacklabs.com/blog-archive/) (2018) **Released**: July 30, 2018 - Blog of cryptographic company that makes open-source libraries and tools, and describes practical data security approaches for applications and infrastructures.

### Wiki pages

* [OWASP Top Ten Project](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project) - The top ten most common and critical security vulnerabilities found in web applications.

### Tools

* [Qualys SSL Labs](https://www.ssllabs.com/) - The infamous suite of SSL and TLS tools.
* [securityheaders.io](https://securityheaders.io/) - Quickly and easily assess the security of your HTTP response headers
* [report-uri.io](https://report-uri.io) - A free CSP and HPKP reporting service.

## Asset Discovery

### Content Discovery
* [RustButer](https://github.com/phra/rustbuster) - Files, directories and vhost buster written in Rust.

### IP Address Discovery
- [Mxtoolbox](https://mxtoolbox.com/BulkLookup.aspx) - Bulk Domain/IP lookup tool  
- [Domaintoipconverter](http://domaintoipconverter.com/) - Bulk domain to IP converter  
- [Massdns](https://github.com/blechschmidt/massdns) - A DNS resolver utility for bulk lookups  
- [Googleapps Dig](https://toolbox.googleapps.com/apps/dig/) - Online Dig tool by Google 
- [DataSploit (IP Address Modules)](https://github.com/DataSploit/datasploit/tree/master/ip) - An OSINT Framework to perform various recon techniques 
- [Domain Dossier](https://centralops.net/co/domaindossier.aspx) - Investigate domains and IP addresses 
- [Bgpview](https://bgpview.io/)- Search ASN, IPv4/IPv6 or resource name 
- [Hurricane Electric BGP Toolkit](https://bgp.he.net/) - Keyword to ASN lookup 
- [Viewdns](https://viewdns.info/): Multiple domain/IP tools 
- [Ultratools ipv6Info](https://www.ultratools.com/tools/ipv6Info) - Multiple information related to IPv6 address 
- [Whois](https://manpages.debian.org/jessie/whois/whois.1.en.html) - Command line utility usually used to find information about registered users/assignees of an Internet resource.
- [ICANN Whois](https://whois.icann.org/en) - Whois service by Internet Corporation for Assigned Names and Numbers (ICANN) 
- Nslookup [Linux](https://manpages.debian.org/jessie/dnsutils/nslookup.1.en.html) / [Windows](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/nslookup) - Command line utility usually used for querying the DNS records
- [bgp](https://bgp.he.net/) - Internet Backbone and Colocation Provider ... Hurricane Electric IP Transit. Our Global Internet Backbone provides IP Transit with low latency, access to thousands of networks, and dual-stack 

### Domain / Subdomain Discovery
- [SubFinder](https://github.com/subfinder/subfinder) - SubFinder is a subdomain discovery tool that discovers valid subdomains for websites. Designed as a passive framework to be useful for bug bounties and safe for penetration testing.
- [Amass](https://github.com/OWASP/Amass) - A subdomain enumeration utility 
- [Sublist3r](https://github.com/aboul3la/Sublist3r) - Subdomains enumeration tool with multiple sources 
- [Aiodnsbrute](https://github.com/blark/aiodnsbrute) - Asynchronous DNS brute force utility 
- [LDNS](https://github.com/NLnetLabs/ldns) - A DNS library useful for DNS tool programming 
- [Dns-nsec3-enum](https://nmap.org/nsedoc/scripts/dns-nsec3-enum.html) - Nmap NSE Script for NSEC3 walking 
- [Nsec3map](https://github.com/anonion0/nsec3map) - A tool to NSEC and NSEC3 walking
- [Crt.sh](https://crt.sh/?a=1): Domain certificate Search 
- [Ct-exposer](https://github.com/chris408/ct-exposer) - A tool to discovers sub-domains by searching Certificate Transparency logs 
- [Certgraph](https://github.com/lanrat/certgraph) - A tool to crawl the graph of certificate Alternate Names 
- [Appsecco - The art of subdomain enumeration](https://github.com/appsecco/the-art-of-subdomain-enumeration) - The supplement material for the book "The art of sub-domain enumeration" 
- [SSLScrape](https://github.com/jhaddix/sslScrape) - A scanning tool to scrape hostnames from SSL certificates 
- [Wolframalpha](https://www.wolframalpha.com/) - Computational knowledge engine 
- [Project Sonar](https://opendata.rapid7.com/sonar.fdns_v2/) - Forward DNS Data 
- [Project Sonar](https://opendata.rapid7.com/sonar.rdns_v2/) - Reverse DNS Data 
- [GoBuster](https://github.com/OJ/gobuster) - Directory/File, DNS and VHost busting tool written in Go
- [Bluto](https://github.com/darryllane/Bluto) - Recon, Subdomain Bruting, Zone Transfers

### Email Discovery
- [Hunter](https://hunter.io/) - Email search for a domain  
- [Skrapp](https://www.skrapp.io/): Browser addon to find emails on Linkedin  
- [Email Extractor](https://chrome.google.com/webstore/detail/email-extractor/jdianbbpnakhcmfkcckaboohfgnngfcc?hl=en) - Chrome extension to extract emails from web pages  
- [Convertcsv](http://convertcsv.com/email-extractor.htm) - Online tool to extract email addresses in text, web pages, data files etc. 
- [linkedin2username](https://github.com/initstring/linkedin2username) - OSINT Tool: Generate username lists for companies on LinkedIn
- [Office365UserEnum](https://bitbucket.org/grimhacker/office365userenum/src/master/) -  Enumerate valid usernames from Office 365 using ActiveSync.

### Network/Port Scanning
- [Zmap](https://github.com/zmap/zmap) - A fast network scanner designed for Internet-wide network surveys  
- [Masscan](https://github.com/robertdavidgraham/masscan) - An asynchronously TCP port scanner  
- [ZMapv6](https://github.com/tumi8/zmap) - A modified version of Zmap with IPv6 support.  
- [Nmap](https://nmap.org/) - A free and open source utility for network discovery. The most popular port scanner. 

### Business Communication Infrastructure Discovery

- [Mxtoolbox](https://mxtoolbox.com/) - Online tool to check mail exchanger (MX) records 
- [MicroBurst](https://github.com/NetSPI/MicroBurst) - PowerShell based Azure security assessment scripts 
- [Lyncsmash](https://github.com/nyxgeek/lyncsmash) - Tools to enumerate and attack self-hosted Lync/Skype for Business 
- [Enumeration-as-a-Service](https://github.com/sosdave/Enumeration-as-a-Service): Script for SaaS offering enumeration through DNS queries 
- [ruler](https://github.com/sensepost/ruler) - A tool to abuse Exchange services

### Source Code Aggregators / Search - Information Discovery

- [Github](https://github.com/search/advanced) - Github Advanced Search 
- [Bitbucket](https://www.google.com/search?q=site:bitbucket.org&q=<keyword>) - Bitbucket Search using Google
- [Gitrob](https://github.com/michenriksen/gitrob) - Reconnaissance tool for GitHub organizations 
- [Gitlab](https://gitlab.com/explore/projects) - Search Gitlab projects 
- [Publicwww](https://publicwww.com/) - Source Code Search Engine 
- [builtwith](https://builtwith.com/test.com) - Web technology information profiler tool. Find out what a website is built with.

### Cloud Infrastructure Discovery

- [CloudScraper](https://github.com/jordanpotti/CloudScraper) - A tool to spider websites for cloud resources (S3 Buckets, Azure Blobs, DigitalOcean Storage Space) 
- [InSp3ctor](https://github.com/brianwarehime/inSp3ctor) - AWS S3 Bucket/Object finder 
- [Buckets Grayhatwarfare](https://buckets.grayhatwarfare.com/) - Search for Open Amazon s3 Buckets and their contents 
- [Spaces-finder](https://github.com/appsecco/spaces-finder) - A tool to hunt for publicly accessible DigitalOcean Spaces 
- [GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute) - A Google Storage buckets enumeration script 
- [CloudStorageFinder](https://github.com/digininja/CloudStorageFinder) - Tools to find public data in cloud storage systems

### Company Information and Associations

- [Crunchbase](https://www.crunchbase.com/) - Information about companies (funding, acquisition, merger etc.) and the people behind them 
- [Companieshouse](https://beta.companieshouse.gov.uk/) - United Kingdom's registrar of companies 
- [OverSeas Registries](https://www.gov.uk/government/publications/overseas-registries/overseas-registries) - List of company registries located around the world 
- [Opencorporates](https://opencorporates.com) - Open database of companies in the world 

### Internet Survey Data

- [Project Resonance](https://redhuntlabs.com/project-resonance) - RedHunt Labs’s Internet wide surveys to study and understand the security state of the Internet.
- [Project Sonar](https://opendata.rapid7.com/) - Rapid7’s internet-wide surveys data across different services and protocols 
- [Scans.io](https://scans.io) - Internet-Wide Scan Data Repository, hosted by the ZMap Team    
- [Portradar](https://portradar.packet.tel/) - Free and open port scan data by packet.tel 

### Social Media / Employee Profiling

- [LinkedInt](https://github.com/mdsecactivebreach/LinkedInt) - A LinkedIn scraper for reconnaissance 
- [Glassdoor](https://www.glassdoor.co.in/Reviews/index.htm) - Company review and rating search 
- [SocialBlade](https://socialblade.com/) - Track user statistics for different platforms including YouTube and Twitter 
- [Social-Searcher](https://www.social-searcher.com/) - Social Media Search Engine 
- [Checkuser](https://checkuser.org) - Social existence checker

### Data Leaks

- [Dumpmon](https://twitter.com/dumpmon) - A twitter bot which monitors multiple paste sites for password dumps and other sensitive information  
- [Pastebin_scraper](https://github.com/Critical-Start/pastebin_scraper) - Automated tool to monitor pastebin for interesting information 
- [Scavenger](https://github.com/rndinfosecguy/Scavenger) - Paste sites crawler (bot) looking for leaked credentials
- [Pwnbin](https://github.com/kahunalu/pwnbin) - Python based Pastebin crawler for keywords.
- [PwnedOrNot](https://github.com/thewhiteh4t/pwnedOrNot) - Tool to find passwords for compromised accounts

### Internet Scan / Archived Information

- [Cachedviews](https://cachedviews.com/): Cached view of pages on the Internet from multiple sources
- [Wayback Machine](http://web.archive.org/) - Internet Archive  
- [Shodan](http://shodan.io/) - Search engine for Internet-connected devices  
- [Censys](https://censys.io/) - Another search engine for internet-connected devices  
- [Zoomeye](https://www.zoomeye.org/) - Cyberspace Search Engine  

## Credits

* [Application Security](https://github.com/paragonie/awesome-appsec)
* [Asset Discovery](https://github.com/redhuntlabs/Awesome-Asset-Discovery)
