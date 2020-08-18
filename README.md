# Awesome Hacking Tools
A collective selection of hacking tools for hackers, pentesters and researchers.

## Table Of Contents
* [Android Security](#Android-Security)
* Application Security
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
