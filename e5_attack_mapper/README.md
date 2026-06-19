---
tags:
- sentence-transformers
- sentence-similarity
- feature-extraction
- generated_from_trainer
- dataset_size:2000
- loss:MultipleNegativesRankingLoss
base_model: BAAI/bge-small-en-v1.5
widget:
- source_sentence: 'query: After establishing the reverse SOCKS proxy connection,'
  sentences:
  - 'passage: Technique ID: T1083


    Technique Name:

    File and Directory Discovery


    Tactic:

    Discovery


    Technique Description:

    Adversaries may enumerate files and directories or may search in specific locations
    of a host or network share for certain information within a file system. Adversaries
    may use the information from [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)
    during automated discovery to shape follow-on behaviors, including whether or
    not the adversary fully infects the target and/or attempts specific actions.


    Many command shell utilities can be used to obtain this information. Examples
    include <code>dir</code>, <code>tree</code>, <code>ls</code>, <code>find</code>,
    and <code>locate</code>.(Citation: Windows Commands JPCERT) Custom tools may also
    be used to gather file and directory information and interact with the [Native
    API](https://attack.mitre.org/techniques/T1106). Adversaries may also leverage
    a [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) on network
    devices to gather file and directory information (e.g. <code>dir</code>, <code>show
    flash</code>, and/or <code>nvram</code>).(Citation: US-CERT-TA18-106A)


    Some files and directories may require elevated or specific user permissions to
    access.


    Tactic Description:

    The adversary is trying to figure out your environment.


    Discovery consists of techniques an adversary may use to gain knowledge about
    the system and internal network. These techniques help adversaries observe the
    environment and orient themselves before deciding how to act. They also allow
    adversaries to explore what they can control and what’s around their entry point
    in order to discover how it could benefit their current objective. Native operating
    system tools are often used toward this post-compromise information-gathering
    objective.'
  - 'passage: Technique ID: T1083


    Technique Name:

    File and Directory Discovery


    Tactic:

    Discovery


    Technique Description:

    Adversaries may enumerate files and directories or may search in specific locations
    of a host or network share for certain information within a file system. Adversaries
    may use the information from [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)
    during automated discovery to shape follow-on behaviors, including whether or
    not the adversary fully infects the target and/or attempts specific actions.


    Many command shell utilities can be used to obtain this information. Examples
    include <code>dir</code>, <code>tree</code>, <code>ls</code>, <code>find</code>,
    and <code>locate</code>.(Citation: Windows Commands JPCERT) Custom tools may also
    be used to gather file and directory information and interact with the [Native
    API](https://attack.mitre.org/techniques/T1106). Adversaries may also leverage
    a [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) on network
    devices to gather file and directory information (e.g. <code>dir</code>, <code>show
    flash</code>, and/or <code>nvram</code>).(Citation: US-CERT-TA18-106A)


    Some files and directories may require elevated or specific user permissions to
    access.


    Tactic Description:

    The adversary is trying to figure out your environment.


    Discovery consists of techniques an adversary may use to gain knowledge about
    the system and internal network. These techniques help adversaries observe the
    environment and orient themselves before deciding how to act. They also allow
    adversaries to explore what they can control and what’s around their entry point
    in order to discover how it could benefit their current objective. Native operating
    system tools are often used toward this post-compromise information-gathering
    objective.'
  - 'passage: Technique ID: T1090


    Technique Name:

    Proxy


    Tactic:

    Command and Control


    Technique Description:

    Adversaries may use a connection proxy to direct network traffic between systems
    or act as an intermediary for network communications to a command and control
    server to avoid direct connections to their infrastructure. Many tools exist that
    enable traffic redirection through proxies or port redirection, including [HTRAN](https://attack.mitre.org/software/S0040),
    ZXProxy, and ZXPortMap. (Citation: Trend Micro APT Attack Tools) Adversaries use
    these types of proxies to manage command and control communications, reduce the
    number of simultaneous outbound network connections, provide resiliency in the
    face of connection loss, or to ride over existing trusted communications paths
    between victims to avoid suspicion. Adversaries may chain together multiple proxies
    to further disguise the source of malicious traffic.


    Adversaries can also take advantage of routing schemes in Content Delivery Networks
    (CDNs) to proxy command and control traffic.


    Tactic Description:

    The adversary is trying to communicate with compromised systems to control them.


    Command and Control consists of techniques that adversaries may use to communicate
    with systems under their control within a victim network. Adversaries commonly
    attempt to mimic normal, expected traffic to avoid detection. There are many ways
    an adversary can establish command and control with various levels of stealth
    depending on the victim’s network structure and defenses.'
- source_sentence: 'query: has used UDP for C2 communications.'
  sentences:
  - 'passage: Technique ID: T1047


    Technique Name:

    Windows Management Instrumentation


    Tactic:

    Execution


    Technique Description:

    Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious
    commands and payloads. WMI is designed for programmers and is the infrastructure
    for management data and operations on Windows systems.(Citation: WMI 1-3) WMI
    is an administration feature that provides a uniform environment to access Windows
    system components.


    The WMI service enables both local and remote access, though the latter is facilitated
    by [Remote Services](https://attack.mitre.org/techniques/T1021) such as [Distributed
    Component Object Model](https://attack.mitre.org/techniques/T1021/003) and [Windows
    Remote Management](https://attack.mitre.org/techniques/T1021/006).(Citation: WMI
    1-3) Remote WMI over DCOM operates using port 135, whereas WMI over WinRM operates
    over port 5985 when using HTTP and 5986 for HTTPS.(Citation: WMI 1-3) (Citation:
    Mandiant WMI)


    An adversary can use WMI to interact with local and remote systems and use it
    as a means to execute various behaviors, such as gathering information for [Discovery](https://attack.mitre.org/tactics/TA0007)
    as well as [Execution](https://attack.mitre.org/tactics/TA0002) of commands and
    payloads.(Citation: Mandiant WMI) For example, `wmic.exe` can be abused by an
    adversary to delete shadow copies with the command `wmic.exe Shadowcopy Delete`
    (i.e., [Inhibit System Recovery](https://attack.mitre.org/techniques/T1490)).(Citation:
    WMI 6)


    **Note:** `wmic.exe` is deprecated as of January of 2024, with the WMIC feature
    being “disabled by default” on Windows 11+. WMIC will be removed from subsequent
    Windows releases and replaced by [PowerShell](https://attack.mitre.org/techniques/T1059/001)
    as the primary WMI interface.(Citation: WMI 7,8) In addition to PowerShell and
    tools like `wbemtool.exe`, COM APIs can also be used to programmatically interact
    with WMI via C++, .NET, VBScript, etc.(Citation: WMI 7,8)


    Tactic Description:

    The adversary is trying to run malicious code.


    Execution consists of techniques that result in adversary-controlled code running
    on a local or remote system. Techniques that run malicious code are often paired
    with techniques from all other tactics to achieve broader goals, like exploring
    a network or stealing data. For example, an adversary might use a remote access
    tool to run a PowerShell script that does Remote System Discovery.'
  - "passage: Technique ID: T1036.005\n\nTechnique Name:\nMasquerading: Match Legitimate\
    \ Resource Name or Location\n\nTactic:\nStealth\n\nTechnique Description:\nAdversaries\
    \ may match or approximate the name or location of legitimate files, Registry\
    \ keys, or other resources when naming/placing them. This is done for the sake\
    \ of evading defenses and observation. \n\nThis may be done by placing an executable\
    \ in a commonly trusted directory (ex: under System32) or giving it the name of\
    \ a legitimate, trusted program (ex: `svchost.exe`). Alternatively, a Windows\
    \ Registry key may be given a close approximation to a key used by a legitimate\
    \ program. In containerized environments, a threat actor may create a resource\
    \ in a trusted namespace or one that matches the naming convention of a container\
    \ pod or cluster.(Citation: Aquasec Kubernetes Backdoor 2023)\n\nTactic Description:\n\
    The adversary is trying to hide and conceal their actions, appearing as normal\
    \ behavior.\n\nStealth consists of techniques that reduce the likelihood of detection\
    \ by blending in with legitimate activity or minimizing observable signals. These\
    \ techniques are characterized by concealment behaviors, such as avoiding, obfuscating,\
    \ or mimicking normal operations, without modifying security controls or compromising\
    \ collection and monitoring feeds. The goal is to remain indistinguishable from\
    \ benign activity while leaving defensive systems intact."
  - 'passage: Technique ID: T1095


    Technique Name:

    Non-Application Layer Protocol


    Tactic:

    Command and Control


    Technique Description:

    Adversaries may use an OSI non-application layer protocol for communication between
    host and C2 server or among infected hosts within a network. The list of possible
    protocols is extensive.(Citation: Wikipedia OSI) Specific examples include use
    of network layer protocols, such as the Internet Control Message Protocol (ICMP),
    transport layer protocols, such as the User Datagram Protocol (UDP), session layer
    protocols, such as Socket Secure (SOCKS), as well as redirected/tunneled protocols,
    such as Serial over LAN (SOL).


    ICMP communication between hosts is one example.(Citation: Cisco Synful Knock
    Evolution) Because ICMP is part of the Internet Protocol Suite, it is required
    to be implemented by all IP-compatible hosts.(Citation: Microsoft ICMP) However,
    it is not as commonly monitored as other Internet Protocols such as TCP or UDP
    and may be used by adversaries to hide communications.


    In ESXi environments, adversaries may leverage the Virtual Machine Communication
    Interface (VMCI) for communication between guest virtual machines and the ESXi
    host. This traffic is similar to client-server communications on traditional network
    sockets but is localized to the physical machine running the ESXi host, meaning
    it does not traverse external networks (routers, switches). This results in communications
    that are invisible to external monitoring and standard networking tools like tcpdump,
    netstat, nmap, and Wireshark. By adding a VMCI backdoor to a compromised ESXi
    host, adversaries may persistently regain access from any guest VM to the compromised
    ESXi host’s backdoor, regardless of network segmentation or firewall rules in
    place.(Citation: Google Cloud Threat Intelligence VMWare ESXi Zero-Day 2023)


    Tactic Description:

    The adversary is trying to communicate with compromised systems to control them.


    Command and Control consists of techniques that adversaries may use to communicate
    with systems under their control within a victim network. Adversaries commonly
    attempt to mimic normal, expected traffic to avoid detection. There are many ways
    an adversary can establish command and control with various levels of stealth
    depending on the victim’s network structure and defenses.'
- source_sentence: 'query: APT32 likely used COVID-19-themed malicious attachments
    against Chinese speaking targets.'
  sentences:
  - "passage: Technique ID: T1566.001\n\nTechnique Name:\nPhishing: Spearphishing\
    \ Attachment\n\nTactic:\nInitial Access\n\nTechnique Description:\nAdversaries\
    \ may send spearphishing emails with a malicious attachment in an attempt to gain\
    \ access to victim systems. Spearphishing attachment is a specific variant of\
    \ spearphishing. Spearphishing attachment is different from other forms of spearphishing\
    \ in that it employs the use of malware attached to an email. All forms of spearphishing\
    \ are electronically delivered social engineering targeted at a specific individual,\
    \ company, or industry. In this scenario, adversaries attach a file to the spearphishing\
    \ email and usually rely upon [User Execution](https://attack.mitre.org/techniques/T1204)\
    \ to gain execution.(Citation: Unit 42 DarkHydrus July 2018) Spearphishing may\
    \ also involve social engineering techniques, such as posing as a trusted source.\n\
    \nThere are many options for the attachment such as Microsoft Office documents,\
    \ executables, PDFs, or archived files. Upon opening the attachment (and potentially\
    \ clicking past protections), the adversary's payload exploits a vulnerability\
    \ or directly executes on the user's system. The text of the spearphishing email\
    \ usually tries to give a plausible reason why the file should be opened, and\
    \ may explain how to bypass system protections in order to do so. The email may\
    \ also contain instructions on how to decrypt an attachment, such as a zip file\
    \ password, in order to evade email boundary defenses. Adversaries frequently\
    \ manipulate file extensions and icons in order to make attached executables appear\
    \ to be document files, or files exploiting one application appear to be a file\
    \ for a different one. \n\nTactic Description:\nThe adversary is trying to get\
    \ into your network.\n\nInitial Access consists of techniques that use various\
    \ entry vectors to gain their initial foothold within a network. Techniques used\
    \ to gain a foothold include targeted spearphishing and exploiting weaknesses\
    \ on public-facing web servers. Footholds gained through initial access may allow\
    \ for continued access, like valid accounts and use of external remote services,\
    \ or may be limited-use due to changing passwords."
  - "passage: Technique ID: T1105\n\nTechnique Name:\nIngress Tool Transfer\n\nTactic:\n\
    Command and Control\n\nTechnique Description:\nAdversaries may transfer tools\
    \ or other files from an external system into a compromised environment. Tools\
    \ or files may be copied from an external adversary-controlled system to the victim\
    \ network through the command and control channel or through alternate protocols\
    \ such as [ftp](https://attack.mitre.org/software/S0095). Once present, adversaries\
    \ may also transfer/spread tools between victim devices within a compromised environment\
    \ (i.e. [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570)). \n\
    \nOn Windows, adversaries may use various utilities to download tools, such as\
    \ `copy`, `finger`, [certutil](https://attack.mitre.org/software/S0160), and [PowerShell](https://attack.mitre.org/techniques/T1059/001)\
    \ commands such as <code>IEX(New-Object Net.WebClient).downloadString()</code>\
    \ and <code>Invoke-WebRequest</code>. On Linux and macOS systems, a variety of\
    \ utilities also exist, such as `curl`, `scp`, `sftp`, `tftp`, `rsync`, `finger`,\
    \ and `wget`.(Citation: t1105_lolbas)  A number of these tools, such as `wget`,\
    \ `curl`, and `scp`, also exist on ESXi. After downloading a file, a threat actor\
    \ may attempt to verify its integrity by checking its hash value (e.g., via `certutil\
    \ -hashfile`).(Citation: Google Cloud Threat Intelligence COSCMICENERGY 2023)\n\
    \nAdversaries may also abuse installers and package managers, such as `yum` or\
    \ `winget`, to download tools to victim hosts. Adversaries have also abused file\
    \ application features, such as the Windows `search-ms` protocol handler, to deliver\
    \ malicious files to victims through remote file searches invoked by [User Execution](https://attack.mitre.org/techniques/T1204)\
    \ (typically after interacting with [Phishing](https://attack.mitre.org/techniques/T1566)\
    \ lures).(Citation: T1105: Trellix_search-ms)\n\nFiles can also be transferred\
    \ using various [Web Service](https://attack.mitre.org/techniques/T1102)s as well\
    \ as native or otherwise present tools on the victim system.(Citation: PTSecurity\
    \ Cobalt Dec 2016) In some cases, adversaries may be able to leverage services\
    \ that sync between a web-based and an on-premises client, such as Dropbox or\
    \ OneDrive, to transfer files onto victim systems. For example, by compromising\
    \ a cloud account and logging into the service's web portal, an adversary may\
    \ be able to trigger an automatic syncing process that transfers the file onto\
    \ the victim's machine.(Citation: Dropbox Malware Sync)\n\nTactic Description:\n\
    The adversary is trying to communicate with compromised systems to control them.\n\
    \nCommand and Control consists of techniques that adversaries may use to communicate\
    \ with systems under their control within a victim network. Adversaries commonly\
    \ attempt to mimic normal, expected traffic to avoid detection. There are many\
    \ ways an adversary can establish command and control with various levels of stealth\
    \ depending on the victim’s network structure and defenses."
  - 'passage: Technique ID: T1047


    Technique Name:

    Windows Management Instrumentation


    Tactic:

    Execution


    Technique Description:

    Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious
    commands and payloads. WMI is designed for programmers and is the infrastructure
    for management data and operations on Windows systems.(Citation: WMI 1-3) WMI
    is an administration feature that provides a uniform environment to access Windows
    system components.


    The WMI service enables both local and remote access, though the latter is facilitated
    by [Remote Services](https://attack.mitre.org/techniques/T1021) such as [Distributed
    Component Object Model](https://attack.mitre.org/techniques/T1021/003) and [Windows
    Remote Management](https://attack.mitre.org/techniques/T1021/006).(Citation: WMI
    1-3) Remote WMI over DCOM operates using port 135, whereas WMI over WinRM operates
    over port 5985 when using HTTP and 5986 for HTTPS.(Citation: WMI 1-3) (Citation:
    Mandiant WMI)


    An adversary can use WMI to interact with local and remote systems and use it
    as a means to execute various behaviors, such as gathering information for [Discovery](https://attack.mitre.org/tactics/TA0007)
    as well as [Execution](https://attack.mitre.org/tactics/TA0002) of commands and
    payloads.(Citation: Mandiant WMI) For example, `wmic.exe` can be abused by an
    adversary to delete shadow copies with the command `wmic.exe Shadowcopy Delete`
    (i.e., [Inhibit System Recovery](https://attack.mitre.org/techniques/T1490)).(Citation:
    WMI 6)


    **Note:** `wmic.exe` is deprecated as of January of 2024, with the WMIC feature
    being “disabled by default” on Windows 11+. WMIC will be removed from subsequent
    Windows releases and replaced by [PowerShell](https://attack.mitre.org/techniques/T1059/001)
    as the primary WMI interface.(Citation: WMI 7,8) In addition to PowerShell and
    tools like `wbemtool.exe`, COM APIs can also be used to programmatically interact
    with WMI via C++, .NET, VBScript, etc.(Citation: WMI 7,8)


    Tactic Description:

    The adversary is trying to run malicious code.


    Execution consists of techniques that result in adversary-controlled code running
    on a local or remote system. Techniques that run malicious code are often paired
    with techniques from all other tactics to achieve broader goals, like exploring
    a network or stealing data. For example, an adversary might use a remote access
    tool to run a PowerShell script that does Remote System Discovery.'
- source_sentence: 'query: can set the KeepPrintedJobs attribute for configured printers
    in SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers to enable
    document stealing.'
  sentences:
  - "passage: Technique ID: T1105\n\nTechnique Name:\nIngress Tool Transfer\n\nTactic:\n\
    Command and Control\n\nTechnique Description:\nAdversaries may transfer tools\
    \ or other files from an external system into a compromised environment. Tools\
    \ or files may be copied from an external adversary-controlled system to the victim\
    \ network through the command and control channel or through alternate protocols\
    \ such as [ftp](https://attack.mitre.org/software/S0095). Once present, adversaries\
    \ may also transfer/spread tools between victim devices within a compromised environment\
    \ (i.e. [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570)). \n\
    \nOn Windows, adversaries may use various utilities to download tools, such as\
    \ `copy`, `finger`, [certutil](https://attack.mitre.org/software/S0160), and [PowerShell](https://attack.mitre.org/techniques/T1059/001)\
    \ commands such as <code>IEX(New-Object Net.WebClient).downloadString()</code>\
    \ and <code>Invoke-WebRequest</code>. On Linux and macOS systems, a variety of\
    \ utilities also exist, such as `curl`, `scp`, `sftp`, `tftp`, `rsync`, `finger`,\
    \ and `wget`.(Citation: t1105_lolbas)  A number of these tools, such as `wget`,\
    \ `curl`, and `scp`, also exist on ESXi. After downloading a file, a threat actor\
    \ may attempt to verify its integrity by checking its hash value (e.g., via `certutil\
    \ -hashfile`).(Citation: Google Cloud Threat Intelligence COSCMICENERGY 2023)\n\
    \nAdversaries may also abuse installers and package managers, such as `yum` or\
    \ `winget`, to download tools to victim hosts. Adversaries have also abused file\
    \ application features, such as the Windows `search-ms` protocol handler, to deliver\
    \ malicious files to victims through remote file searches invoked by [User Execution](https://attack.mitre.org/techniques/T1204)\
    \ (typically after interacting with [Phishing](https://attack.mitre.org/techniques/T1566)\
    \ lures).(Citation: T1105: Trellix_search-ms)\n\nFiles can also be transferred\
    \ using various [Web Service](https://attack.mitre.org/techniques/T1102)s as well\
    \ as native or otherwise present tools on the victim system.(Citation: PTSecurity\
    \ Cobalt Dec 2016) In some cases, adversaries may be able to leverage services\
    \ that sync between a web-based and an on-premises client, such as Dropbox or\
    \ OneDrive, to transfer files onto victim systems. For example, by compromising\
    \ a cloud account and logging into the service's web portal, an adversary may\
    \ be able to trigger an automatic syncing process that transfers the file onto\
    \ the victim's machine.(Citation: Dropbox Malware Sync)\n\nTactic Description:\n\
    The adversary is trying to communicate with compromised systems to control them.\n\
    \nCommand and Control consists of techniques that adversaries may use to communicate\
    \ with systems under their control within a victim network. Adversaries commonly\
    \ attempt to mimic normal, expected traffic to avoid detection. There are many\
    \ ways an adversary can establish command and control with various levels of stealth\
    \ depending on the victim’s network structure and defenses."
  - "passage: Technique ID: T1036.005\n\nTechnique Name:\nMasquerading: Match Legitimate\
    \ Resource Name or Location\n\nTactic:\nStealth\n\nTechnique Description:\nAdversaries\
    \ may match or approximate the name or location of legitimate files, Registry\
    \ keys, or other resources when naming/placing them. This is done for the sake\
    \ of evading defenses and observation. \n\nThis may be done by placing an executable\
    \ in a commonly trusted directory (ex: under System32) or giving it the name of\
    \ a legitimate, trusted program (ex: `svchost.exe`). Alternatively, a Windows\
    \ Registry key may be given a close approximation to a key used by a legitimate\
    \ program. In containerized environments, a threat actor may create a resource\
    \ in a trusted namespace or one that matches the naming convention of a container\
    \ pod or cluster.(Citation: Aquasec Kubernetes Backdoor 2023)\n\nTactic Description:\n\
    The adversary is trying to hide and conceal their actions, appearing as normal\
    \ behavior.\n\nStealth consists of techniques that reduce the likelihood of detection\
    \ by blending in with legitimate activity or minimizing observable signals. These\
    \ techniques are characterized by concealment behaviors, such as avoiding, obfuscating,\
    \ or mimicking normal operations, without modifying security controls or compromising\
    \ collection and monitoring feeds. The goal is to remain indistinguishable from\
    \ benign activity while leaving defensive systems intact."
  - 'passage: Technique ID: T1112


    Technique Name:

    Modify Registry


    Tactic:

    Persistence


    Technique Description:

    Adversaries may interact with the Windows Registry as part of a variety of other
    techniques to aid in defense evasion, persistence, and execution.


    Access to specific areas of the Registry depends on account permissions, with
    some keys requiring administrator-level access. The built-in Windows command-line
    utility [Reg](https://attack.mitre.org/software/S0075) may be used for local or
    remote Registry modification.(Citation: Microsoft Reg) Other tools, such as remote
    access tools, may also contain functionality to interact with the Registry through
    the Windows API.


    The Registry may be modified in order to hide configuration information or malicious
    payloads via [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027).(Citation:
    Unit42 BabyShark Feb 2019)(Citation: Avaddon Ransomware 2021)(Citation: Microsoft
    BlackCat Jun 2022)(Citation: CISA Russian Gov Critical Infra 2018) The Registry
    may also be modified to impair defenses, such as by enabling macros for all Microsoft
    Office products, allowing privilege escalation without alerting the user, increasing
    the maximum number of allowed outbound requests, and/or modifying systems to store
    plaintext credentials in memory.(Citation: CISA LockBit 2023)(Citation: Unit42
    BabyShark Feb 2019)


    The Registry of a remote system may be modified to aid in execution of files as
    part of lateral movement. It requires the remote Registry service to be running
    on the target system.(Citation: Microsoft Remote) Often [Valid Accounts](https://attack.mitre.org/techniques/T1078)
    are required, along with access to the remote system''s [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)
    for RPC communication.


    Finally, Registry modifications may also include actions to hide keys, such as
    prepending key names with a null character, which will cause an error and/or be
    ignored when read via [Reg](https://attack.mitre.org/software/S0075) or other
    utilities using the Win32 API.(Citation: Microsoft Reghide NOV 2006) Adversaries
    may abuse these pseudo-hidden keys to conceal payloads/commands used to maintain
    persistence.(Citation: TrendMicro POWELIKS AUG 2014)(Citation: SpectorOps Hiding
    Reg Jul 2017)


    Tactic Description:

    The adversary is trying to maintain their foothold.


    Persistence consists of techniques that adversaries use to keep access to systems
    across restarts, changed credentials, and other interruptions that could cut off
    their access. Techniques used for persistence include any access, action, or configuration
    changes that let them maintain their foothold on systems, such as replacing or
    hijacking legitimate code or adding startup code.'
- source_sentence: 'query: has the ability to list the directories on a compromised
    host.'
  sentences:
  - 'passage: Technique ID: T1083


    Technique Name:

    File and Directory Discovery


    Tactic:

    Discovery


    Technique Description:

    Adversaries may enumerate files and directories or may search in specific locations
    of a host or network share for certain information within a file system. Adversaries
    may use the information from [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)
    during automated discovery to shape follow-on behaviors, including whether or
    not the adversary fully infects the target and/or attempts specific actions.


    Many command shell utilities can be used to obtain this information. Examples
    include <code>dir</code>, <code>tree</code>, <code>ls</code>, <code>find</code>,
    and <code>locate</code>.(Citation: Windows Commands JPCERT) Custom tools may also
    be used to gather file and directory information and interact with the [Native
    API](https://attack.mitre.org/techniques/T1106). Adversaries may also leverage
    a [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) on network
    devices to gather file and directory information (e.g. <code>dir</code>, <code>show
    flash</code>, and/or <code>nvram</code>).(Citation: US-CERT-TA18-106A)


    Some files and directories may require elevated or specific user permissions to
    access.


    Tactic Description:

    The adversary is trying to figure out your environment.


    Discovery consists of techniques an adversary may use to gain knowledge about
    the system and internal network. These techniques help adversaries observe the
    environment and orient themselves before deciding how to act. They also allow
    adversaries to explore what they can control and what’s around their entry point
    in order to discover how it could benefit their current objective. Native operating
    system tools are often used toward this post-compromise information-gathering
    objective.'
  - 'passage: Technique ID: T1090


    Technique Name:

    Proxy


    Tactic:

    Command and Control


    Technique Description:

    Adversaries may use a connection proxy to direct network traffic between systems
    or act as an intermediary for network communications to a command and control
    server to avoid direct connections to their infrastructure. Many tools exist that
    enable traffic redirection through proxies or port redirection, including [HTRAN](https://attack.mitre.org/software/S0040),
    ZXProxy, and ZXPortMap. (Citation: Trend Micro APT Attack Tools) Adversaries use
    these types of proxies to manage command and control communications, reduce the
    number of simultaneous outbound network connections, provide resiliency in the
    face of connection loss, or to ride over existing trusted communications paths
    between victims to avoid suspicion. Adversaries may chain together multiple proxies
    to further disguise the source of malicious traffic.


    Adversaries can also take advantage of routing schemes in Content Delivery Networks
    (CDNs) to proxy command and control traffic.


    Tactic Description:

    The adversary is trying to communicate with compromised systems to control them.


    Command and Control consists of techniques that adversaries may use to communicate
    with systems under their control within a victim network. Adversaries commonly
    attempt to mimic normal, expected traffic to avoid detection. There are many ways
    an adversary can establish command and control with various levels of stealth
    depending on the victim’s network structure and defenses.'
  - 'passage: Technique ID: T1083


    Technique Name:

    File and Directory Discovery


    Tactic:

    Discovery


    Technique Description:

    Adversaries may enumerate files and directories or may search in specific locations
    of a host or network share for certain information within a file system. Adversaries
    may use the information from [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)
    during automated discovery to shape follow-on behaviors, including whether or
    not the adversary fully infects the target and/or attempts specific actions.


    Many command shell utilities can be used to obtain this information. Examples
    include <code>dir</code>, <code>tree</code>, <code>ls</code>, <code>find</code>,
    and <code>locate</code>.(Citation: Windows Commands JPCERT) Custom tools may also
    be used to gather file and directory information and interact with the [Native
    API](https://attack.mitre.org/techniques/T1106). Adversaries may also leverage
    a [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) on network
    devices to gather file and directory information (e.g. <code>dir</code>, <code>show
    flash</code>, and/or <code>nvram</code>).(Citation: US-CERT-TA18-106A)


    Some files and directories may require elevated or specific user permissions to
    access.


    Tactic Description:

    The adversary is trying to figure out your environment.


    Discovery consists of techniques an adversary may use to gain knowledge about
    the system and internal network. These techniques help adversaries observe the
    environment and orient themselves before deciding how to act. They also allow
    adversaries to explore what they can control and what’s around their entry point
    in order to discover how it could benefit their current objective. Native operating
    system tools are often used toward this post-compromise information-gathering
    objective.'
pipeline_tag: sentence-similarity
library_name: sentence-transformers
---

# SentenceTransformer based on BAAI/bge-small-en-v1.5

This is a [sentence-transformers](https://www.SBERT.net) model finetuned from [BAAI/bge-small-en-v1.5](https://huggingface.co/BAAI/bge-small-en-v1.5). It maps sentences & paragraphs to a 384-dimensional dense vector space and can be used for retrieval.

## Model Details

### Model Description
- **Model Type:** Sentence Transformer
- **Base model:** [BAAI/bge-small-en-v1.5](https://huggingface.co/BAAI/bge-small-en-v1.5) <!-- at revision 5c38ec7c405ec4b44b94cc5a9bb96e735b38267a -->
- **Maximum Sequence Length:** 512 tokens
- **Output Dimensionality:** 384 dimensions
- **Similarity Function:** Cosine Similarity
- **Supported Modality:** Text
<!-- - **Training Dataset:** Unknown -->
<!-- - **Language:** Unknown -->
<!-- - **License:** Unknown -->

### Model Sources

- **Documentation:** [Sentence Transformers Documentation](https://sbert.net)
- **Repository:** [Sentence Transformers on GitHub](https://github.com/huggingface/sentence-transformers)
- **Hugging Face:** [Sentence Transformers on Hugging Face](https://huggingface.co/models?library=sentence-transformers)

### Full Model Architecture

```
SentenceTransformer(
  (0): Transformer({'transformer_task': 'feature-extraction', 'modality_config': {'text': {'method': 'forward', 'method_output_name': 'last_hidden_state'}}, 'module_output_name': 'token_embeddings', 'architecture': 'BertModel'})
  (1): Pooling({'embedding_dimension': 384, 'pooling_mode': 'cls', 'include_prompt': True})
  (2): Normalize({})
)
```

## Usage

### Direct Usage (Sentence Transformers)

First install the Sentence Transformers library:

```bash
pip install -U sentence-transformers
```
Then you can load this model and run inference.
```python
from sentence_transformers import SentenceTransformer

# Download from the 🤗 Hub
model = SentenceTransformer("sentence_transformers_model_id")
# Run inference
sentences = [
    'query: has the ability to list the directories on a compromised host.',
    'passage: Technique ID: T1083\n\nTechnique Name:\nFile and Directory Discovery\n\nTactic:\nDiscovery\n\nTechnique Description:\nAdversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.\n\nMany command shell utilities can be used to obtain this information. Examples include <code>dir</code>, <code>tree</code>, <code>ls</code>, <code>find</code>, and <code>locate</code>.(Citation: Windows Commands JPCERT) Custom tools may also be used to gather file and directory information and interact with the [Native API](https://attack.mitre.org/techniques/T1106). Adversaries may also leverage a [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) on network devices to gather file and directory information (e.g. <code>dir</code>, <code>show flash</code>, and/or <code>nvram</code>).(Citation: US-CERT-TA18-106A)\n\nSome files and directories may require elevated or specific user permissions to access.\n\nTactic Description:\nThe adversary is trying to figure out your environment.\n\nDiscovery consists of techniques an adversary may use to gain knowledge about the system and internal network. These techniques help adversaries observe the environment and orient themselves before deciding how to act. They also allow adversaries to explore what they can control and what’s around their entry point in order to discover how it could benefit their current objective. Native operating system tools are often used toward this post-compromise information-gathering objective.',
    'passage: Technique ID: T1083\n\nTechnique Name:\nFile and Directory Discovery\n\nTactic:\nDiscovery\n\nTechnique Description:\nAdversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.\n\nMany command shell utilities can be used to obtain this information. Examples include <code>dir</code>, <code>tree</code>, <code>ls</code>, <code>find</code>, and <code>locate</code>.(Citation: Windows Commands JPCERT) Custom tools may also be used to gather file and directory information and interact with the [Native API](https://attack.mitre.org/techniques/T1106). Adversaries may also leverage a [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) on network devices to gather file and directory information (e.g. <code>dir</code>, <code>show flash</code>, and/or <code>nvram</code>).(Citation: US-CERT-TA18-106A)\n\nSome files and directories may require elevated or specific user permissions to access.\n\nTactic Description:\nThe adversary is trying to figure out your environment.\n\nDiscovery consists of techniques an adversary may use to gain knowledge about the system and internal network. These techniques help adversaries observe the environment and orient themselves before deciding how to act. They also allow adversaries to explore what they can control and what’s around their entry point in order to discover how it could benefit their current objective. Native operating system tools are often used toward this post-compromise information-gathering objective.',
]
embeddings = model.encode(sentences)
print(embeddings.shape)
# [3, 384]

# Get the similarity scores for the embeddings
similarities = model.similarity(embeddings, embeddings)
print(similarities)
# tensor([[1.0000, 0.6915, 0.6915],
#         [0.6915, 1.0000, 1.0000],
#         [0.6915, 1.0000, 1.0000]])
```
<!--
### Direct Usage (Transformers)

<details><summary>Click to see the direct usage in Transformers</summary>

</details>
-->

<!--
### Downstream Usage (Sentence Transformers)

You can finetune this model on your own dataset.

<details><summary>Click to expand</summary>

</details>
-->

<!--
### Out-of-Scope Use

*List how the model may foreseeably be misused and address what users ought not to do with the model.*
-->

<!--
## Bias, Risks and Limitations

*What are the known or foreseeable issues stemming from this model? You could also flag here known failure cases or weaknesses of the model.*
-->

<!--
### Recommendations

*What are recommendations with respect to the foreseeable issues? For example, filtering explicit content.*
-->

## Training Details

### Training Dataset

#### Unnamed Dataset

* Size: 2,000 training samples
* Columns: <code>sentence_0</code> and <code>sentence_1</code>
* Approximate statistics based on the first 100 samples:
  |          | sentence_0                                                                         | sentence_1                                                                            |
  |:---------|:-----------------------------------------------------------------------------------|:--------------------------------------------------------------------------------------|
  | type     | string                                                                             | string                                                                                |
  | modality | text                                                                               | text                                                                                  |
  | details  | <ul><li>min: 7 tokens</li><li>mean: 24.04 tokens</li><li>max: 112 tokens</li></ul> | <ul><li>min: 285 tokens</li><li>mean: 448.42 tokens</li><li>max: 512 tokens</li></ul> |
* Samples:
  | sentence_0                                                                                                                                      | sentence_1                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
  |:------------------------------------------------------------------------------------------------------------------------------------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
  | <code>query: Get Directory Information The malware gets information for the provided directory address using the following WINAPI calls:</code> | <code>passage: Technique ID: T1083<br><br>Technique Name:<br>File and Directory Discovery<br><br>Tactic:<br>Discovery<br><br>Technique Description:<br>Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.<br><br>Many command shell utilities can be used to obtain this information. Examples include <code>dir</code>, <code>tree</code>, <code>ls</code>, <code>find</code>, and <code>locate</code>.(Citation: Windows Commands JPCERT) Custom tools may also be used to gather file and directory information and interact with the [Native API](https://attack.mitre.org/techniques/T1106). Adversaries may also leverage a [Network Device CLI](https://attack.mitre.org/techniq...</code>       |
  | <code>query: These emails may contain a malicious link or file that provide the cyber actor access to the victim’s device</code>                | <code>passage: Technique ID: T1566.001<br><br>Technique Name:<br>Phishing: Spearphishing Attachment<br><br>Tactic:<br>Initial Access<br><br>Technique Description:<br>Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon [User Execution](https://attack.mitre.org/techniques/T1204) to gain execution.(Citation: Unit 42 DarkHydrus July 2018) Spearphishing may also involve social engineering techniques, such as posing as a trusted source.<br><br>There are many options for the attachment such as Microsoft Office documents, executables, PDFs, or archived ...</code>       |
  | <code>query: uses various WMI queries to check if the sample is running in a sandbox.(Citation: Unit 42 DarkHydrus July 2018)</code>            | <code>passage: Technique ID: T1047<br><br>Technique Name:<br>Windows Management Instrumentation<br><br>Tactic:<br>Execution<br><br>Technique Description:<br>Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads. WMI is designed for programmers and is the infrastructure for management data and operations on Windows systems.(Citation: WMI 1-3) WMI is an administration feature that provides a uniform environment to access Windows system components.<br><br>The WMI service enables both local and remote access, though the latter is facilitated by [Remote Services](https://attack.mitre.org/techniques/T1021) such as [Distributed Component Object Model](https://attack.mitre.org/techniques/T1021/003) and [Windows Remote Management](https://attack.mitre.org/techniques/T1021/006).(Citation: WMI 1-3) Remote WMI over DCOM operates using port 135, whereas WMI over WinRM operates over port 5985 when using HTTP and 5986 for HTTPS.(Citation: WMI 1-3) (Citation: Mandiant WMI)<br><br>An adversary c...</code> |
* Loss: [<code>MultipleNegativesRankingLoss</code>](https://sbert.net/docs/package_reference/sentence_transformer/losses.html#multiplenegativesrankingloss) with these parameters:
  ```json
  {
      "scale": 20.0,
      "similarity_fct": "cos_sim",
      "gather_across_devices": false,
      "directions": [
          "query_to_doc"
      ],
      "partition_mode": "joint",
      "hardness_mode": null,
      "hardness_strength": 0.0
  }
  ```

### Training Hyperparameters
#### Non-Default Hyperparameters

- `per_device_train_batch_size`: 16
- `num_train_epochs`: 1
- `per_device_eval_batch_size`: 16
- `multi_dataset_batch_sampler`: round_robin

#### All Hyperparameters
<details><summary>Click to expand</summary>

- `per_device_train_batch_size`: 16
- `num_train_epochs`: 1
- `max_steps`: -1
- `learning_rate`: 5e-05
- `lr_scheduler_type`: linear
- `lr_scheduler_kwargs`: None
- `warmup_steps`: 0
- `optim`: adamw_torch_fused
- `optim_args`: None
- `weight_decay`: 0.0
- `adam_beta1`: 0.9
- `adam_beta2`: 0.999
- `adam_epsilon`: 1e-08
- `optim_target_modules`: None
- `gradient_accumulation_steps`: 1
- `average_tokens_across_devices`: True
- `max_grad_norm`: 1
- `label_smoothing_factor`: 0.0
- `bf16`: False
- `fp16`: False
- `bf16_full_eval`: False
- `fp16_full_eval`: False
- `tf32`: None
- `gradient_checkpointing`: False
- `gradient_checkpointing_kwargs`: None
- `torch_compile`: False
- `torch_compile_backend`: None
- `torch_compile_mode`: None
- `use_liger_kernel`: False
- `liger_kernel_config`: None
- `use_cache`: False
- `neftune_noise_alpha`: None
- `torch_empty_cache_steps`: None
- `auto_find_batch_size`: False
- `log_on_each_node`: True
- `logging_nan_inf_filter`: True
- `include_num_input_tokens_seen`: no
- `log_level`: passive
- `log_level_replica`: warning
- `disable_tqdm`: False
- `project`: huggingface
- `trackio_space_id`: None
- `trackio_bucket_id`: None
- `trackio_static_space_id`: None
- `per_device_eval_batch_size`: 16
- `prediction_loss_only`: True
- `eval_on_start`: False
- `eval_do_concat_batches`: True
- `eval_use_gather_object`: False
- `eval_accumulation_steps`: None
- `include_for_metrics`: []
- `batch_eval_metrics`: False
- `save_only_model`: False
- `save_on_each_node`: False
- `enable_jit_checkpoint`: False
- `push_to_hub`: False
- `hub_private_repo`: None
- `hub_model_id`: None
- `hub_strategy`: every_save
- `hub_always_push`: False
- `hub_revision`: None
- `load_best_model_at_end`: False
- `ignore_data_skip`: False
- `restore_callback_states_from_checkpoint`: False
- `full_determinism`: False
- `seed`: 42
- `data_seed`: None
- `use_cpu`: False
- `accelerator_config`: {'split_batches': False, 'dispatch_batches': None, 'even_batches': True, 'use_seedable_sampler': True, 'non_blocking': False, 'gradient_accumulation_kwargs': None}
- `parallelism_config`: None
- `dataloader_drop_last`: False
- `dataloader_num_workers`: 0
- `dataloader_pin_memory`: True
- `dataloader_persistent_workers`: False
- `dataloader_prefetch_factor`: None
- `remove_unused_columns`: True
- `label_names`: None
- `train_sampling_strategy`: random
- `length_column_name`: length
- `ddp_find_unused_parameters`: None
- `ddp_bucket_cap_mb`: None
- `ddp_broadcast_buffers`: False
- `ddp_static_graph`: None
- `ddp_backend`: None
- `ddp_timeout`: 1800
- `fsdp`: None
- `fsdp_config`: None
- `deepspeed`: None
- `debug`: []
- `skip_memory_metrics`: True
- `do_predict`: False
- `resume_from_checkpoint`: None
- `warmup_ratio`: None
- `local_rank`: -1
- `prompts`: None
- `batch_sampler`: batch_sampler
- `multi_dataset_batch_sampler`: round_robin
- `router_mapping`: {}
- `learning_rate_mapping`: {}

</details>

### Training Time
- **Training**: 48.9 minutes

### Framework Versions
- Python: 3.12.0
- Sentence Transformers: 5.5.1
- Transformers: 5.12.1
- PyTorch: 2.12.0+cpu
- Accelerate: 1.14.0
- Datasets: 5.0.0
- Tokenizers: 0.22.2

## Citation

### BibTeX

#### Sentence Transformers
```bibtex
@inproceedings{reimers-2019-sentence-bert,
    title = "Sentence-BERT: Sentence Embeddings using Siamese BERT-Networks",
    author = "Reimers, Nils and Gurevych, Iryna",
    booktitle = "Proceedings of the 2019 Conference on Empirical Methods in Natural Language Processing",
    month = "11",
    year = "2019",
    publisher = "Association for Computational Linguistics",
    url = "https://arxiv.org/abs/1908.10084",
}
```

#### MultipleNegativesRankingLoss
```bibtex
@misc{oord2019representationlearningcontrastivepredictive,
      title={Representation Learning with Contrastive Predictive Coding},
      author={Aaron van den Oord and Yazhe Li and Oriol Vinyals},
      year={2019},
      eprint={1807.03748},
      archivePrefix={arXiv},
      primaryClass={cs.LG},
      url={https://arxiv.org/abs/1807.03748},
}
```

<!--
## Glossary

*Clearly define terms in order to be accessible across audiences.*
-->

<!--
## Model Card Authors

*Lists the people who create the model card, providing recognition and accountability for the detailed work that goes into its construction.*
-->

<!--
## Model Card Contact

*Provides a way for people who have updates to the Model Card, suggestions, or questions, to contact the Model Card authors.*
-->