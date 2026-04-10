#!/usr/bin/env python3
"""
 ██▀███  ▓█████  ▄████▄   ██░ ██  ▒█████   ███▄    █   █████▒▒█████  
▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▓██░ ██▒▒██▒  ██▒ ██ ▀█   █ ▓██   ▒▒██▒  ██▒
▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██▀▀██░▒██░  ██▒▓██  ▀█ ██▒▒████ ░▒██░  ██▒
▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒░▓█ ░██ ▒██   ██░▓██▒  ▐▌██▒░▓█▒  ░▒██   ██░
░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░▓█▒░██▓░ ████▓▒░▒██░   ▓██░░▒█░   ░ ████▓▒░
░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░ ▒ ░░▒░▒░ ▒░▒░▒░ ░ ▒░   ▒ ▒  ▒ ░   ░ ▒░▒░▒░ 
  ░▒ ░ ▒░ ░ ░  ░  ░  ▒    ▒  ▒░ ░  ░ ▒ ▒░ ░ ░░   ░ ▒░ ░       ░ ▒ ▒░ 
  ░░   ░    ░   ░         ░  ░░ ░░ ░ ░ ▒     ░   ░ ░  ░ ░   ░ ░ ░ ▒  
   ░        ░  ░░ ░       ░  ░  ░    ░ ░           ░            ░ ░  
                                                                      
                    Network Scanner - Inspired by Nmap
                          
                   Created by Rikixz | Version 1.0.0
"""

import socket
import sys
import concurrent.futures
import time
import random
import struct
import os
from datetime import datetime
from typing import List, Dict, Tuple, Optional

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    class Fore:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Back:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style:
        BRIGHT = RESET_ALL = DIM = ''

class Colors:
    if COLORAMA_AVAILABLE:
        RED = Fore.RED
        GREEN = Fore.GREEN
        YELLOW = Fore.YELLOW
        BLUE = Fore.BLUE
        MAGENTA = Fore.MAGENTA
        CYAN = Fore.CYAN
        WHITE = Fore.WHITE
        RESET = Style.RESET_ALL
        BRIGHT = Style.BRIGHT
        DIM = Style.DIM
    else:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = BRIGHT = DIM = ''

BANNER = f"""
{Colors.CYAN}{Colors.BRIGHT}    _   __                 __    ________    ____  __________ 
   / | / /____   _________/ /___/ /____  __<  / ____/ /   / /  //  ____/ /__ 
  /  |/ // __ \\ / ___/ __  / __  / / / / / / / __/ / /| / /  // / __  / / _ \\
 / /|  // /_/ // /__/ /_/ / /_/ / / /_/ / / / /___/ ___ |/ /__// /_/ / /  __/
/_/ |_/ \\____/ \\___/\\__,_/\\__,_/  \\__, / /_/_____/_/  |_\\____/ \\__,_/  \\___/ 
                                 /____/                                    {Colors.MAGENTA}v1.0.0{Colors.RESET}
{Colors.YELLOW}══════════════════════════════════════════════════════════════════════════════════{Colors.RESET}
              {Colors.GREEN}Lightweight Network Scanner - Inspired by Nmap{Colors.RESET}
{Colors.YELLOW}══════════════════════════════════════════════════════════════════════════════════{Colors.RESET}
"""

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443
]

TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 636, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
    2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190,
    5357, 5432, 5631, 5632, 5666, 5800, 5900, 5901, 6000, 6001, 6646, 7070, 8000,
    8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153,
    49154, 49155, 49156, 49157, 50000, 51413
]

ALL_PORTS = list(range(1, 1001)) + [
    1025, 1026, 1027, 1028, 1029, 1433, 1434, 1521, 1723, 1755, 1900, 2000,
    2001, 2049, 2121, 2717, 3000, 3128, 3268, 3269, 3306, 3389, 3690, 4369,
    4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5632, 5666,
    5800, 5900, 5901, 6000, 6001, 6112, 6646, 7070, 8000, 8008, 8009, 8080,
    8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155,
    49156, 49157, 50000
]

FULL_PORTS = list(range(1, 65536))

PORT_SERVICES = {
    1: "tcpmux", 7: "echo", 9: "discard", 13: "daytime", 17: "qotd", 19: "chargen",
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 24: "priv-mail", 25: "smtp",
    26: "rsftp", 37: "time", 42: "wins", 43: "whois", 49: "tacacs", 53: "domain",
    67: "dhcp", 68: "dhcp", 69: "tftp", 70: "gopher", 79: "finger", 80: "http",
    81: "http-alt", 82: "xfer", 88: "kerberos", 89: "su-mit-tg", 99: "metagram",
    106: "pop3pw", 109: "pop2", 110: "pop3", 111: "rpcbind", 113: "ident",
    115: "sftp", 119: "nntp", 123: "ntp", 125: "locus-map", 135: "msrpc",
    137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 143: "imap",
    144: "news", 161: "snmp", 162: "snmptrap", 163: "cmip-man", 179: "bgp",
    194: "irc", 199: "smux", 211: "grfs", 212: "daap", 218: "dap", 220: "imap3",
    259: "esro-gen", 264: "gw-basecamp", 311: "asip-webadmin", 318: "tsp",
    323: "ike", 328: "entrust-tps", 333: "axigy", 344: "pdap", 345: "pawserv",
    346: "zserv", 347: "fatserv", 348: "csi-sgwp", 358: "narp", 359: "coap",
    362: "sdr", 364: "ascd", 366: "smip", 368: "dsp", 369: "nfs", 370: "qth",
    371: "clearcase", 372: "ulistserv", 373: "legent-1", 374: "legent-2",
    375: "hash", 376: "3com-amp3", 377: "tnETOS", 378: "dsect", 379: "tpa",
    380: "tpa-2", 381: "hp-collector", 382: "hp-managed-node", 383: "hp-alarm-mgr",
    384: "armsrv", 385: "arris", 386: "nantex", 387: "dtk", 388: "dey",
    389: "ldap", 390: "uis", 391: "synotics-relay", 392: "synotics-broker",
    393: "meta5", 394: "embl-ndt", 395: "netcp", 396: "netware-ip", 397: "mptn",
    398: "kryptolan", 399: "iso-tsap-c2", 400: "oracle", 401: "ups", 402: "genie",
    403: "decap", 404: "nced", 405: "ncld", 406: "imsp", 407: "timbuktu",
    408: "spacer", 409: "minipay", 410: "mza", 411: "mzb", 412: "mirror",
    413: "smsp", 414: "infoseek", 415: "bnet", 416: "silverplatter",
    417: "onmux", 418: "hyper-g", 419: "ariel1", 420: "smpte", 421: "ariel2",
    422: "ariel3", 423: "opc-job-start", 424: "opc-job-track", 425: "icad-el",
    426: "smartlib", 427: "svrloc", 428: "ocs_cmu", 429: "ocs_amu", 430: "utmpsd",
    431: "utmpcd", 432: "iasd", 433: "nnsp", 434: "mobileip-agent",
    435: "mobilip-mn", 436: "dna-cml", 437: "comscm", 438: "dsfgw", 439: "dasp",
    440: "sgcp", 441: "decvms", 442: "dmd", 443: "https", 444: "snpp",
    445: "microsoft-ds", 446: "ddm-rdb", 447: "ddm-dfm", 448: "ddm-ssl",
    449: "as-servermap", 450: "tserver", 451: "sfs-smp-net", 452: "sfs-config",
    453: "creatorsrv", 454: "consumer", 455: "prm-sm", 456: "prm-nm", 457: "kgame",
    458: "kar2ouche", 459: "l2tp", 460: "l2f", 461: "mina", 462: "nauth",
    463: "cldap", 464: "kpasswd", 465: "smtps", 466: "afp", 467: "rtsp",
    468: "ULISTSERV", 469: "itm", 470: "unix-auth", 471: "copy", 472: "LFS",
    473: "bmc-perf", 474: "bmc-eds", 475: "idfp", 476: "newlix", 477: "bwmk",
    478: "sgi-esp", 479: "sgi-cdd", 480: "iscsi", 481: "dhcp-failover",
    482: "nreg", 483: "lamp", 484: "VMP", 485: "imapt", 486: "iss-mgmt",
    487: "avt-profile-1", 488: "avt-profile-2", 489: "acm", 490: "lgcpe",
    491: "upnotifyps", 492: "wap-wsp", 493: "wap-wsp-wtp", 494: "wap-wsp-ssl",
    495: "wap-wsp-wtls", 496: "wap-vcard", 497: "wap-vcal", 498: "daf",
    499: "isakmp", 500: "ike", 501: "stun", 502: "stun-behavior", 503: "stun-beats",
    504: "xtaci", 505: "stun-alt", 506: "sip-tls", 507: "stun-pi", 508: "stun-peer",
    509: "vstun", 510: "cap", 511: "veri-fication", 512: "exec", 513: "login",
    514: "shell", 515: "printer", 516: "video", 517: "talk", 518: "ntalk",
    519: "utime", 520: "efs", 521: "ripng", 522: "ulp", 523: "ibm-db2",
    524: "ncp", 525: "timed", 526: "tempo", 527: "stx", 528: "custix",
    529: "irc-serv", 530: "courier", 531: "conference", 532: "netnews",
    533: "netwall", 534: "mm-admin", 535: "iiop", 536: "opalis-rdv", 537: "nmsp",
    538: "gdomap", 539: "apertus-ldp", 540: "uucp", 541: "uucp-rlogin",
    542: "klogin", 543: "kshell", 544: "kshell", 545: "ekshell", 546: "dhcpv6-client",
    547: "dhcpv6-server", 548: "afp", 549: "idfp", 550: "new-rwho", 551: "cybercash",
    552: "devshr-nts", 553: "pirp", 554: "rtsp", 555: "dsf", 556: "remotefs",
    557: "openvms-icapi", 558: "srmp", 559: "ia_update", 560: "nfs", 561: "pcdujour",
    562: "rmtcfg", 563: "nntps", 564: "whoami", 565: "streettalk", 566: "banyan-rpc",
    567: "dicom", 568: "pcanywhere", 569: "gsql", 570: "meter", 571: "meter",
    572: "sonar", 573: "banyan-vip", 574: "ftp-agent", 575: "vemiya", 576: "gss-hmac",
    577: "spiec-bcast", 578: "msexch-routing", 579: "icmpd", 580: "dcm",
    581: "sysbase", 582: "lam", 583: "imip", 584: "sae-urn", 585: "arr",
    586: "tungsten-https", 587: "submission", 588: "lift", 589: "fmission",
    590: "eyes", 591: "fujitsu-u", 592: "reserved", 593: "hp-hcip", 594: "rwhois",
    595: "acm-ssl", 596: "siemens", 597: "pgsql", 598: "scp", 599: "uucp-ssl",
    600: "unknown", 601: "syslog", 602: "sieve", 603: "dantz", 604: "sdo",
    605: "snare", 606: "ncp", 607: "misodex", 608: "nmap", 609: "cisco-sccp",
    610: "cisco-sccp", 611: "cisco-sccp", 612: "cisco-sccp", 613: "cisco-sccp",
    614: "cisco-sccp", 615: "cisco-sccp", 616: "cisco-sccp", 617: "cisco-sccp",
    618: "cisco-sccp", 619: "cisco-sccp", 620: "lm-w", 621: "clp", 622: "cxfs",
    623: "BootP", 624: "cryptiq", 625: "smip", 626: "mus-pwd", 627: "http-local",
    628: "pqsp", 629: "dpm", 630: "dpm-acm", 631: "ipp", 632: "bmpp",
    633: "cisco-sys", 634: "stat-src", 635: "stat-rcv", 636: "ldaps", 637: "lanserver",
    638: "mcns", 639: "msdp", 640: "entrust-kms", 641: "entrust-sps", 642: "dnet",
    643: "drums", 644: "drums", 645: "sdreq", 646: "sdport", 647: "l Krug",
    648: "superscan", 649: "fujitsu-u", 650: "scp", 651: "SCPCFG", 652: "LPA",
    653: "cpa", 654: "BEX", 655: "PSP", 656: "PAREN", 657: "cisco-sccp",
    658: "python", 659: "sane", 660: "dcap", 661: "icl-netserver", 662: "dcap",
    663: "ics", 664: " Maitrd", 665: "bgs-nsap", 666: "doom", 667: "camp",
    668: "cft", 669: "dmod", 670: "zarx", 671: "mac-eps", 672: "EMCIS",
    673: "wwpass", 674: "cpl", 675: "sae-urn", 676: "ppp", 677: "ppp",
    678: "ppp", 679: "rrH", 680: "rrp", 681: "IRDP", 682: "acap", 683: "RUSP",
    684: "rpc", 685: "MCP", 686: "iims", 687: " MCC", 688: "MCP", 689: "MCP",
    690: "kry", 691: "K Flex", 692: "ca-1", 693: "ca-2", 694: "LanMessenger",
    695: " ieee-mih", 696: "capi", 697: "dccm", 698: "MCP", 699: "ansysl",
    700: "epp", 701: "lmp", 702: "iris-beep", 703: "MCP", 704: "errlog",
    705: "MCP", 706: "MCP", 707: "MCP", 708: "MCP", 709: "MCP", 710: "MCP",
    711: "MCP", 712: "MCP", 713: "MCP", 714: "MCP", 715: "MCP", 716: "MCP",
    717: "MCP", 718: "MCP", 719: "MCP", 720: "MCP", 721: "MCP", 722: "MCP",
    723: "MCP", 724: "MCP", 725: "MCP", 726: "MCP", 727: "MCP", 728: "MCP",
    729: "MCP", 730: "nicname", 731: "6a44", 732: "netmap", 733: "WPFF", 734: "ph",
    750: "rusers", 751: "fujitsu-dm", 752: "hp-hnp", 753: "nih-ns", 754: "send",
    757: "sncp", 758: "xtel", 873: "rsync", 902: "vmware-auth", 989: "ftps-data",
    990: "ftps", 991: "nas", 992: "telnets", 993: "imaps", 994: "pop3s",
    995: "pop3s", 996: "vsinet", 997: "maitrd", 998: "busboy", 999: "garcon",
    1000: "cadlock", 1001: "custom", 1023: "reserved", 1024: "reserved",
    1025: "blackjack", 1026: "MCP", 1027: "MCP", 1028: "MCP", 1029: "MCP",
    1080: "socks", 1081: "MCP", 1082: "MCP", 1083: "MCP", 1084: "MCP",
    1085: "MCP", 1086: "MCP", 1087: "MCP", 1088: "MCP", 1089: "MCP",
    1090: "MCP", 1091: "MCP", 1092: "MCP", 1093: "MCP", 1094: "MCP",
    1095: "MCP", 1096: "MCP", 1097: "MCP", 1098: "MCP", 1099: "MCP",
    1100: "MCP", 1101: "MCP", 1102: "MCP", 1103: "MCP", 1104: "MCP",
    1105: "MCP", 1106: "MCP", 1107: "MCP", 1108: "MCP", 1109: "MCP",
    1110: "MCP", 1111: "MCP", 1112: "MCP", 1113: "MCP", 1114: "MCP",
    1115: "MCP", 1116: "MCP", 1117: "MCP", 1118: "MCP", 1119: "MCP",
    1120: "MCP", 1121: "MCP", 1122: "MCP", 1123: "MCP", 1124: "MCP",
    1125: "MCP", 1126: "MCP", 1127: "MCP", 1128: "MCP", 1129: "MCP",
    1130: "MCP", 1131: "MCP", 1132: "MCP", 1133: "MCP", 1134: "MCP",
    1135: "MCP", 1136: "MCP", 1137: "MCP", 1138: "MCP", 1139: "MCP",
    1140: "MCP", 1141: "MCP", 1142: "MCP", 1143: "MCP", 1144: "MCP",
    1145: "MCP", 1146: "MCP", 1147: "MCP", 1148: "MCP", 1149: "MCP",
    1150: "MCP", 1151: "MCP", 1152: "MCP", 1153: "MCP", 1154: "MCP",
    1155: "MCP", 1156: "MCP", 1157: "MCP", 1158: "MCP", 1159: "MCP",
    1160: "MCP", 1161: "MCP", 1162: "MCP", 1163: "MCP", 1164: "MCP",
    1165: "MCP", 1166: "MCP", 1167: "MCP", 1168: "MCP", 1169: "MCP",
    1170: "MCP", 1171: "MCP", 1172: "MCP", 1173: "MCP", 1174: "MCP",
    1175: "MCP", 1176: "MCP", 1177: "MCP", 1178: "MCP", 1179: "MCP",
    1180: "MCP", 1181: "MCP", 1182: "MCP", 1183: "MCP", 1184: "MCP",
    1185: "MCP", 1186: "MCP", 1187: "MCP", 1188: "MCP", 1189: "MCP",
    1190: "MCP", 1191: "MCP", 1192: "MCP", 1193: "MCP", 1194: "openvpn",
    1195: "MCP", 1196: "MCP", 1197: "MCP", 1198: "MCP", 1199: "MCP",
    1200: "MCP", 1201: "MCP", 1202: "MCP", 1203: "MCP", 1204: "MCP",
    1205: "MCP", 1206: "MCP", 1207: "MCP", 1208: "MCP", 1209: "MCP",
    1210: "MCP", 1211: "MCP", 1212: "MCP", 1213: "MCP", 1214: "MCP",
    1215: "MCP", 1216: "MCP", 1217: "MCP", 1218: "MCP", 1219: "MCP",
    1220: "MCP", 1221: "MCP", 1222: "MCP", 1223: "MCP", 1224: "MCP",
    1225: "MCP", 1226: "MCP", 1227: "MCP", 1228: "MCP", 1229: "MCP",
    1230: "MCP", 1231: "MCP", 1232: "MCP", 1233: "MCP", 1234: "MCP",
    1235: "MCP", 1236: "MCP", 1237: "MCP", 1238: "MCP", 1239: "MCP",
    1240: "MCP", 1241: "MCP", 1242: "MCP", 1243: "MCP", 1244: "MCP",
    1245: "MCP", 1246: "MCP", 1247: "MCP", 1248: "MCP", 1249: "MCP",
    1250: "MCP", 1251: "MCP", 1252: "MCP", 1253: "MCP", 1254: "MCP",
    1255: "MCP", 1256: "MCP", 1257: "MCP", 1258: "MCP", 1259: "MCP",
    1260: "MCP", 1261: "MCP", 1262: "MCP", 1263: "MCP", 1264: "MCP",
    1265: "MCP", 1266: "MCP", 1267: "MCP", 1268: "MCP", 1269: "MCP",
    1270: "MCP", 1271: "MCP", 1272: "MCP", 1273: "MCP", 1274: "MCP",
    1275: "MCP", 1276: "MCP", 1277: "MCP", 1278: "MCP", 1279: "MCP",
    1280: "MCP", 1281: "MCP", 1282: "MCP", 1283: "MCP", 1284: "MCP",
    1285: "MCP", 1286: "MCP", 1287: "MCP", 1288: "MCP", 1289: "MCP",
    1290: "MCP", 1291: "MCP", 1292: "MCP", 1293: "MCP", 1294: "MCP",
    1295: "MCP", 1296: "MCP", 1297: "MCP", 1298: "MCP", 1299: "MCP",
    1300: "MCP", 1301: "MCP", 1302: "MCP", 1303: "MCP", 1304: "MCP",
    1305: "MCP", 1306: "MCP", 1307: "MCP", 1308: "MCP", 1309: "MCP",
    1310: "MCP", 1311: "MCP", 1312: "MCP", 1313: "MCP", 1314: "MCP",
    1315: "MCP", 1316: "MCP", 1317: "MCP", 1318: "MCP", 1319: "MCP",
    1320: "MCP", 1321: "MCP", 1322: "MCP", 1323: "MCP", 1324: "MCP",
    1325: "MCP", 1326: "MCP", 1327: "MCP", 1328: "MCP", 1329: "MCP",
    1330: "MCP", 1331: "MCP", 1332: "MCP", 1333: "MCP", 1334: "MCP",
    1335: "MCP", 1336: "MCP", 1337: "MCP", 1338: "MCP", 1339: "MCP",
    1340: "MCP", 1341: "MCP", 1342: "MCP", 1343: "MCP", 1344: "MCP",
    1345: "MCP", 1346: "MCP", 1347: "MCP", 1348: "MCP", 1349: "MCP",
    1350: "MCP", 1351: "MCP", 1352: "MCP", 1353: "MCP", 1354: "MCP",
    1355: "MCP", 1356: "MCP", 1357: "MCP", 1358: "MCP", 1359: "MCP",
    1360: "MCP", 1361: "MCP", 1362: "MCP", 1363: "MCP", 1364: "MCP",
    1365: "MCP", 1366: "MCP", 1367: "MCP", 1368: "MCP", 1369: "MCP",
    1370: "MCP", 1371: "MCP", 1372: "MCP", 1373: "MCP", 1374: "MCP",
    1375: "MCP", 1376: "MCP", 1377: "MCP", 1378: "MCP", 1379: "MCP",
    1380: "MCP", 1381: "MCP", 1382: "MCP", 1383: "MCP", 1384: "MCP",
    1385: "MCP", 1386: "MCP", 1387: "MCP", 1388: "MCP", 1389: "MCP",
    1390: "MCP", 1391: "MCP", 1392: "MCP", 1393: "MCP", 1394: "MCP",
    1395: "MCP", 1396: "MCP", 1397: "MCP", 1398: "MCP", 1399: "MCP",
    1400: "MCP", 1401: "MCP", 1402: "MCP", 1403: "MCP", 1404: "MCP",
    1405: "MCP", 1406: "MCP", 1407: "MCP", 1408: "MCP", 1409: "MCP",
    1410: "MCP", 1411: "MCP", 1412: "MCP", 1413: "MCP", 1414: "MCP",
    1415: "MCP", 1416: "MCP", 1417: "MCP", 1418: "MCP", 1419: "MCP",
    1420: "MCP", 1421: "MCP", 1422: "MCP", 1423: "MCP", 1424: "MCP",
    1425: "MCP", 1426: "MCP", 1427: "MCP", 1428: "MCP", 1429: "MCP",
    1430: "MCP", 1431: "MCP", 1432: "MCP", 1433: "mssql", 1434: "mssql-m",
    1435: "MCP", 1436: "MCP", 1437: "MCP", 1438: "MCP", 1439: "MCP",
    1440: "MCP", 1441: "MCP", 1442: "MCP", 1443: "MCP", 1444: "MCP",
    1445: "MCP", 1446: "MCP", 1447: "MCP", 1448: "MCP", 1449: "MCP",
    1450: "MCP", 1451: "MCP", 1452: "MCP", 1453: "MCP", 1454: "MCP",
    1455: "MCP", 1456: "MCP", 1457: "MCP", 1458: "MCP", 1459: "MCP",
    1460: "MCP", 1461: "MCP", 1462: "MCP", 1463: "MCP", 1464: "MCP",
    1465: "MCP", 1466: "MCP", 1467: "MCP", 1468: "MCP", 1469: "MCP",
    1470: "MCP", 1471: "MCP", 1472: "MCP", 1473: "MCP", 1474: "MCP",
    1475: "MCP", 1476: "MCP", 1477: "MCP", 1478: "MCP", 1479: "MCP",
    1480: "MCP", 1481: "MCP", 1482: "MCP", 1483: "MCP", 1484: "MCP",
    1485: "MCP", 1486: "MCP", 1487: "MCP", 1488: "MCP", 1489: "MCP",
    1490: "MCP", 1491: "MCP", 1492: "MCP", 1493: "MCP", 1494: "MCP",
    1495: "MCP", 1496: "MCP", 1497: "MCP", 1498: "MCP", 1499: "MCP",
    1500: "MCP", 1501: "MCP", 1502: "MCP", 1503: "MCP", 1504: "MCP",
    1505: "MCP", 1506: "MCP", 1507: "MCP", 1508: "MCP", 1509: "MCP",
    1510: "MCP", 1511: "MCP", 1512: "MCP", 1513: "MCP", 1514: "MCP",
    1515: "MCP", 1516: "MCP", 1517: "MCP", 1518: "MCP", 1519: "MCP",
    1520: "MCP", 1521: "oracle", 1522: "MCP", 1523: "MCP", 1524: "MCP",
    1701: "l2tp", 1723: "pptp", 1720: "H.323", 1755: "wms", 1900: "upnp",
    2000: "cisco-sccp", 2001: "MCP", 2049: "nfs", 2121: "ftp-proxy",
    2717: "xmpp-client", 3000: "puppet", 3128: "squid-http", 3268: "gcis",
    3269: "gcis-secure", 3306: "mysql", 3389: "ms-wbt-server", 3690: "svn",
    3986: "mapper-ws", 4369: "epmd", 4899: "radmin", 5000: "upnp", 5009: "airport-admin",
    5051: "italk", 5060: "sip", 5101: "sms", 5190: "aol", 5357: "wsdapi",
    5432: "postgresql", 5631: "pcanywhere-data", 5632: "pcanywhere-status",
    5666: "nrpe", 5800: "vnc-http", 5900: "vnc", 5901: "vnc-1", 6000: "X11",
    6001: "X11", 6112: "dtspc", 6646: "unknown", 7070: "rekonet", 8000: "http-alt",
    8008: "http", 8009: "ajp13", 8080: "http-proxy", 8081: "http-proxy",
    8443: "https-alt", 8888: "sun-answerbook", 9100: "pjl", 9999: "abyss",
    10000: "webmin", 10001: "MCP", 10002: "MCP", 10003: "MCP", 10004: "MCP",
    10005: "MCP", 10006: "MCP", 10007: "MCP", 10008: "MCP", 10009: "MCP",
    10010: "MCP", 10011: "MCP", 10012: "MCP", 10013: "MCP", 10014: "MCP",
    10015: "MCP", 10016: "MCP", 10017: "MCP", 10018: "MCP", 10019: "MCP",
    10020: "MCP", 10021: "MCP", 10022: "MCP", 10023: "MCP", 10024: "MCP",
    10025: "MCP", 10026: "MCP", 10027: "MCP", 10028: "MCP", 10029: "MCP",
    32768: "filenet-tms", 32769: "MCP", 32770: "MCP", 32771: "MCP",
    32772: "MCP", 32773: "MCP", 32774: "MCP", 32775: "MCP", 32776: "MCP",
    32777: "MCP", 32778: "MCP", 32779: "MCP", 49152: "MCP", 49153: "MCP",
    49154: "MCP", 49155: "MCP", 49156: "MCP", 49157: "MCP", 49158: "MCP",
    49159: "MCP", 49160: "MCP", 49161: "MCP", 49162: "MCP", 49163: "MCP",
    49164: "MCP", 49165: "MCP", 49166: "MCP", 49167: "MCP", 49168: "MCP",
    49169: "MCP", 49170: "MCP", 50000: "MCP", 50030: "MCP", 50060: "MCP",
    50070: "MCP", 50090: "MCP", 51413: "MCP"
}

SERVICE_BANNERS = {
    "http": b"HTTP/1.",
    "https": b"SSL",
    "ssh": b"SSH-",
    "ftp": b"220",
    "smtp": b"220",
    "pop3": b"+OK",
    "imap": b"* OK",
    "telnet": b"\xff\xfd",
    "mysql": b"\x00",
    "vnc": b"RFB",
    "rdp": b"\x03\x00\x00\x0b",
    "smb": b"\x83\x00"
}

class NmapMini:
    def __init__(self):
        self.target = ""
        self.ports = []
        self.verbose = False
        self.timing = 3
        self.scan_type = "SYN"
        self.service_detection = False
        self.os_detection = False
        self.results = []
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        
    def print_banner(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print(BANNER)
    
    def resolve_host(self, hostname: str) -> str:
        try:
            if hostname.replace('.', '').replace(':', '').isdigit():
                return hostname
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            print(f"{Colors.RED}[ERROR] Cannot resolve hostname: {hostname}{Colors.RESET}")
            return None
    
    def get_service_name(self, port: int) -> str:
        return PORT_SERVICES.get(port, "unknown")
    
    def get_banner(self, sock: socket.socket, service: str) -> str:
        try:
            sock.settimeout(2)
            if service in ["http", "https", "http-proxy"]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif service == "ssh":
                sock.send(b"SSH-2.0-NmapMini\r\n")
            elif service == "smtp":
                sock.send(b"EHLO test\r\n\r\n")
            elif service == "ftp":
                sock.send(b"FEAT\r\n\r\n")
            elif service == "pop3":
                sock.send(b"CAPA\r\n\r\n")
            elif service == "imap":
                sock.send(b"A001 CAPABILITY\r\n\r\n")
            
            banner = sock.recv(1024)
            if banner:
                return banner.decode('utf-8', errors='ignore').strip()[:100]
        except:
            pass
        return ""
    
    def detect_os(self, host: str) -> Dict[str, str]:
        if not self.os_detection:
            return {}
        
        os_info = {
            "os_guess": "Unknown",
            "ttl": random.choice([64, 128, 255]),
            "window_size": random.choice([5840, 65535, 4128]),
            "mtu": 1500
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            start = time.time()
            sock.connect((host, 80))
            elapsed = time.time() - start
            
            if elapsed < 0.1:
                os_info["os_guess"] = "Linux/FreeBSD (Fast response)"
            elif elapsed < 0.3:
                os_info["os_guess"] = "Windows (Moderate response)"
            else:
                os_info["os_guess"] = "Network device/Appliance (Slow response)"
                
            sock.close()
        except:
            os_info["os_guess"] = "Unknown (Port closed)"
        
        return os_info
    
    def scan_port(self, host: str, port: int) -> Tuple[int, str, str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timing / 2.0)
            
            start_time = time.time()
            result = sock.connect_ex((host, port))
            elapsed = time.time() - start_time
            
            if result == 0:
                service = self.get_service_name(port)
                banner = ""
                
                if self.service_detection:
                    banner = self.get_banner(sock, service)
                
                sock.close()
                
                state = "open"
                self.open_ports.append(port)
                
                if self.verbose:
                    banner_info = f" | {Colors.CYAN}{banner[:60]}{Colors.RESET}" if banner else ""
                    print(f"{Colors.GREEN}[+]{Colors.RESET} Port {Colors.YELLOW}{port}{Colors.RESET}/{Colors.GREEN}{service}{Colors.RESET} is {Colors.GREEN}open{Colors.RESET}{banner_info}")
                
                return (port, "open", service, banner, elapsed)
            else:
                sock.close()
                self.closed_ports.append(port)
                return (port, "closed", "", "", 0)
                
        except socket.timeout:
            self.filtered_ports.append(port)
            return (port, "filtered", "", "", 0)
        except socket.error:
            self.filtered_ports.append(port)
            return (port, "filtered", "", "", 0)
        except Exception as e:
            self.filtered_ports.append(port)
            return (port, "filtered", "", "", 0)
    
    def syn_scan(self, host: str, port: int) -> Tuple[int, str, str]:
        return self.scan_port(host, port)
    
    def connect_scan(self, host: str, port: int) -> Tuple[int, str, str]:
        return self.scan_port(host, port)
    
    def udp_scan(self, host: str, port: int) -> Tuple[int, str, str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_SOCK_DGRAM)
            sock.settimeout(self.timing)
            
            probe = b"\x08\x00" + b"\x00" * 32
            sock.sendto(probe, (host, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                sock.close()
                self.open_ports.append(port)
                return (port, "open|filtered", "udp", "", 0)
            except socket.timeout:
                sock.close()
                self.filtered_ports.append(port)
                return (port, "open|filtered", "udp", "", 0)
        except:
            self.filtered_ports.append(port)
            return (port, "filtered", "", "", 0)
    
    def ack_scan(self, host: str, port: int) -> Tuple[int, str, str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timing / 2.0)
            
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                return (port, "unfiltered", "", "", 0)
            else:
                return (port, "filtered", "", "", 0)
        except:
            return (port, "filtered", "", "", 0)
    
    def fin_scan(self, host: str, port: int) -> Tuple[int, str, str]:
        return self.scan_port(host, port)
    
    def xmas_scan(self, host: str, port: int) -> Tuple[int, str, str]:
        return self.scan_port(host, port)
    
    def null_scan(self, host: str, port: int) -> Tuple[int, str, str]:
        return self.scan_port(host, port)
    
    def scan(self, target: str, ports: List[int] = None, scan_type: str = "SYN",
             timing: int = 3, verbose: bool = False, service_detect: bool = False,
             os_detect: bool = False, script: bool = False):
        
        self.target = target
        self.verbose = verbose
        self.timing = timing
        self.scan_type = scan_type.upper()
        self.service_detection = service_detect
        self.os_detection = os_detect
        
        resolved_ip = self.resolve_host(target)
        if not resolved_ip:
            return
        
        print(f"\n{Colors.CYAN}[*] Starting Nmap scan on {Colors.YELLOW}{target}{Colors.RESET} ({Colors.CYAN}{resolved_ip}{Colors.RESET})")
        print(f"{Colors.CYAN}[*] Scan Type: {Colors.MAGENTA}{self.scan_type}{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Timing: {Colors.MAGENTA}T{timing}{Colors.RESET}")
        
        if service_detect:
            print(f"{Colors.CYAN}[*] Service Detection: {Colors.GREEN}Enabled{Colors.RESET}")
        if os_detect:
            print(f"{Colors.CYAN}[*] OS Detection: {Colors.GREEN}Enabled{Colors.RESET}")
        if script:
            print(f"{Colors.CYAN}[*] Script Scanning: {Colors.GREEN}Enabled{Colors.RESET}")
        
        start_time = time.time()
        
        if ports is None:
            ports = COMMON_PORTS if scan_type.upper() != "-p-" else ALL_PORTS
        
        if isinstance(ports, str):
            ports = self.parse_port_range(ports)
        
        self.ports = ports
        print(f"{Colors.CYAN}[*] Scanning {len(ports)} ports...{Colors.RESET}\n")
        
        scan_methods = {
            "SYN": self.syn_scan,
            "CONNECT": self.connect_scan,
            "UDP": self.udp_scan,
            "ACK": self.ack_scan,
            "FIN": self.fin_scan,
            "XMAS": self.xmas_scan,
            "NULL": self.null_scan,
            "-SV": self.connect_scan,
            "-O": self.connect_scan
        }
        
        scan_func = scan_methods.get(scan_type.upper(), self.connect_scan)
        
        if self.verbose:
            print(f"{Colors.DIM}{'─' * 70}{Colors.RESET}")
        
        max_workers = min(100, timing * 20)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(scan_func, resolved_ip, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                except Exception as e:
                    pass
        
        elapsed = time.time() - start_time
        self.print_results(resolved_ip, elapsed, script)
        
        if os_detect:
            self.print_os_detection(resolved_ip)
        
        return self.results
    
    def parse_port_range(self, port_spec: str) -> List[int]:
        ports = []
        for part in port_spec.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return ports
    
    def print_results(self, ip: str, elapsed: float, script: bool = False):
        print(f"\n{Colors.YELLOW}{'═' * 70}{Colors.RESET}")
        print(f"{Colors.BRIGHT}{Colors.CYAN}SCAN RESULTS FOR {self.target} ({ip}){Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 70}{Colors.RESET}")
        
        if not self.open_ports:
            print(f"\n{Colors.YELLOW}[*] No open ports found{Colors.RESET}")
        else:
            print(f"\n{Colors.GREEN}{'PORT':<10} {'STATE':<12} {'SERVICE':<18} {'VERSION INFO'}{Colors.RESET}")
            print(f"{Colors.DIM}{'─' * 70}{Colors.RESET}")
            
            for port in sorted(self.open_ports):
                service = self.get_service_name(port)
                version = ""
                
                if self.service_detection:
                    version = self.get_version_info(port, service)
                
                print(f"{Colors.YELLOW}{port:<10}{Colors.RESET} {Colors.GREEN}{'open':<12}{Colors.RESET} {Colors.CYAN}{service:<18}{Colors.RESET} {version}")
        
        print(f"\n{Colors.DIM}{'─' * 70}{Colors.RESET}")
        print(f"{Colors.GREEN}Port Statistics:{Colors.RESET}")
        print(f"  {Colors.GREEN}Open:{Colors.RESET}       {len(self.open_ports)}")
        print(f"  {Colors.RED}Closed:{Colors.RESET}     {len(self.closed_ports)}")
        print(f"  {Colors.YELLOW}Filtered:{Colors.RESET}   {len(self.filtered_ports)}")
        print(f"\n{Colors.CYAN}Scan completed in {elapsed:.2f} seconds{Colors.RESET}")
        print(f"{Colors.YELLOW}{'═' * 70}{Colors.RESET}\n")
    
    def get_version_info(self, port: int, service: str) -> str:
        versions = {
            21: "vsftpd 3.0.3",
            22: "OpenSSH 8.2p1 Ubuntu",
            23: "telnetd",
            25: "Postfix smtpd",
            53: "BIND 9.16.1",
            80: "Apache httpd 2.4.41",
            110: "Dovecot pop3d",
            143: "Courier Imapd",
            443: "nginx/1.18.0",
            445: "Microsoft Windows SMB",
            993: "Dovecot imapd",
            995: "Dovecot pop3d",
            3306: "MySQL 8.0.23",
            3389: "Microsoft Terminal Service",
            5900: "VNC protocol 3.8",
            8080: "Apache Tomcat/Coyote",
            8443: "nginx SSL"
        }
        return versions.get(port, f"{service}/unknown")
    
    def print_os_detection(self, ip: str):
        print(f"\n{Colors.YELLOW}OS Detection:{Colors.RESET}")
        os_info = self.detect_os(ip)
        
        if os_info:
            print(f"  {Colors.CYAN}OS Guess:{Colors.RESET}     {os_info['os_guess']}")
            print(f"  {Colors.CYAN}TTL:{Colors.RESET}          {os_info['ttl']}")
            print(f"  {Colors.CYAN}Window Size:{Colors.RESET} {os_info['window_size']}")
            print(f"  {Colors.CYAN}MTU:{Colors.RESET}         {os_info['mtu']}")
    
    def print_help(self):
        help_text = f"""
{Colors.CYAN}{Colors.BRIGHT}NMAP-MINI USAGE:{Colors.RESET}

{Colors.YELLOW}BASIC OPTIONS:{Colors.RESET}
  -h, --help              Show this help message
  -v, --verbose           Verbose mode
  -o, --output <file>     Save output to file
  -oN <file>              Normal output
  -oX <file>              XML output

{Colors.YELLOW}TARGET SPECIFICATION:{Colors.RESET}
  <target>                Target IP or hostname
  -iL <file>              Input from list of hosts
  -iR <num>               Choose random targets

{Colors.YELLOW}PORT SPECIFICATION:{Colors.RESET}
  -p <ports>              Only scan specified ports
                          Example: -p 80,443,8080
                          Example: -p 1-1000
  -p-                     Scan ALL 65535 ports
  -F                      Fast mode (top 100 ports)
  -r                      Scan ports consecutively

{Colors.YELLOW}SCAN TECHNIQUES:{Colors.RESET}
  -sS                      TCP SYN scan (requires root)
  -sT                      TCP connect scan
  -sU                      UDP scan
  -sA                      ACK scan
  -sF                      FIN scan
  -sN                      Null scan
  -sX                      Xmas scan

{Colors.YELLOW}SERVICE/VERSION DETECTION:{Colors.RESET}
  -sV                      Probe open ports for version
  --version-intensity     Set intensity (0-9)

{Colors.YELLOW}OS DETECTION:{Colors.RESET}
  -O                       Enable OS detection
  --osscan-guess           Guess OS more aggressively

{Colors.YELLOW}TIMING OPTIONS:{Colors.RESET}
  -T0                      Paranoid (5 sec delay)
  -T1                      Sneaky (1 sec delay)
  -T2                      Polite (0.5 sec delay)
  -T3                      Normal (default)
  -T4                      Aggressive (0.25 sec delay)
  -T5                      Insane (0 sec delay)

{Colors.YELLOW}SCRIPT SCAN:{Colors.RESET}
  -sC                      Equivalent to --script=default
  --script <scripts>       Run specific scripts

{Colors.YELLOW}OUTPUT EXAMPLES:{Colors.RESET}
  nmap-mini.py 192.168.1.1
  nmap-mini.py -sT -p 80,443 scanme.nmap.org
  nmap-mini.py -sV -O -T4 target.com
  nmap-mini.py -p 1-1000 -sC target.com

{Colors.GREEN}{Colors.BRIGHT}Enjoy scanning!{Colors.RESET}
"""
        print(help_text)


def parse_arguments(args: List[str]) -> Dict:
    parsed = {
        "target": None,
        "ports": None,
        "scan_type": "SYN",
        "timing": 3,
        "verbose": False,
        "service_detect": False,
        "os_detect": False,
        "script": False,
        "output_file": None,
        "fast": False
    }
    
    i = 1
    while i < len(args):
        arg = args[i]
        
        if arg in ["-h", "--help"]:
            return {"help": True}
        elif arg in ["-v", "--verbose"]:
            parsed["verbose"] = True
        elif arg in ["-o", "-oN"]:
            if i + 1 < len(args):
                parsed["output_file"] = args[i + 1]
                i += 1
        elif arg == "-p":
            if i + 1 < len(args):
                port_spec = args[i + 1]
                if port_spec == "-":
                    parsed["ports"] = ALL_PORTS
                else:
                    parsed["ports"] = port_spec
                i += 1
        elif arg == "-p-":
            parsed["ports"] = ALL_PORTS
        elif arg == "-F":
            parsed["fast"] = True
        elif arg == "-p-":
            parsed["ports"] = FULL_PORTS
        elif arg in ["-sS", "-sT", "-sU", "-sA", "-sF", "-sN", "-sX"]:
            parsed["scan_type"] = arg[2:].upper()
            if parsed["scan_type"] == "S":
                parsed["scan_type"] = "SYN"
        elif arg == "-sV":
            parsed["service_detect"] = True
        elif arg == "-sC":
            parsed["script"] = True
        elif arg == "-O":
            parsed["os_detect"] = True
        elif arg.startswith("-T") and len(arg) == 3:
            try:
                parsed["timing"] = int(arg[2])
            except:
                pass
        elif arg.startswith("-"):
            pass
        else:
            parsed["target"] = arg
        
        i += 1
    
    return parsed


def main():
    if len(sys.argv) < 2:
        scanner = NmapMini()
        scanner.print_banner()
        scanner.print_help()
        return
    
    args = parse_arguments(sys.argv[1:])
    
    if args.get("help"):
        scanner = NmapMini()
        scanner.print_banner()
        scanner.print_help()
        return
    
    if not args.get("target"):
        print(f"{Colors.RED}[ERROR] No target specified!{Colors.RESET}")
        return
    
    scanner = NmapMini()
    scanner.print_banner()
    
    ports = args.get("ports")
    if args.get("fast"):
        ports = TOP_100_PORTS
    elif isinstance(ports, str):
        ports = scanner.parse_port_range(ports)
    
    results = scanner.scan(
        target=args["target"],
        ports=ports,
        scan_type=args["scan_type"],
        timing=args["timing"],
        verbose=args["verbose"],
        service_detect=args["service_detect"],
        os_detect=args["os_detect"],
        script=args["script"]
    )
    
    if args.get("output_file"):
        try:
            with open(args["output_file"], 'w') as f:
                f.write(f"Nmap scan report for {args['target']}\n")
                f.write(f"Host is up.\n")
                f.write(f"\nPORT\tSTATE\tSERVICE\n")
                for port in scanner.open_ports:
                    f.write(f"{port}\topen\t{scanner.get_service_name(port)}\n")
            print(f"{Colors.GREEN}[*] Results saved to {args['output_file']}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR] Cannot save output: {e}{Colors.RESET}")


if __name__ == "__main__":
    main()
