//
// Created by sven on 4/5/17.
//

#include "hardware.h"

#ifdef _WIN32
#include <string>
#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#if _MSC_VER >=1400    // VC2005才支持intrin.h
#include <intrin.h>    // 所有Intrinsics函数
#endif
#else
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string>
#include <memory.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/hdreg.h>
#endif

#ifndef _WIN32
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#include <sys/socket.h>
#endif

namespace tinker {

#ifdef _WIN32

// IOCTL
#if(_WIN32_WINNT < 0x0400)
#define SMART_GET_VERSION				0x00074080
#define SMART_RCV_DRIVE_DATA			0x0007c088
#endif
#define FILE_DEVICE_SCSI				0x0000001b
#define IOCTL_SCSI_MINIPORT_IDENTIFY	((FILE_DEVICE_SCSI << 16) + 0x0501)
#define IOCTL_SCSI_MINIPORT				0x0004D008

// IDEREGS
#define IDE_ATAPI_IDENTIFY		0xA1
#define IDE_ATA_IDENTIFY		0xEC
#define IDENTIFY_BUFFER_SIZE	512
#define SENDIDLENGTH			sizeof(SENDCMDOUTPARAMS) + IDENTIFY_BUFFER_SIZE

typedef struct _GETVERSIONOUTPARAMS {
  BYTE bVersion;
  BYTE bRevision;
  BYTE bReserved;
  BYTE bIDEDeviceMap;
  DWORD fCapabilities;
  DWORD dwReserved[4];
} GETVERSIONOUTPARAMS, *PGETVERSIONOUTPARAMS, *LPGETVERSIONOUTPARAMS;

typedef struct _IDSECTOR {
  USHORT  wGenConfig;
  USHORT  wNumCyls;
  USHORT  wReserved;
  USHORT  wNumHeads;
  USHORT  wBytesPerTrack;
  USHORT  wBytesPerSector;
  USHORT  wSectorsPerTrack;
  USHORT  wVendorUnique[3];
  CHAR    sSerialNumber[20];
  USHORT  wBufferType;
  USHORT  wBufferSize;
  USHORT  wECCSize;
  CHAR    sFirmwareRev[8];
  CHAR    sModelNumber[40];
  USHORT  wMoreVendorUnique;
  USHORT  wDoubleWordIO;
  USHORT  wCapabilities;
  USHORT  wReserved1;
  USHORT  wPIOTiming;
  USHORT  wDMATiming;
  USHORT  wBS;
  USHORT  wNumCurrentCyls;
  USHORT  wNumCurrentHeads;
  USHORT  wNumCurrentSectorsPerTrack;
  ULONG   ulCurrentSectorCapacity;
  USHORT  wMultSectorStuff;
  ULONG   ulTotalAddressableSectors;
  USHORT  wSingleWordDMA;
  USHORT  wMultiWordDMA;
  BYTE    bReserved[128];
} IDSECTOR, *PIDSECTOR;

typedef struct _SRB_IO_CONTROL {
  ULONG HeaderLength;
  UCHAR Signature[8];
  ULONG Timeout;
  ULONG ControlCode;
  ULONG ReturnCode;
  ULONG Length;
} SRB_IO_CONTROL, *PSRB_IO_CONTROL;

#if(_WIN32_WINNT < 0x0400)
typedef struct _DRIVERSTATUS {
  UCHAR bDriverError;
  UCHAR bIDEError;
  UCHAR bReserved[2];
  ULONG dwReserved[2];
} DRIVERSTATUS, *PDRIVERSTATUS, *LPDRIVERSTATUS;

typedef struct _SENDCMDOUTPARAMS {
  ULONG        cBufferSize;
  DRIVERSTATUS DriverStatus;
  UCHAR        bBuffer[1];
} SENDCMDOUTPARAMS, *PSENDCMDOUTPARAMS, *LPSENDCMDOUTPARAMS;

typedef struct _IDEREGS {
  UCHAR bFeaturesReg;
  UCHAR bSectorCountReg;
  UCHAR bSectorNumberReg;
  UCHAR bCylLowReg;
  UCHAR bCylHighReg;
  UCHAR bDriveHeadReg;
  UCHAR bCommandReg;
  UCHAR bReserved;
} IDEREGS, *PIDEREGS, *LPIDEREGS;

typedef struct _SENDCMDINPARAMS {
  ULONG   cBufferSize;
  IDEREGS irDriveRegs;
  UCHAR   bDriveNumber;
  UCHAR   bReserved[3];
  ULONG   dwReserved[4];
  UCHAR   bBuffer[1];
} SENDCMDINPARAMS, *PSENDCMDINPARAMS, *LPSENDCMDINPARAMS;
#endif

// 获取IDE硬盘序列号(只支持Windows NT/2000/XP以上操作系统)
bool GetIDEHDSerial(int driveNum, std::string& serialNum) {
  BYTE IdOutCmd[sizeof(SENDCMDOUTPARAMS) + IDENTIFY_BUFFER_SIZE - 1];
  bool bFlag = false;
  char driveName[32];
  HANDLE hDevice = 0;

  sprintf_s(driveName, 32, "\\\\.\\PhysicalDrive%d", driveNum);
  // 创建文件需要管理员权限
  hDevice = CreateFileA(driveName, GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
  if (hDevice != INVALID_HANDLE_VALUE) {
    GETVERSIONOUTPARAMS versionParams;
    DWORD bytesReturned = 0;
    // 得到驱动器的IO控制器版本
    memset((void*)&versionParams, 0, sizeof(versionParams));
    if (DeviceIoControl(hDevice, SMART_GET_VERSION, NULL, 0,
      &versionParams, sizeof(versionParams), &bytesReturned, NULL)) {
      if (versionParams.bIDEDeviceMap > 0) {
        BYTE bIDCmd = 0;   // IDE或者ATAPI识别命令
        SENDCMDINPARAMS scip;

        // 如果驱动器是光驱，采用命令IDE_ATAPI_IDENTIFY
        // 否则采用命令IDE_ATA_IDENTIFY读取驱动器信息
        bIDCmd = (versionParams.bIDEDeviceMap >> driveNum & 0x10) ? IDE_ATAPI_IDENTIFY : IDE_ATA_IDENTIFY;
        memset(&scip, 0, sizeof(scip));
        memset(IdOutCmd, 0, sizeof(IdOutCmd));
        // 为读取设备信息准备参数
        scip.cBufferSize = IDENTIFY_BUFFER_SIZE;
        scip.irDriveRegs.bFeaturesReg = 0;
        scip.irDriveRegs.bSectorCountReg = 1;
        scip.irDriveRegs.bSectorNumberReg = 1;
        scip.irDriveRegs.bCylLowReg = 0;
        scip.irDriveRegs.bCylHighReg = 0;
        // 计算驱动器位置
        scip.irDriveRegs.bDriveHeadReg = 0xA0 | (((BYTE)driveNum & 1) << 4);
        // 设置读取命令
        scip.irDriveRegs.bCommandReg = bIDCmd;
        scip.bDriveNumber = (BYTE)driveNum;
        scip.cBufferSize = IDENTIFY_BUFFER_SIZE;

        // 读取驱动器信息
        if (DeviceIoControl(hDevice, SMART_RCV_DRIVE_DATA,
          (LPVOID)&scip, sizeof(SENDCMDINPARAMS) - 1, (LPVOID)&IdOutCmd,
          sizeof(SENDCMDOUTPARAMS) + IDENTIFY_BUFFER_SIZE - 1,
          &bytesReturned, NULL)) {
          USHORT *pIdSector = (USHORT *)((PSENDCMDOUTPARAMS)IdOutCmd)->bBuffer;

          int nIndex = 0, nPosition = 0;
          char szSeq[32] = { 0 };
          for (nIndex = 10; nIndex < 20; nIndex++) {
            szSeq[nPosition] = (unsigned char)(pIdSector[nIndex] / 256);
            nPosition++;
            szSeq[nPosition] = (unsigned char)(pIdSector[nIndex] % 256);
            nPosition++;
          }
          serialNum = szSeq;
          serialNum.erase(0, serialNum.find_first_not_of(" "));
          bFlag = true;  // 读取硬盘信息成功
        }
      }
    }
    CloseHandle(hDevice);  // 关闭句柄
  }
  return bFlag;
}

// 获取SCSI硬盘序列号(只支持Windows NT/2000/XP以上操作系统)
bool GetSCSIHDSerial(int driveNum, std::string& serialNum) {
  bool bFlag = false;
  int controller = driveNum;
  HANDLE hDevice = 0;
  char driveName[32];
  sprintf_s(driveName, 32, "\\\\.\\Scsi%d:", controller);
  hDevice = CreateFileA(driveName, GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
  if (hDevice != INVALID_HANDLE_VALUE) {
    DWORD dummy;
    for (int drive = 0; drive < 2; drive++) {
      char buffer[sizeof(SRB_IO_CONTROL) + SENDIDLENGTH];
      SRB_IO_CONTROL *p = (SRB_IO_CONTROL *)buffer;
      SENDCMDINPARAMS *pin = (SENDCMDINPARAMS *)(buffer + sizeof(SRB_IO_CONTROL));
      // 准备参数
      memset(buffer, 0, sizeof(buffer));
      p->HeaderLength = sizeof(SRB_IO_CONTROL);
      p->Timeout = 10000;
      p->Length = SENDIDLENGTH;
      p->ControlCode = IOCTL_SCSI_MINIPORT_IDENTIFY;
      strncpy_s((char *)p->Signature, 9, "SCSIDISK", 9);
      pin->irDriveRegs.bCommandReg = IDE_ATA_IDENTIFY;
      pin->bDriveNumber = drive;
      // 得到SCSI硬盘信息
      if (DeviceIoControl(hDevice, IOCTL_SCSI_MINIPORT, buffer,
        sizeof(SRB_IO_CONTROL) + sizeof(SENDCMDINPARAMS) - 1,
        buffer, sizeof(SRB_IO_CONTROL) + SENDIDLENGTH, &dummy, NULL)) {
        SENDCMDOUTPARAMS *pOut = (SENDCMDOUTPARAMS *)(buffer + sizeof(SRB_IO_CONTROL));
        IDSECTOR *pId = (IDSECTOR *)(pOut->bBuffer);
        if (pId->sModelNumber[0]) {
          USHORT *pIdSector = (USHORT *)pId;
          int nIndex = 0, nPosition = 0;
          char szSeq[32] = { 0 };
          for (nIndex = 10; nIndex < 20; nIndex++) {
            szSeq[nPosition] = (unsigned char)(pIdSector[nIndex] / 256);
            nPosition++;
            szSeq[nPosition] = (unsigned char)(pIdSector[nIndex] % 256);
            nPosition++;
          }
          serialNum = szSeq;
          serialNum.erase(0, serialNum.find_first_not_of(" "));
          bFlag = true;  // 读取硬盘信息成功
          break;
        }
      }
    }
    CloseHandle(hDevice);  // 关闭句柄
  }
  return bFlag;
}

int Hardware::GetCpuID(std::string& cpu_id) {
  char buf[32] = { 0 };
#if 0
  unsigned long s1, s2;
  __asm{
    mov eax, 01h   //eax=1:取CPU序列号
      xor edx, edx
      cpuid
      mov s1, edx
      mov s2, eax
  }
  if (s1) {
    memset(buf, 0, 32);
    sprintf_s(buf, 32, "%08X", s1);
    cpu_id += buf;
  }
  if (s2) {
    memset(buf, 0, 32);
    sprintf_s(buf, 32, "%08X", s2);
    cpu_id += buf;
  }

  __asm{
    mov eax, 03h
      xor ecx, ecx
      xor edx, edx
      cpuid
      mov s1, edx
      mov s2, ecx
  }
  if (s1) {
    memset(buf, 0, 32);
    sprintf_s(buf, 32, "%08X", s1);
    cpu_id += buf;
  }
  if (s2) {
    memset(buf, 0, 32);
    sprintf_s(buf, 32, "%08X", s2);
    cpu_id += buf;
  }
#else
  INT32 dwBuf[4];
  __cpuidex(dwBuf, 01, 0);
  memset(buf, 0, 32);
  sprintf_s(buf, 32, "%08X%08X", dwBuf[3], dwBuf[0]);
  cpu_id = buf;
#endif
  return 0;
}

int Hardware::GetDiskSN(std::string& serial_no) {
  for (int driveNum = 0; driveNum < 5; driveNum++) {
    if (GetIDEHDSerial(driveNum, serial_no) || GetSCSIHDSerial(driveNum, serial_no))
      return 0;
  }
  return -1;
}


int Hardware::GetMac(std::string& mac)
{
  int ret = 0;

  ULONG outBufLen = sizeof(IP_ADAPTER_ADDRESSES);
  PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
  if (pAddresses == NULL)
    return -1;
  // Make an initial call to GetAdaptersAddresses to get the necessary size into the ulOutBufLen variable
  if(GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &outBufLen) == ERROR_BUFFER_OVERFLOW)
  {
    free(pAddresses);
    pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
    if (pAddresses == NULL)
      return -1;
  }

  if(GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &outBufLen) == NO_ERROR)
  {
    // If successful, output some information from the data we received
    for(PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses; pCurrAddresses != NULL; pCurrAddresses = pCurrAddresses->Next)
    {
      // 确保MAC地址的长度为 00-00-00-00-00-00
      if(pCurrAddresses->PhysicalAddressLength != 6)
        continue;
      char acMAC[32];
      _snprintf_s(acMAC, 32, "%02X%02X%02X%02X%02X%02X",
        int (pCurrAddresses->PhysicalAddress[0]),
        int (pCurrAddresses->PhysicalAddress[1]),
        int (pCurrAddresses->PhysicalAddress[2]),
        int (pCurrAddresses->PhysicalAddress[3]),
        int (pCurrAddresses->PhysicalAddress[4]),
        int (pCurrAddresses->PhysicalAddress[5]));
      mac = acMAC;
      ret = true;
      break;
    }
  }

  free(pAddresses);
  return ret;
}

#else

int Hardware::GetCpuID(std::string& cpu_id) {

  unsigned long s1,s2;
  char buf[32] = {0};

  asm volatile(
  "movl $0x01, %%eax;"
      "xorl %%edx, %%edx;"
      "cpuid;"
      "movl %%edx, %0;"
      "movl %%eax, %1;"
  :"=m"(s1), "=m"(s2)
  );
  if (s1) {
    memset(buf, 0, 32);
    snprintf(buf, 32, "%08X", (unsigned int)s1);
    cpu_id += buf;
  }
  if (s2) {
    memset(buf, 0, 32);
    snprintf(buf, 32, "%08X", (unsigned int)s2);
    cpu_id += buf;
  }

  //FIXME(zhangwen): on linux the cpuid is different in different code
  return 0;

  asm volatile(
  "movl $0x03, %%eax;"
      "xorl %%ecx, %%ecx;"
      "xorl %%edx, %%edx;"
      "cpuid;"
      "movl %%edx, %0;"
      "movl %%ecx, %1;"
  :"=m"(s1), "=m"(s2)
  );
  if (s1) {
    memset(buf, 0, 32);
    snprintf(buf, 32, "%08X", (unsigned int)s1);
    cpu_id += buf;
  }
  if (s2) {
    memset(buf, 0, 32);
    snprintf(buf, 32, "%08X", (unsigned int)s2);
    cpu_id += buf;
  }
  return 0;
}


int Hardware::GetDiskSN(std::string& serial_no) {
  int fd;
  struct hd_driveid hid;
  FILE *fp;
  char line[0x100], *disk, *root, *p;

  fp = fopen("/etc/mtab", "r");
  if (fp == NULL) {
    return -1;
  }

  fd = -1;
  while (fgets(line, sizeof line, fp) != NULL) {
    disk = strtok(line, " ");
    if (disk == NULL) {
      continue;
    }

    root = strtok(NULL, " ");
    if (root == NULL) {
      continue;
    }

    if (strcmp(root, "/") == 0) {
      for (p = disk + strlen(disk) - 1; isdigit(*p); p--) {
        *p = '\0';
      }
      fd = open(disk, O_RDONLY);
      break;
    }
  }

  fclose(fp);

  if (fd < 0) {
    return -1;
  }

  if (ioctl(fd, HDIO_GET_IDENTITY, &hid) < 0) {
    return -1;
  }

  close(fd);

  char buf[32] = { 0 };
  snprintf(buf, 32, "%s", hid.serial_no);
  serial_no = buf;
  return 0;
}

int Hardware::GetMac(std::string& mac) {
  int sockfd;
  struct ifreq tmp;
  char mac_addr[32];

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("create socket fail\n");
    return -1;
  }

  bool got = false;
  memset(&tmp, 0, sizeof(struct ifreq));
  strncpy(tmp.ifr_name, "eth0", sizeof(tmp.ifr_name) - 1);
  if ((ioctl(sockfd, SIOCGIFHWADDR, &tmp)) == 0) {
    got = true;
  }

  if (!got) {
    memset(&tmp, 0, sizeof(struct ifreq));
    strncpy(tmp.ifr_name, "em1", sizeof(tmp.ifr_name) - 1);
    if ((ioctl(sockfd, SIOCGIFHWADDR, &tmp)) == 0) {
      got = true;
    }
  }
  close(sockfd);

  if (!got) {
    perror("cannot get mac!\n");
    return -1;
  }

  sprintf(mac_addr, "%02x%02x%02x%02x%02x%02x",
          (unsigned char)tmp.ifr_hwaddr.sa_data[0],
          (unsigned char)tmp.ifr_hwaddr.sa_data[1],
          (unsigned char)tmp.ifr_hwaddr.sa_data[2],
          (unsigned char)tmp.ifr_hwaddr.sa_data[3],
          (unsigned char)tmp.ifr_hwaddr.sa_data[4],
          (unsigned char)tmp.ifr_hwaddr.sa_data[5]
  );
  mac = mac_addr;

  return 0;
}

#endif


int Hardware::GetLocalIp(std::string& ip) {
#ifndef _WIN32
  // linux
  int sockfd;
  struct ifreq tmp;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("create socket fail\n");
    return -1;
  }

  bool got = false;
  memset(&tmp, 0, sizeof(struct ifreq));
  strncpy(tmp.ifr_name, "eth0", sizeof(tmp.ifr_name) - 1);
  if ((ioctl(sockfd, SIOCGIFADDR, &tmp)) == 0) {
    got = true;
  }

  if (!got) {
    memset(&tmp, 0, sizeof(struct ifreq));
    strncpy(tmp.ifr_name, "em1", sizeof(tmp.ifr_name) - 1);
    if ((ioctl(sockfd, SIOCGIFADDR, &tmp)) == 0) {
      got = true;
    }
  }

  if (!got) {
    perror("cannot get mac!\n");
    close(sockfd);
    return -1;
  }
  //ip = std::string(inet_ntoa(((sockaddr_in*)&sa)->sin_addr));
  ip = std::string(inet_ntoa(((sockaddr_in*)&tmp.ifr_ifru.ifru_addr)->sin_addr));

  close(sockfd);
  return 0;
#else
  // win32
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    WSACleanup();
    return -1;
  }
  char local[255] = { 0 };
  gethostname(local, sizeof(local));
  hostent* ph = gethostbyname(local);
  if (ph == NULL) {
    WSACleanup();
    return -1;
  }
  in_addr addr;
  memcpy(&addr, ph->h_addr_list[0], sizeof(in_addr)); // 这里仅获取第一个ip  
  ip.assign(inet_ntoa(addr));

  WSACleanup();
#endif

  return 0;
}

int Hardware::GetNetDevice(std::string& mac, std::string& ip) {
#ifndef _WIN32
  struct ifreq ifr;
  struct ifreq *IFR;
  struct ifconf ifc;
  unsigned int uNICCount = 0;
  char buf[1024];
  char szbuff[16];
  int sock_fd;
  int ok = 0;

  sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock_fd < 0) {
    perror("create socket fail\n");
    return -1;
  }

  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;
  ioctl(sock_fd, SIOCGIFCONF, &ifc);
  uNICCount = ifc.ifc_len / sizeof(struct ifreq);

  IFR = ifc.ifc_req;
  std::string ip_tmp;
  for (size_t i = 0; i < uNICCount; i++,IFR++) {
    strcpy(ifr.ifr_name, IFR->ifr_name);
    if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) == 0) {
      if (!(ifr.ifr_flags & IFF_LOOPBACK)) {
        if (ioctl(sock_fd, SIOCGIFADDR, &ifr) == 0) {
          ip_tmp = std::move(std::string(inet_ntoa(((sockaddr_in*)&ifr.ifr_ifru.ifru_addr)->sin_addr)));
        }
        if (!ip.empty() && (ip_tmp.compare(ip) != 0 && ip.compare("127.0.0.1") != 0)) {
          continue;
        }
        if (ip.compare("127.0.0.1") != 0) {
          ip = std::move(ip_tmp);
        }

        if (ioctl(sock_fd, SIOCGIFHWADDR, &ifr) == 0) {
          sprintf(szbuff,"%02x%02x%02x%02x%02x%02x",
                  (unsigned char)ifr.ifr_hwaddr.sa_data[0],
                  (unsigned char)ifr.ifr_hwaddr.sa_data[1],
                  (unsigned char)ifr.ifr_hwaddr.sa_data[2],
                  (unsigned char)ifr.ifr_hwaddr.sa_data[3],
                  (unsigned char)ifr.ifr_hwaddr.sa_data[4],
                  (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
          mac = szbuff;
          ok = 1;
        }
        else {
          close(sock_fd);
          return 0;
        }
      }
    }
  }
  close(sock_fd);
  if (ok != 0) return -1;
#else
  std::string ip_t = ip;
  if (ip.empty()) {
    GetLocalIp(ip_t);
    ip = ip_t;
  }
  else if (ip.compare("127.0.0.1") == 0) {
    GetLocalIp(ip_t);
  }
  char szMac[64];
  PIP_ADAPTER_INFO pAdapterInfo;
  PIP_ADAPTER_INFO pAdapter = NULL;
  DWORD dwRetVal = 0;
  std::string ip_tmp;
  unsigned long ulOutBufLen;

  pAdapterInfo = (IP_ADAPTER_INFO *) malloc( sizeof(IP_ADAPTER_INFO) );
  ulOutBufLen = sizeof(IP_ADAPTER_INFO);

  if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
    free(pAdapterInfo);
    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
  }

  if ((dwRetVal = GetAdaptersInfo( pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
    pAdapter = pAdapterInfo;
    while (pAdapter) {
      // 网卡可能有多IP,通过循环去判断
      IP_ADDR_STRING *pIpAddrString = &(pAdapter->IpAddressList);
      bool found_ip = false;
      do {
        // todo:
        ip_tmp = pIpAddrString->IpAddress.String;
        if (!ip_t.empty() && ip_tmp.compare(ip_t) != 0) {
          pIpAddrString = pIpAddrString->Next;
          continue;
        }
        found_ip = true;
        break;
      } while (pIpAddrString);

      if (found_ip) {
        memset(szMac, 0, 64);
        sprintf(szMac, "%02x%02x%02x%02x%02x%02x",
          pAdapter->Address[0],
          pAdapter->Address[1],
          pAdapter->Address[2],
          pAdapter->Address[3],
          pAdapter->Address[4],
          pAdapter->Address[5]);
        mac = szMac;
        break;
      }
      pAdapter = pAdapter->Next;
    }
  }
#endif
  return 0;
}

} //namespace tinker
