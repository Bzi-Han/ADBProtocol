#ifndef LOG_H // !LOG_H
#define LOG_H

#include <stdio.h>

#if defined(ANDROID) || defined(__ANDROID__)
#include <android/log.h>
#include <jni.h>
#define Log(type, format, ...) __android_log_print(ANDROID_LOG_INFO, "ADBProtocol", ("[ADBProtocol] " type format), ##__VA_ARGS__)
#else
#define Log(type, format, ...) printf(("[ADBProtocol] " type format "\n"), ##__VA_ARGS__)
#endif

#define LogOperation(format, ...) Log("[*] ", format, ##__VA_ARGS__)
#define LogInfo(format, ...) Log("[=] ", format, ##__VA_ARGS__)
#define LogFailed(format, ...) Log("[-] ", format, ##__VA_ARGS__)
#define LogError(format, ...) Log("[!] ", format, ##__VA_ARGS__)
#define LogSucceeded(format, ...) Log("[+] ", format, ##__VA_ARGS__)

#endif // !LOG_H