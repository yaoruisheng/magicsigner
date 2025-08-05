# MagicSigner

一个用于 signtool 的补丁 DLL，允许使用 **已过期的证书** 进行签名。

---

## 一、构建 32 位 DLL

1. 打开 `x86 Native Tools Command Prompt for VS 2022`
2. 进入项目目录：
   ```cmd
   cd MagicSigner
   ```
3. 执行以下命令：
   ```cmd
   cmake -S . -B build32 -A Win32
   cmake --build build32 --config Release
   ```

---

## 二、构建 64 位 DLL

1. 进入项目目录：
   ```cmd
   cd MagicSigner
   ```
2. 执行以下命令：
   ```cmd
   cmake -S . -B build64 -A x64
   cmake --build build64 --config Release
   ```

---

## 使用方法

将生成的 `XmlLite.dll` 放在 `signtool.exe` 所在目录，即可自动生效。

---

## 效果演示

略
---

## 替代方案

你也可以通过**将系统时间调回证书有效期内**来绕过验证。

但此方法存在以下问题：

- 需要管理员权限；
- 容易影响其他程序，尤其是使用 HTTPS 等 TLS 通信的服务；
- 可能导致大量证书校验失败。

---

## 如何防御这种技术

启用微软官方提供的  
[驱动程序阻止列表（Microsoft Vulnerable Driver Blocklist）](https://learn.microsoft.com/zh-cn/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)  
该列表包含了所有已知泄露的证书。

---

## License 

This project is based on the open source projects  
https://github.com/namazso/MagicSigner and https://github.com/microsoft/Detours.  
Thanks to the original authors for their contributions.

Copyright of the modifications and new code in this project belong to yaoruisheng,  
licensed under BSD Zero Clause License.

By using this project, you agree to comply with the applicable open source licenses.

Thanks to ChatGPT and OpenAI for technical support and assistance.

---

##许可证

本项目基于开源项目 https://github.com/namazso/MagicSigner 以及 https://github.com/microsoft/Detours，感谢原作者的贡献。

本项目中修改及新增的代码版权归 yaoruisheng 所有，遵循 BSD Zero Clause License 许可。

使用本项目即表示同意遵守相应开源协议。

感谢 ChatGPT/OpenAI 的技术支持与协助。
