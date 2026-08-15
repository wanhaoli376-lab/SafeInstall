# Alpha testing guide

SafeInstall v0.2.0-alpha.1 is a public testing release. Windows x64 is the recommended platform.
You do not need Python, a terminal, an account, or an OpenAI API key.

The experimental `SafeInstall-macOS-unsigned.zip` build is for Apple Silicon (arm64) only. It
does not support Intel Macs, is not signed with an Apple Developer ID, and is not notarized;
Gatekeeper may display a warning. Windows remains the recommended Alpha.1 test platform.

## Windows test

1. Download `SafeInstall-Windows-x64.zip` from the GitHub Release.
2. Compare the ZIP's SHA-256 with `SHA256SUMS.txt`.
3. Extract the ZIP.
4. Open `SafeInstall/SafeInstall.exe`.
5. Scan a non-confidential source-code folder.
6. Scan a non-confidential ZIP archive.
7. Open **Technical Details** and check whether the evidence is understandable.
8. Export one Markdown report and one JSON report.
9. Repeat with a folder whose path contains spaces or non-English characters if available.
10. Disconnect from the network and confirm a local scan still works. GitHub URL scans are expected
    to show a friendly network error while offline.

The Windows binary is unsigned, so SmartScreen may show a warning. Do not disable Microsoft
Defender or permanently disable SmartScreen for this test.

## What to tell us

- Windows or macOS version
- SafeInstall version
- whether the app opened
- target type: file, folder, ZIP/TAR, or public GitHub URL
- whether scanning and report export completed
- whether the overview and recommendation were understandable
- any false-positive Rule ID and a minimal sanitized example

Use the [Alpha feedback form](https://github.com/wanhaoli376-lab/SafeInstall/issues/new/choose).
Never upload confidential files, passwords, API keys, private source code, full local paths, or
unredacted reports.

## 中文测试步骤

下载 Windows ZIP，核对 SHA-256，解压后双击 `SafeInstall.exe`。依次扫描一个不含机密信息的源码目录和 ZIP，查看技术详情，并导出 Markdown 与 JSON 报告。整个本地流程不需要 Python、终端、账号或 OpenAI API Key。反馈时只提交经过脱敏的最小示例，不要上传私有源码、密码、API Key、本地完整路径或未脱敏报告。
