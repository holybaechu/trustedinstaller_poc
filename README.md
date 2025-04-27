# TrustedInstaller PoC in Rust
A Proof of Concept of opening any program (in this case, CMD) as TrustedInstaller in Rust using `windows` and `windows-service` crates.

## ⚠️ Caution
This is a Proof of Concept and should not be used for malicious purposes.

## Usage
1. Download the latest release from the [latest release](https://github.com/holybaechu/trustedinstaller_poc/releases/latest) or build it yourself. Then, run the executable.
2. The program will open a UAC prompt if you are not running as Administrator. Accept the prompt.
3. The program will then open CMD as TrustedInstaller.

## Building
To build this project, you need to have Rust, VS Build Tools and the Windows SDK installed.

To build the project, run the following command:
```
cargo build --release
```

## How it works
You can visit the blog from [FourCoreLabs](https://fourcore.io/blogs/no-more-access-denied-i-am-trustedinstaller) to learn how it works.

## Credits
This was inspired by [Go PoC by FourCoreLabs](https://github.com/FourCoreLabs/TrustedInstallerPOC)
