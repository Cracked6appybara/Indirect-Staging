### Payload Loader Features

- Remote code injection support
- Mapping injection using direct syscalls via Hell's Gate
- API Hashing
- Anti-Analysis functionality
- RC4 payload encryption
- Brute forcing the decryption key
- No CRT library imports

### Description

This project was made by me from the help of the MalDev malware development online course. I have learnt a lot from this course and this was a final project from the course. In this project I combined some of the things that I have learnt from the course to be able to create a feature full payload that bypasses AV solutions.

---

### Installation & Usage
> **- First Download the project from this repository.**

> **- Once installed to be able to modify the Loader to the features that you would like you will need to open the project and go into the main.c file.**

Once here at the top there will be 2 different options:

Inject to a remote process.
```C
// uncomment to inject to remote process
//
#define TARGET_PROCESS	L"notepad.exe"
```


Enable Antianalysis Features.
```C
// uncomment to enable antianalysis features
//
#define ANTI_ANALYSIS
```

From here you will need to build the project in RELEASE mode otherwise there will be errors.

![ezgif com-video-to-gif](https://github.com/0a4s9uufc1/---M1J0W-SHELL-INJECT---/assets/145394420/aec4f767-f522-45a4-89bb-d07235ee412c)


If you wanted to run the payload with Debug enabled to allow you to see that everything is working how it should, uncomment the enable debug mode option in Debug.h header file.
```C
// uncomment to enable debug mode
//
#define DEBUG
```

**Right now I have put in calc.exe shellcode that will be executed by the injector. This will spawn a calc process once the payload is run.**

### INFO

I am still going forwads with this course and will definetly come back to this project to add some other features to make it harder for the payload to be analysed and will try other methods of evading AVs and different injection techniques.
