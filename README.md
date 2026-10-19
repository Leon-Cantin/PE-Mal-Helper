A Collection of helpers to parse PE files, obfuscate strings and resolve dynamic calls without adding entries to the IAT in Rust.
It's made out of a few components.
## strobf
* macros to log certain levels of messages and remove them at compile time depending on the feature set:
    * max_verbose_off
    * max_verbose_error
    * max_verbose_info
    * max_verbose_debug
* string obfuscation templates that you can extend to add new obfuscation algorithms, used notably by the dynamic resolver. Set the type TObf to the one of your algoritm of choice so it propagate to all modules.
    *djb2 for hashing (feature: tobf_djb2)
    *raw strings for debugging (feature: tobf_raw)
## ld
Dynamicly resolve dll calls and syscalls without adding anything to the IAT. This works by essentially doing what LD does in linux and then uses the strobf module to propagate your obfuscation method of choice throughout its functions totally transparently.
* Set your functions declarations like you see in the dll_imp example
* call them just like you would any other function and they will be resolved at runtime.
* most of the functions are dynamic calls free so you can call them when you do a reflective dll for example.
* for syscalls it will need the Nt prefixed function to find the correct SSN.
## pe_mapper
Lots of functions to map a PE file into memory, set the permissions and only minimally read the file before mapping it out. It can do the relocations in place before you send your PE to the infected process. This removes some of the restrictions of not using anything that hasn't yet been relocated. Together with LD you save a lot of headaches in the early stages of infection.
## dll_imp
Just an example collection of syscalls and windows dll calls definitions. This is so the stubs and global data are generated for LD and so you have a clean function to add.
## rflt_dll
An example project of what you can do with this. The early stages of infection can use relocation and dynamic calls, no problem.