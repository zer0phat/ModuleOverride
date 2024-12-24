# ModuleOverride
ModuleOverride is a process injection technique, discussed (this blog post)[], which reuses - or override - the the memory space of a target DLL to store a shellcode.

# Caveats
This repository only contains a PoC which is only intended to be used for research purposes. The current source only focuses on the technique it self, it's not meant to be stealth or undetected.

# Different technques
You may notice diffent commented sections in the source. These lines are part of the thread hijacking technique, discussed in the blog, that can be used to remotely trigger the shellcode execution. Evry uncommented part, is used to trigger execution locally, within the injected process, via CreateThread call.

# PoC
<img align="center" href="/imgs/89e02985-5e85-4bde-b447-9cbedc8e19fa.gif" src="/imgs/89e02985-5e85-4bde-b447-9cbedc8e19fa.gif">