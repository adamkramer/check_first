# check_first
Just-in-time VirusTotal checker

This is a proof of concept.

The idea is that before running ANY file, it can be pushed through this program to see whether any of the AV engines on VT show it as a threat. 

I acknowledge that searching by hash alone isn't the best way to find threats!! but this isn't designed to replace AV.

Infact, for commonly distrubted malware - it is likely to be in the signatures of one of the engines pretty quickly (they're good at what they do!)

Potential way to use:

1. I'm going to have this on my desktop so I can drop newly downloaded files onto it as a method to open them

2. I may also include it in %PATH% so I can run it quickly via the cmd prompt

Usage:
check_first.exe [file to be checked] [/stop-unknowns] <-- optional

File to be checked can be any type: .exe .doc .pdf etc.

What the program does is:

1. Calculates SHA256 hash of respective file

2. Submits HASH via VirusTotal API (does not upload file at this point)

3. If VT has *never* seen the hash, or has and there are no AV detections then the file will run/open as normal. If VT detects it as a threat, the web browser opens to the appropriate VT analysis page for the user to review (the file will NOT run)

Optional:

4. If /stop-unknowns is passed as a second argument, files that VT has never seen will not be run
(Interestingly enough - VT has seen plenty of legit files and shows them as clean, try it on notepad.exe)

TODO:

1. Create option to upload files (based on command line argument) if VT has never seen them and the user is happy for files to be uploaded
