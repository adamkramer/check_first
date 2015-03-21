# check_first
Just-in-time VirusTotal checker

This is a proof of concept.

The idea is that before running ANY file, it can be pushed through this program to see whether any of the AV engines on VT show it as a threat (either by HASH or by uploading the file for a scan)

Potential way to use:

1. I'm going to have this on my desktop so I can drop newly downloaded files onto it as a method to open them

2. I may also include it in %PATH% so I can run it quickly via the cmd prompt

Usage:
check_first.exe [file to be checked] [/stop-unknowns] [/submit-unknowns] [/wait-response]

File to be checked can be any type: .exe .doc .pdf etc.

What the program does is:

1. Calculates SHA256 hash of respective file

2. Submits HASH via VirusTotal API (does not upload file at this point)

3. If VT has *never* seen the hash, or has and there are no AV detections then the file will run/open as normal. If VT detects it as a threat, the web browser opens to the appropriate VT analysis page for the user to review (the file will NOT run)

Optional:

4. If /stop-unknowns is passed as a second argument, files that VT has never seen will not be run
(Interestingly enough - VT has seen plenty of legit files and shows them as clean, try it on notepad.exe)

5. If /submit-unknowns is passed, the file will be uploaded to VirusTotal if they have never seen it before for a full scan by all engines

6. If /wait-response is passed, the program will wait for the result of /submit-unknowns before making a decision (n.b. this can sometimes take a while if VT is busy)

