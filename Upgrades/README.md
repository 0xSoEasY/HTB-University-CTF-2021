# Upgrades

## Summary

* [First contact with the challenge](#first-contact-with-the-challenge)
* [Opening macros in LibreOffice](#opening-macros-in-libreoffice)
* [Macro emulation with ViperMonkey](#macro-emulation-with-vipermonkey)

## First contact with the challenge

We download the challenge and find a file named `Upgrades.pptm`. Let's take some basic information on this file: 
```bash
$ file ./Upgrades.pptm
./Upgrades.pptm: Microsoft PowerPoint 2007+
```

We have to keep in mind that this is a reversing challenge so we can think about macros. Let's dig into it.

## Opening macros in LibreOffice

We can then open the file with our default application (for examplePowerpoint or LibreOffice in my case) and a message appears:
> Ce document contient des macros.
L'exécution de ces macros est désactivée en raison des paramètres actifs de sécurité des macros dans Outils - Options - LibreOffice - Sécurité.
En conséquence, certaines fonctionnalités peuvent ne pas être disponibles.

Basically, this is a (French) warning message telling us that there are some macros in the document, which are disabled because of security parameters.

We can then examinate those macros by going into `Tools > Macros > Manage macros > LibreOffice Basic`. Then we can see some interesting module in `Upgrades.pptm > VBAProject > Modules > Module1`. After clicking the `edit` button, we've got this VBA macro :

```vba
Rem Attribute VBA_ModuleType=VBAModule
Sub Module1
Rem Private Function q(g) As String
Rem q = ""
Rem For Each I In g
Rem q = q & Chr((I * 59 - 54) And 255)
Rem Next I
Rem End Function
Rem Sub OnSlideShowPageChange()
Rem j = Array(q(Array(245, 46, 46, 162, 245, 162, 254, 250, 33, 185, 33)), _
Rem q(Array(215, 120, 237, 94, 33, 162, 241, 107, 33, 20, 81, 198, 162, 219, 159, 172, 94, 33, 172, 94)), _
Rem q(Array(245, 46, 46, 162, 89, 159, 120, 33, 162, 254, 63, 206, 63)), _
Rem q(Array(89, 159, 120, 33, 162, 11, 198, 237, 46, 33, 107)), _
Rem q(Array(232, 33, 94, 94, 33, 120, 162, 254, 237, 94, 198, 33)))
Rem g = Int((UBound(j) + 1) * Rnd)
Rem With ActivePresentation.Slides(2).Shapes(2).TextFrame
Rem .TextRange.Text = j(g)
Rem End With
Rem If StrComp(Environ$(q(Array(81, 107, 33, 120, 172, 85, 185, 33))), q(Array(154, 254, 232, 3, 171, 171, 16, 29, 111, 228, 232, 245, 111, 89, 158, 219, 24, 210, 111, 171, 172, 219, 210, 46, 197, 76, 167, 233)), vbBinaryCompare) = 0 Then
Rem VBA.CreateObject(q(Array(215, 11, 59, 120, 237, 146, 94, 236, 11, 250, 33, 198, 198))).Run (q(Array(59, 185, 46, 236, 33, 42, 33, 162, 223, 219, 162, 107, 250, 81, 94, 46, 159, 55, 172, 162, 223, 11)))
Rem End If
Rem End Sub
Rem 
Rem 
Rem 
End Sub
```

## Macro emulation with ViperMonkey

Because we don't want do reverse this by hand, we will use a super tool called ViperMonkey (https://github.com/decalage2/ViperMonkey).

We just need to clone the repository, have docker installed and run `ViperMonkey/docker/dockermonkey.sh` on our `Upgrades.pptm` file and let the magic happen!

```bash
$ chmod +x ViperMonkey/docker/dockermonkey.sh 
$ sudo ViperMonkey/docker/dockermonkey.sh ./Upgrades.pptm 
[sudo] Mot de passe de SoEasY : 
[*] Running 'docker ps' to see if script has required privileges to run...
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
[*] Pulling and starting container...
latest: Pulling from haroldogden/vipermonkey
Digest: sha256:0ebbe27f2d0da95f4668de5386df7eee8fb6bb0ced6f2fb92492e677b41eca79
Status: Image is up to date for haroldogden/vipermonkey:latest
docker.io/haroldogden/vipermonkey:latest
[*] Attempting to copy file ./Upgrades.pptm into container ID ee99fa16391aef2869aa17e387a8bb3e70955ac6d11d954374e95971c7eacf57
[*] Starting openoffice listener for file content conversions...
[*] Checking for ViperMonkey and dependency updates...
[*] Disabling network connection for container ID ee99fa16391aef2869aa17e387a8bb3e70955ac6d11d954374e95971c7eacf57
INFO     Starting emulation...
INFO     Emulating an Office (VBA) file.
INFO     Reading document metadata...
WARNING  Reading in metadata failed. Trying fallback. not an OLE2 structured storage file
WARNING  File is not an Excel 97 file. Not reading with xlrd2.
INFO     Saving dropped analysis artifacts in /root/Upgrades.pptm_artifacts/
INFO     Parsing VB...
INFO     Modifying VB code...
INFO     parsed Function q ([ByRef g]): 2 statement(s)
INFO     parsed Sub OnSlideShowPageChange (): 4 statement(s)
INFO     Modifying VB code...
[...] 
INFO     evaluating Sub Label1_Click
INFO     Making dropped sample directory ...
 _    ___                 __  ___            __             
| |  / (_)___  ___  _____/  |/  /___  ____  / /_____  __  __
| | / / / __ \/ _ \/ ___/ /|_/ / __ \/ __ \/ //_/ _ \/ / / /
| |/ / / /_/ /  __/ /  / /  / / /_/ / / / / ,< /  __/ /_/ / 
|___/_/ .___/\___/_/  /_/  /_/\____/_/ /_/_/|_|\___/\__, /  
     /_/                                           /____/   
vmonkey 1.0.2 - https://github.com/decalage2/ViperMonkey
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/ViperMonkey/issues

===============================================================================
FILE: /root/Upgrades.pptm
-------------------------------------------------------------------------------
VBA MACRO Module1.bas 
in file: ppt/vbaProject.bin - OLE stream: u'VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
-------------------------------------------------------------------------------
VBA CODE (with long lines collapsed):

Private Function q(g) As String
q = ""
For Each I In g
q = q & Chr((I * 59 - 54) And 255)
Next I
End Function
Sub OnSlideShowPageChange()
j = Array(q(Array(245, 46, 46, 162, 245, 162, 254, 250, 33, 185, 33)), q(Array(215, 120, 237, 94, 33, 162, 241, 107, 33, 20, 81, 198, 162, 219, 159, 172, 94, 33, 172, 94)), q(Array(245, 46, 46, 162, 89, 159, 120, 33, 162, 254, 63, 206, 63)), q(Array(89, 159, 120, 33, 162, 11, 198, 237, 46, 33, 107)), q(Array(232, 33, 94, 94, 33, 120, 162, 254, 237, 94, 198, 33)))
g = Int((UBound(j)  + 1) * Rnd)
With ActivePresentation.Slides(2).Shapes(2).TextFrame
.TextRange.Text = j(g)
End With
If StrComp(Environ$(q(Array(81, 107, 33, 120, 172, 85, 185, 33))), q(Array(154, 254, 232, 3, 171, 171, 16, 29, 111, 228, 232, 245, 111, 89, 158, 219, 24, 210, 111, 171, 172, 219, 210, 46, 197, 76, 167, 233)), vbBinaryCompare) = 0 Then
VBA.CreateObject(q(Array(215, 11, 59, 120, 237, 146, 94, 236, 11, 250, 33, 198, 198))).Run (q(Array(59, 185, 46, 236, 33, 42, 33, 162, 223, 219, 162, 107, 250, 81, 94, 46, 159, 55, 172, 162, 223, 11)))
End If
End Sub
-------------------------------------------------------------------------------
PARSING VBA CODE:
-------------------------------------------------------------------------------
VBA MACRO Slide1.cls 
in file: ppt/vbaProject.bin - OLE stream: u'VBA/Slide1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
-------------------------------------------------------------------------------
VBA CODE (with long lines collapsed):

Private Sub Label1_Click()
End Sub
-------------------------------------------------------------------------------
PARSING VBA CODE:
-------------------------------------------------------------------------------
TRACING VBA CODE (entrypoint = Auto*):
Recorded Actions:
+----------------------+-----------------------+---------------------------------+
| Action               | Parameters            | Description                     |
+----------------------+-----------------------+---------------------------------+
| Start Regular        |                       | All wildcard matches will match |
| Emulation            |                       |                                 |
| Found Entry Point    | label1_click          |                                 |
| Found Entry Point    | Label1_Click          |                                 |
| Found Heuristic      | OnSlideShowPageChange |                                 |
| Entry Point          |                       |                                 |
| Environ              | ['username']          | Interesting Function Call       |
| Found Heuristic      | OnSlideShowPageChange |                                 |
| Entry Point          |                       |                                 |
| Environ              | ['username']          | Interesting Function Call       |
| Found Heuristic      | Label1_Click          |                                 |
| Entry Point          |                       |                                 |
| Found Heuristic      | Label1_Click          |                                 |
| Entry Point          |                       |                                 |
+----------------------+-----------------------+---------------------------------+

VBA Builtins Called: ['Array', 'Chr', 'CreateObject', 'Environ', 'Int', 'Run', 'Shapes', 'Slides', 'StrComp', 'UBound']

Decoded Strings (7):
  Add A Theme
  Write Useful Content
  Add More TODO
  More Slides
  Better Title
  username
  HTB{33zy_VBA_M4CR0_3nC0d1NG}

Finished analyzing /root/Upgrades.pptm .

  adding: root/Upgrades.pptm_artifacts/ (stored 0%)
[*] Dropped files are in Upgrades.pptm_artifacts.zip
[*] Done - Killing docker container ee99fa16391aef2869aa17e387a8bb3e70955ac6d11d954374e95971c7eacf57
``` 

And we can finally found our flag in the decoded strings at the end : the flag `HTB{33zy_VBA_M4CR0_3nC0d1NG}` validates the challenge !
