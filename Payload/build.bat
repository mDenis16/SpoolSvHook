call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=amd64
cl -DALPC -c -nologo -Os -O2 -Gm- -GR- -EHa -Oi -GS- payload.c /I"A:\repos\SpoolSvHook\RE_ntlib"
link /order:@alpc.txt /entry:TpAlpcCallBack /fixed payload.obj -subsystem:console -nodefaultlib -stack:0x100000,0x100000
xbin payload.exe .text
copy payload.exe64.bin ..\build\payload.bin
