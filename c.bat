@ECHO OFF

rc resources.rc
cvtres /MACHINE:x64 /OUT:resources.o resources.res
