fchdir(3);
open("flag",0);
sendfile(1,4,0,0x40);