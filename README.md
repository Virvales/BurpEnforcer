Burp plugin.

Currently supports

1)HTTP Response splitting. Althought burp should support it, it not always works. You can check it here:

http://testphp.vulnweb.com/redir.php?r=/

Burp does see vulnerability here, but this plugin does.

2)Tries to overflow variables by putting 4096 A symbols.

3)Dirbuster Try to add extensions, that assosiated with temporary files (~, .bak, .tmp, etc) and check existance of a such file

In case of false-positives or false-negatives contact me vi virvales at gmail.com, I'll try to tune plugin
