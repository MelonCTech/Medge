<p align="center"><img src="https://github.com/Water-Melon/Medge/blob/master/.misc/logo.png?raw=true" width="160px"/></p>
<p align="center"><img src="https://img.shields.io/github/license/Water-Melon/Melang" /></p>



Medge is an HTTP API Server.

API developers can use [Melang](https://melang.org/) to implement their API services and run in Medge.

With the special features that Melang provide, Medge can processing all HTTP requests in a single thread. And make sure each request processing script task will be isolated as a preemptive scheduling co-routine. And in fact, Medge is a multi-process program.

**Note**: This project is not production-ready yet. It is only support HTTP/1.0 and HTTP/1.1 without SSL or TLS.



### Installation

This project depends on the core library [Melon](https://github.com/Water-Melon/Melon) and [Melang](https://github.com/Water-Melon/Melang) dynamic libraries. So please install these projects at first. For more details about them, please visit their repositories on Github.

After that, please follow the commands given below:

```shell
$ git clone https://github.com/Water-Melon/Medge.git
$ cd Medge
$ ./configure [--prefix=INSTALL_PATH] [--libpath=INSTALLED_MELON_PATH]
$ make
$ make install
```



### Usage

```
$ medge -h
./medge OPTIONS
	-a Listen address, 0.0.0.0 as default
	-p Listen port, 80 as default
	-w Worker process number, 1 as default
	-d Base directory path of entry script, /opt/medge/ as default
	-D Enable changing root directory. This parameter only work on user 'root'.
	-v Show version
	-h Show help information
```

`-d` is used to set the base directory path of the entry script of every API services.

For example:

```
|- /opt/medge/
    |- service_1/
        |- entry.m
        |- ...
    |- service_2/
        |- entry.m
        |- ...
```

This is the base directory tree. The base directory is `/opt/medge` in this example. And there are two API services named `service_1` and `service_2`. And there is a entry script file named `entry.m` in both of their directories.

`-D` is used to enable `chroot` system call. But if it is enabled, user has to solve directory problems manually.



### Example

Let's see a complete example.

The service base path is `/opt/medge`.

```
|- /opt/medge/
    |- 127.0.0.1:8080/
        |- entry.m
        |- index.m
```

`127.0.0.1:8080` is a directory. Because in Medge, HTTP host is used as service name.

```
//entry.m
/*
 * Implement a simple controller.
 * There are three variable injected in this script task:
 *   1. Req. Its prototype is:
 *       Req {
 *           method; //string  e.g. GET POST DELETE ...
 *           version; //string e.g. HTTP/1.0 HTTP/1.1
 *           uri; //string e.g. /index/index
 *           args; //an key-value array, e.g. ["key":"val", ...]
 *           headers; //an key-value array, e.g. ["Content-Type":"application/json", ...]
 *           body; //string
 *       }
 *
 *    2. Resp. Its prototype is:
 *        Resp {
 *            version; //same as Req's version
 *            code; //integer  e.g. 200
 *            headers; //same as Req's headers
 *            body; //same as Req's body
 *        }
 *
 *.   3. Basedir. A string of the base directory path. (Not used in this example)
 */

#include "@/index.m"

str = Import('str');
sys = Import('sys');

uri = str.slice(Req.uri, '/');
ctlr = str.capitalize(uri[0]);
o = $ctlr;
if (sys.has(o, uri[1]) != 'method') {
  Resp.code = 404;
} else {
  o.__action__ = uri[1];
  Resp.body = o.__action__();
  Resp.headers['Content-Length'] = str.strlen(Resp.body);
}
```

```
//index.m

Json = Import('json');

Index {
    @index() {
        Resp.headers['Content-Type'] = 'application/json';
        return Json.encode(['code': 200, 'msg': 'OK']);
    }
}
```

Now, let's start Medge:

```shell
$ medge -p 8080 -d /opt/medge/ -w 1
```

Then we send a HTTP request to Medge.

```shell
$ curl -v http://127.0.0.1:8080/index/index
*   Trying 127.0.0.1:8080...
* Connected to 127.0.0.1 (127.0.0.1) port 8080 (#0)
> GET /index/index HTTP/1.1
> Host: 127.0.0.1:8080
> User-Agent: curl/7.81.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Content-Length: 23
< Content-Type: application/json
< 
* Connection #0 to host 127.0.0.1 left intact
{"code":200,"msg":"OK"}
```



### License

[BSD-3-Clause License](https://github.com/Water-Melon/Melang/blob/master/LICENSE)

Copyright (c) 2014-present, Niklaus F. Schen




### Docker

You can pull the built container image.

```shell
docker pull melonc/medge
```



### Contact

Twitter: @MelangInc

QQ: 756582294

