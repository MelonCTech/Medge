<p align="center"><img src="https://github.com/Water-Melon/Medge/blob/master/.misc/logo.png?raw=true" width="160px"/></p>
<p align="center"><img src="https://img.shields.io/github/license/Water-Melon/Melang" /></p>



Medge is an HTTP Server.

For more information such as purposes, features and limitations, please visit our [Wiki](https://github.com/Water-Melon/Medge/wiki/About-Medge).



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



### Docker

You can pull the docker image.

```shell
docker pull melonc/medge
```



### Usage

```
$ medge -h
./medge OPTIONS
	-a Listen address, 0.0.0.0 as default
	-p Listen port, 80 as default
	-w Worker process number, 1 as default
	-d Base directory path of entry script, /opt/medge/ as default
	-e Entry expression file, 'index' as default
	-D Enable changing root directory. This parameter only work on user 'root'.
	-v Show version
	-h Show help information
```

`-d` is used to set the base directory path of the entry script.

For example:

```
|- /opt/medge/
    |- index
```

This is the base directory tree. The base directory is `/opt/medge` in this example. And there is an entry expression file named `index`.

`-D` is used to enable `chroot` system call. But if it is enabled, user has to solve directory problems manually.



### Example

Let's see a complete example.

The service base path is `/opt/medge`.

```
|- /opt/medge/
    |- index
    |- index.html
```

In Medge, HTTP host is used as the service directory name.

```
//index
setResponseBody(readFile('/opt/medge/index.html'))
```

```
//index.html
<!DOCTYPE html>
<html>
<head>
<title>Welcome to Medge!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to medge!</h1>
<p>If you see this page, the medge web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://medge.org/">medge.org</a>.<br/>
Commercial support is available at
<a href="http://medge.com/">medge.com</a>.</p>

<p><em>Thank you for using medge.</em></p>
</body>
</html>
```

Now, let's start Medge:

```shell
$ medge -p 8080 -d /opt/medge/ -w 1
```

Then we send a HTTP request to Medge.

```shell
$ curl -v http://127.1:8080/
*   Trying 127.0.0.1:8080...
* Connected to 127.0.0.1 (127.0.0.1) port 8080 (#0)
> GET / HTTP/1.1
> Host: 127.0.0.1:8080
> User-Agent: curl/7.81.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
* no chunk, no close, no size. Assume close to signal end
< 
<!DOCTYPE html>
<html>
<head>
<title>Welcome to Medge!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to medge!</h1>
<p>If you see this page, the medge web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://medge.org/">medge.org</a>.<br/>
Commercial support is available at
<a href="http://medge.com/">medge.com</a>.</p>

<p><em>Thank you for using medge.</em></p>
</body>
</html>
* Closing connection 0
```



### Collaboration

If you are interested in this project and want to be the collaborator, please open an issue with the title **Collaborator** by the account that want to be invited.



### License

[BSD-3-Clause License](https://github.com/Water-Melon/Melang/blob/master/LICENSE)

Copyright (c) 2014-present, Niklaus F. Schen



### Contact

Twitter: [@MelonTechnology](https://twitter.com/MelonTechnology)

QQ: [756582294](http://qm.qq.com/cgi-bin/qm/qr?_wv=1027&k=4e2GRrKLo6cz7kptaU_cUHhZ3JeHQT5b&authKey=ffV3ztGX3QAZP%2BRCnbdwAUETeT8O3VIxiIeyBch0DkvxAoM3J%2Bs3Ol1sZjcZwuto&noverify=0&group_code=756582294)

