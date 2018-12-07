本程序是一个简易的基于字典的DNS子域名爆破程序。这个程序仅为示范DNS over HTTPS协议（[RFC8484](https://tools.ietf.org/html/rfc8484)），请勿用于非法用途！

### 编译
仅测试了在Visual Studio 2017下可编译，并且需要.NET Framework 4.6.1支持。

### 字典文件
`SecureDNSProbing`目录下的`subdomaindictionary.txt`字典文件是从[dnsrecon项目](https://github.com/darkoperator/dnsrecon/blob/master/subdomains-top1mil-5000.txt)复制过来的。运行本程序时需要把这个文件复制到和exe文件同一个文件夹下，也可以使用其他字典文件，但是文件名必须是`subdomaindictionary.txt`。

### Freebuf文章链接
《[浅析加密DNS（附子域名爆破工具）](https://www.freebuf.com/articles/168659.html)》
