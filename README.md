# -scan
基于python3.8，引用了py3PortScanner项目，通过模拟发包获取设备ip，mac连接他们写入文件，再通过文件读取分别替换IP与mac地址，引用pyPortScanner接口获取ip对应的端口内容，再通过切片获取对应的mac片段查库获取对应的厂商内容，最后通过端口选择出开放端口，再进行查库获取端口对应服务。