# 批量 主机扫描

扫描 局域网内的 openwrt 

论，如何偷别人的流量 (笑


# 自定义指纹

页面出现的， 都可以被当成指纹用
"指纹":"类型"

写入到 data.txt 文件内即可

# 未完善的问题

~~有的页面是稍后加载的， 不会直接被加载， 所以这种页面就算有了指纹也不能够，准备判断出资产类型~~

~~ssl 证书不信任， 也获取不到有效信息 : vm esxi 之类的~~

1. 网页报 js 无法加载的错误， 影响后面的判断， 因为python 的请求库是无法动态加载js的
2. ip 地址不能正确的识别， 或者说不能完美识别

# 优化日志
## 2021.7.6
1. ip 地址 生成做了一点优化
2. 多线程优化， 使得程序可以实现真正的并行访问， 时间也从 扫一个24段网络， 4s 到现在的 1.3 s



