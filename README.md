# NMIStackWalk  
检测无模块驱动  
原理： 
发NMI，然后在注册的NMI回调内做栈回溯，代码没在全系统测试
