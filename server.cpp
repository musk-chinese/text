#include<stdio.h>
#include<string.h>
#include<stdlib.h>  
typedef unsigned char byte;//定义帧单位

//用于生成CRC32码表
unsigned int crc32_for_byte(unsigned int r){
    for (int j = 0; j <8; ++j)
        r = (r & 1 ? 0 : (unsigned int)0xEDB88320L) ^ r >> 1;
    return r ^(unsigned int)0xFF000000L;
}

//CRC32校验
unsigned int crc32(const void *data, int n_bytes){
    unsigned int crc = 0xFFFFFFFF;
    static unsigned int table[0x100];
    if (!*table)
        for (int i = 0;i <0x100; ++i)
            table[i] = crc32_for_byte(i);
    for (int i = 0; i < n_bytes; ++i)
        crc = table[(byte)crc ^ ((byte *)data)[i]] ^ crc >> 8;
    return crc;
}

//将short转为byte数组
void shortToByte(short i,byte* bytes){
    bytes[0] = (byte) ((0xff00 & i) >> 8);
    bytes[1] = (byte) (0xff & i);
}

//将byte数组转为short
short bytesToShort(byte* bytes){
    short num = bytes[1] | (bytes[0] << 8);
    return num;
}

//将byte数组打印显示（修复字符串常量警告）
void displayByte(const char str[], byte* arr, int len){
    printf("%s:\t", str);
    for(int i = 0; i < len; i++){
        printf("%02x ", arr[i]);
    }
    printf("\n");
}

//主机结构体
struct HOST{
    byte port[2];//端口
    byte ip[4];//IP
    byte address[6];//MAC地址
}srcHost, desHost;

//源主机和目的主机的端口，IP，MAC地址信息
byte srcPort[2]={0x00,0xee};
byte desPort[2]={0x00,0xff};
byte srcIP[4]={0x00,0x01,0x02,0xee};
byte desIP[4]={0x00,0x01,0x02,0xff};
byte srcAddress[6]={0x00,0x11,0x22,0x33,0x44,0xee};
byte desAddress[6]={0x00,0x11,0x22,0x33,0x44,0xff};

//初始化源主机和目的主机
void initHots(){
    memcpy(srcHost.port, srcPort, 2);
    memcpy(srcHost.ip, srcIP, 4);
    memcpy(srcHost.address, srcAddress, 6);

    memcpy(desHost.port, desPort, 2);
    memcpy(desHost.ip, desIP, 4);
    memcpy(desHost.address, desAddress, 6);
}

byte mark1OCP[2]={0x00,0x02};//标志字段1，表示数据包开始
byte protocolOCP[2]={0x00,0x01};//协议版本，第一版
byte controlOCP[2]={0x00,0x16};//控制字段，发送消息
byte srcID[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
byte desID[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
byte sumOCP[2]={0x00,0x00};
byte reservationOCP[6]={0x00,0x00,0x00,0x00,0x00,0x00};
byte mark2OCP[2]={0x00,0x03};

//OCP协议结构体
struct OCP{
    byte mark1[2];//标志1
    byte protocol[2];//协议版本
    byte control[2];//控制字段
    byte srcID[8];//源用户ID
    byte desID[8];//目的用户ID
    byte sum[2];//校验和
    byte reservation[6];//预留字段
    byte mark2[2];//标志2
    byte len[2];//长度
    byte* data;//数据（服务端用指针没问题，因为data是main栈上的数组）
};

//打印OCP
void displayOCP(OCP &ocp){
    printf("------------OCP-------------\n");
    displayByte("mark1", ocp.mark1, 2);
    displayByte("protocol", ocp.protocol, 2);
    displayByte("control", ocp.control, 2);
    displayByte("srcID", ocp.srcID, 8);
    displayByte("desID", ocp.desID, 8);
    displayByte("sum", ocp.sum, 2);
    displayByte("reservation", ocp.reservation, 6);
    displayByte("mark2", ocp.mark2, 2);
    displayByte("len", ocp.len, 2);
    // 边界检查：防止数据长度为负/越界
    short data_len = bytesToShort(ocp.len) - 34;
    if (data_len > 0) {
        displayByte("data", ocp.data, data_len);
    } else {
        displayByte("data", ocp.data, 0);
        printf("警告：OCP数据长度异常\n");
    }
}

byte sumUDP[2]={0x00,0x00};//源端口

//UDP协议结构体
struct UDP{
    byte srcPort[2];//源端口
    byte desPort[2];//目的端口
    byte sum[2];//校验和
    byte len[2];//长度
    OCP ocp;//封装的OCP报文
};

//打印UDP
void displayUDP(UDP &udp){
    printf("\n----------------UDP---------------\n");
    displayByte("srcPort", udp.srcPort, 2);
    displayByte("desPort", udp.desPort, 2);
    displayByte("sum", udp.sum, 2);
    displayByte("len", udp.len, 2);
    displayOCP(udp.ocp);
}

byte headerIP[1]={0x45};//版本IPv4 +首部长度5个4字节
byte serviceIP[1]={0x00};//区分服务，未使用
byte layer2IP[4]={0x00,0x00,0x00,0x00};//标识+标志+片偏移都默认为0
byte timeIP[1]={0x01};//生存时间为1，表明只能在本局域网中传送
byte protocolIP[1]={0x11};//协议号为17，表明使用UDP协议处理
byte sumIP[2]={0x00,0x00};//检验和

//IP协议结构体
struct IP{
    byte header[1];//版本+首部长度
    byte service[1];//区分服务
    byte len[2];//总长度
    byte layer2[4];//标识+标志+片偏移
    byte time[1];//生存时间
    byte protocal[1];//协议
    byte sum[2];//首部检验和
    byte srcIP[4];//源地址
    byte desIP[4];//目的地址
    UDP udp;//封装的udp报文段
};

//打印IP
void displayIP(IP &ip){
    printf("\n------------------IP---------------\n");
    displayByte("header", ip.header, 1);
    displayByte("service", ip.service, 1);
    displayByte("len", ip.len, 2);
    displayByte("layer2", ip.layer2, 4);
    displayByte("time", ip.time, 1);
    displayByte("protocal", ip.protocal, 1);
    displayByte("sum", ip.sum, 2);
    displayByte("srcIP", ip.srcIP, 4);
    displayByte("desIP", ip.desIP, 4);
    displayUDP(ip.udp);
}

byte typeMAC[2]={0x00,0x00};//类型为IPv4
byte FCSMAC[4]={0x00,0x00,0x00,0x00};//FCS校验和

//MAC协议结构体
struct MAC{
    byte srcAddress[6];//源地址
    byte desAddress[6];//目的地址
    byte type[2];//类型
    IP ip;//封装的IP数据报
    byte FCS[4];//FCS校验和
};

//打印MAC
void displayMAC(MAC &mac){
    printf("\n--------------MAC--------------\n");
    displayByte("srcAddress", mac.srcAddress, 6);
    displayByte("desAddress", mac.desAddress, 6);
    displayByte("type", mac.type, 2);
    displayIP(mac.ip);
    printf("\n----------------------MAC-----------------\n");
    displayByte("FCS", mac.FCS, 4);
}

//IP头校验和计算
short IPCheckSum(byte *ip_head_buffer, short ip_hdr_len){
    unsigned int check_sum = 0;//校验和初始化

    /*校验和计算*/
    while (ip_hdr_len > 1){
        byte t1=*ip_head_buffer++;
        byte t2=*ip_head_buffer++;
        short s=(short)(t1<<8)|t2;
        check_sum += s;//一次移动2字节
        ip_hdr_len -= sizeof(short);
    }

    /*如果有剩余1字节*/
    if (ip_hdr_len > 0){
        check_sum += *(byte *)ip_head_buffer;
    }

    /*进位相加*/
    check_sum = (check_sum & 0x0000FFFF) + (check_sum >> 16);
    check_sum += (check_sum >> 16);
    check_sum = ~check_sum;//取反
    return (short)check_sum;
}

//UDP校验和计算
short UdpCheckSum(byte* ip_src_addr, byte* ip_dst_addr, byte *udp_buffer, short udp_size)
{
    /*定义伪首部*/
    byte rawBuffer[300];//定义缓存数组
    struct pseudo_hdr{
        byte src[4];//源IP地址
        byte dst[4];//目的IP地址
        byte mbz;//全0,8bit
        byte protocol;//协议字段，8bit
        short len;//UDP长度，16bit
    };
    struct pseudo_hdr *phead = (struct pseudo_hdr *)rawBuffer;
    int phead_len = sizeof(struct pseudo_hdr);

    /*伪首部赋值*/
    short check_sum = 0;
    memcpy(phead -> src, ip_src_addr, 4);
    memcpy(phead -> dst, ip_dst_addr, 4);
    phead -> mbz = 0;
    phead -> protocol = 17;//UDP协议代码17
    phead -> len = udp_size;

    /*计算校验和*/
    memcpy(rawBuffer + phead_len, udp_buffer, udp_size);
    check_sum = IPCheckSum((byte *)rawBuffer, phead_len + udp_size);
    return check_sum;
}

//将MAC帧转换成byte数据（增加边界检查）
void macToByte(MAC& mac, short lenMAC, byte frame[]){
    if (lenMAC <= 80) {
        printf("错误：MAC帧长度过小（%d），无法转换\n", lenMAC);
        return;
    }

    IP ip = mac.ip;
    UDP udp = ip.udp;
    OCP ocp = udp.ocp;

    //MAC头部
    memcpy(&frame[0], mac.srcAddress, 6);
    memcpy(&frame[6], mac.desAddress, 6);
    memcpy(&frame[12], mac.type, 2);
    //IP头部
    memcpy(&frame[14], ip.header, 1);
    memcpy(&frame[15], ip.service, 1);
    memcpy(&frame[16], ip.len, 2);
    memcpy(&frame[18], ip.layer2, 4);
    memcpy(&frame[22], ip.time, 1);
    memcpy(&frame[23], ip.protocal, 1);
    memcpy(&frame[24], ip.sum, 2);
    memcpy(&frame[26], ip.srcIP, 4);
    memcpy(&frame[30], ip.desIP, 4);
    //IP头校验和计算并更新
    short sumIP = IPCheckSum(&frame[14], 20);
    shortToByte(sumIP, ip.sum);
    memcpy(&frame[24], ip.sum, 2);
    //UDP头部
    memcpy(&frame[34], udp.srcPort, 2);
    memcpy(&frame[36], udp.desPort, 2);
    memcpy(&frame[38], udp.sum, 2);
    memcpy(&frame[40], udp.len, 2);
    //UDP校验和计算并更新
    short udp_len = bytesToShort(udp.len);
    short sumUDP = UdpCheckSum(ip.srcIP, ip.desIP, &frame[34], udp_len);
    shortToByte(sumUDP, udp.sum);
    memcpy(&frame[38], udp.sum, 2);
    //OCP头部
    memcpy(&frame[42], ocp.mark1, 2);
    memcpy(&frame[44], ocp.protocol, 2);
    memcpy(&frame[46], ocp.control, 2);
    memcpy(&frame[48], ocp.srcID, 8);
    memcpy(&frame[56], ocp.desID, 8);
    memcpy(&frame[64], ocp.sum, 2);
    memcpy(&frame[66], ocp.reservation, 6);
    memcpy(&frame[72], ocp.mark2, 2);
    memcpy(&frame[74], ocp.len, 2);
    //OCP数据（边界检查）
    int ocp_data_len = lenMAC - 80;
    if (ocp_data_len > 0 && ocp.data != NULL) {
        memcpy(&frame[76], ocp.data, ocp_data_len);
    }
    //OCP头校验和计算并更新
    short sumOCP = IPCheckSum(&frame[42], 32);
    shortToByte(sumOCP, ocp.sum);
    memcpy(&frame[64], ocp.sum, 2);
    //FCS校验和
    unsigned int FCS = crc32(frame, lenMAC - 4);
    memcpy(&frame[lenMAC - 4], &FCS, 4);
    memcpy(mac.FCS, &FCS, 4);

    //回写更新后的数据
    udp.ocp = ocp;
    ip.udp = udp;
    mac.ip = ip;
}

//将byte数据转换成MAC帧（服务端暂未调用，保留但修复边界检查）
MAC bytesToMAC(byte* frame, byte Data[]){
    OCP ocp = {0};
    UDP udp = {0};
    IP ip = {0};
    MAC mac = {0};
    short lenMAC = 0;

    //MAC头部解析
    memcpy(mac.srcAddress, &frame[0], 6);
    memcpy(mac.desAddress, &frame[6], 6);
    memcpy(mac.type, &frame[12], 2);
    //IP头部解析
    memcpy(ip.header, &frame[14], 1);
    memcpy(ip.service, &frame[15], 1);
    memcpy(ip.len, &frame[16], 2);
    memcpy(ip.layer2, &frame[18], 4);
    memcpy(ip.time, &frame[22], 1);
    memcpy(ip.protocal, &frame[23], 1);
    memcpy(ip.sum, &frame[24], 2);
    memcpy(ip.srcIP, &frame[26], 4);
    memcpy(ip.desIP, &frame[30], 4);

    // 计算MAC帧总长度（边界检查）
    lenMAC = bytesToShort(ip.len) + 18;
    if (lenMAC < 80) {
        printf("错误：MAC帧长度异常 %d\n", lenMAC);
        return mac;
    }

    //UDP头部解析
    memcpy(udp.srcPort, &frame[34], 2);
    memcpy(udp.desPort, &frame[36], 2);
    memcpy(udp.sum, &frame[38], 2);
    memcpy(udp.len, &frame[40], 2);
    //OCP头部解析
    memcpy(ocp.mark1, &frame[42], 2);
    memcpy(ocp.protocol, &frame[44], 2);
    memcpy(ocp.control, &frame[46], 2);
    memcpy(ocp.srcID, &frame[48], 8);
    memcpy(ocp.desID, &frame[56], 8);
    memcpy(ocp.sum, &frame[64], 2);
    memcpy(ocp.reservation, &frame[66], 6);
    memcpy(ocp.mark2, &frame[72], 2);
    memcpy(ocp.len, &frame[74], 2);

    // OCP数据解析（边界检查）
    int ocp_data_len = lenMAC - 80;
    if (ocp_data_len > 0) {
        memcpy(Data, &frame[76], ocp_data_len);
        ocp.data = Data;
    }

    //MAC FCS解析
    memcpy(mac.FCS, &frame[lenMAC - 4], 4);

    // 组装结构体
    udp.ocp = ocp;
    ip.udp = udp;
    mac.ip = ip;

    return mac;
}

//将byte数据写入文件（修复：移除内部fclose，统一由调用方管理）
void writeMessage(byte* data, short len, FILE *fp){
    if (fp == NULL) {
        printf("错误：文件句柄为空，无法写入\n");
        return;
    }
    size_t write_len = fwrite(data, sizeof(byte), len, fp);
    if (write_len != len) {
        printf("警告：写入字节数不匹配，预期%d，实际%d\n", len, (int)write_len);
    }
    printf("Message written to file successfully.\n");
}

//从文件中读取byte数据（服务端暂未调用，修复内部fclose）
void readMessage(byte* data, short len, FILE *fp){
    if (fp == NULL) {
        printf("错误：文件句柄为空，无法读取\n");
        return;
    }
    size_t read_len = fread(data, sizeof(byte), len, fp);
    if (read_len != len) {
        printf("警告：读取字节数不匹配，预期%d，实际%d\n", len, (int)read_len);
    }
    printf("Message read from file successfully.\n");
}

//封装OCP报文
OCP encapsulateOCP(byte data[], int len){
    OCP ocp = {0};
    memcpy(ocp.mark1, mark1OCP, 2);
    memcpy(ocp.protocol, protocolOCP, 2);
    memcpy(ocp.control, controlOCP, 2);
    memcpy(ocp.srcID, srcID, 8);
    memcpy(ocp.desID, desID, 8);
    memcpy(ocp.reservation, reservationOCP, 6);
    memcpy(ocp.mark2, mark2OCP, 2);

    // 边界检查：限制数据长度不超过256
    short lenOCP = (len > 256) ? 256 + 34 : len + 34;
    shortToByte(lenOCP, ocp.len);
    ocp.data = data; // 服务端此处用指针没问题（data是main栈上的数组）
    return ocp;
}

//封装UDP报文
UDP encapsulateUDP(OCP &ocp){
    UDP udp = {0};
    memcpy(udp.srcPort, srcPort, 2);
    memcpy(udp.desPort, desPort, 2);
    memcpy(udp.sum, sumUDP, 2);
    udp.ocp = ocp;
    short lenUDP = bytesToShort(ocp.len) + 8;
    shortToByte(lenUDP, udp.len);
    return udp; 
}

//封装IP数据报
IP encapsulateIP(UDP &udp){
    IP ip = {0};
    memcpy(ip.header, headerIP, 1);
    memcpy(ip.service, serviceIP, 1);
    memcpy(ip.layer2, layer2IP, 4);
    memcpy(ip.time, timeIP, 1);
    memcpy(ip.protocal, protocolIP, 1);
    memcpy(ip.sum, sumIP, 2);
    memcpy(ip.srcIP, srcIP, 4);
    memcpy(ip.desIP, desIP, 4);
    ip.udp = udp;
    short lenIP = bytesToShort(udp.len) + 20;
    shortToByte(lenIP, ip.len);
    return ip;
}

//封装MAC帧
MAC encapsulateMAC(IP &ip){
    MAC mac = {0};
    memcpy(mac.srcAddress, srcAddress, 6);
    memcpy(mac.desAddress, desAddress, 6);
    memcpy(mac.type, typeMAC, 2);
    mac.ip = ip;
    memcpy(mac.FCS, FCSMAC, 4);
    return mac;
}

//将data数据封装成MAC帧
MAC encapsulateData(byte data[], int len){
    OCP ocp = encapsulateOCP(data, len);
    UDP udp = encapsulateUDP(ocp);
    IP ip = encapsulateIP(udp);
    MAC mac = encapsulateMAC(ip);
    return mac;
}

//逐位检查两个byte数据是否相同
bool check(byte* arr1, int len1, byte* arr2, int len2){
    if(len1 != len2){
        return false;
    }
    for(int i = 0; i < len1; i++){
        if(arr1[i] != arr2[i]){
            return false;
        }
    }
    return true;
}

//将MAC帧解封装（修复：printf冗余参数）
void decapsulateMAC(MAC &mac){
    IP ip = mac.ip;
    UDP udp = ip.udp;
    OCP ocp = udp.ocp;

    //校验目的主机信息
    if(!check(desHost.address, 6, mac.desAddress, 6)){
        printf("Error: Destination MAC address does not match.\n");
    }
    else if(!check(desHost.ip, 4, ip.desIP, 4)){
        printf("Error: Destination IP address does not match.\n");
    }
    else if(!check(desHost.port, 2, udp.desPort, 2)){
        printf("Error: Destination port does not match.\n");
    }
    else{
        printf("Message received successfully.\n"); // 修复：移除冗余的ocp.data参数
    }
}

//检验FCS校验和是否正确
void checkFCS(byte* frame, short lenMAC){
    if (lenMAC < 4) {
        printf("FCS check failed: frame length too short\n");
        return;
    }
    unsigned int FCS_int = crc32(frame, lenMAC - 4);
    byte FCS_cp[4];
    byte FCS_frame[4];
    memcpy(FCS_cp, &FCS_int, 4);
    memcpy(FCS_frame, &frame[lenMAC - 4], 4);

    if(check(FCS_cp, 4, FCS_frame, 4)){
        printf("FCS check passed.\n");
    }
    else{
        printf("FCS check failed.\n");
    }
}

//校验和检查（修复：UDP长度错误）
void checkSum(byte* frame){
    //检验IP头校验和
    short num1 = IPCheckSum(&frame[14], 20);
    if(num1 == 0){
        printf("IP checksum check passed.\n");
    }
    else{
        printf("IP checksum check failed.\n");
    }

    // 修复：读取UDP实际长度，而非固定8
    byte udp_len_bytes[2];
    memcpy(udp_len_bytes, &frame[40], 2);
    short udp_len = bytesToShort(udp_len_bytes);
    //检验UDP头校验和
    short num2 = UdpCheckSum(&frame[26], &frame[30], &frame[34], udp_len);
    if(num2 == 0){
        printf("UDP checksum check passed.\n");
    }
    else{
        printf("UDP checksum check failed.\n");
    }

    //检验OCP头校验和
    short num3 = IPCheckSum(&frame[42], 32);
    if(num3 == 0){
        printf("OCP checksum check passed.\n"); 
    }
    else{
        printf("OCP checksum check failed.\n");
    }
}

//得到数据帧的长度（服务端暂未调用，修复内部fclose）
short getLenMAC(FILE *fp){
    byte data[18] = {0};
    size_t read_len = fread(data, sizeof(byte), 18, fp);
    if (read_len != 18) {
        printf("错误：读取IP长度失败，仅读取%d字节\n", (int)read_len);
        return 0;
    }
    byte IPLEN[2];
    memcpy(IPLEN, &data[16], 2);
    fseek(fp, 0, SEEK_SET);  // 重置文件指针到开头
    short lenIP = bytesToShort(IPLEN);
    return (lenIP > 0) ? (lenIP + 18) : 0;
}   

int main(){
    initHots();

    while(true){
        // 替换整个输入处理逻辑
        printf("\n请输入要发送的消息（输入quit退出）：");

        byte data[256] = {0};
        // 用 fgets 读取完整输入（包含空格）
        if (fgets((char*)data, sizeof(data), stdin) == NULL) {
            printf("读取输入失败\n");
            continue;
        }
        // 去掉 fgets 读取的换行符
        data[strcspn((char*)data, "\n")] = '\0';

        // 增加退出逻辑
        if (strcmp((char*)data, "quit") == 0) {
            printf("程序退出...\n");
            break;
        }

        int len = strlen((const char*)data);
        printf("输入字符串的长度为：%d\n", len);
        printf("输入字符串为：%s\n", (char*)data);

        // 封装数据为MAC帧
        MAC mac = encapsulateData(data, len);
        // 计算各层长度（修复：MAC长度计算逻辑）
        short lenOCP = bytesToShort(mac.ip.udp.ocp.len);  // OCP总长度（头部+数据）
        short lenUDP = lenOCP + 8;                       // UDP头部(8) + OCP
        short lenIP = lenUDP + 20;                       // IP头部(20) + UDP
        short lenMAC = lenIP + 18;                       // MAC头部(14)+FCS(4) + IP

        // 堆上分配帧内存（核心修复：调整free位置）
        byte* frame = (byte*)malloc(lenMAC);
        if (frame == NULL) {
            printf("内存分配失败！\n");
            return 1;
        }

        // 将MAC结构体转换为字节数组
        macToByte(mac, lenMAC, frame);

        // 展示16进制数据（修复：用实际lenMAC而非sizeof frame）
        displayByte("Frame", frame, lenMAC);
        // 展示MAC帧结构体数据
        displayMAC(mac);

        // 写入文件（核心修复：统一管理文件句柄）
        FILE *fpWrite = fopen("test.txt", "wb");
        if (fpWrite == NULL) {
            printf("文件打开失败！\n");
            free(frame); // 释放内存
            return 1;
        }
        writeMessage(frame, lenMAC, fpWrite);
        fclose(fpWrite); // 调用方关闭文件

        // 核心修复：使用完内存后再释放，避免野指针
        free(frame);
    }
    return 0;
}