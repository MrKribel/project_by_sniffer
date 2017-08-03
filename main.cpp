//
// Created by root on 02.08.17.
//

#include <pcap/pcap.h>
#include <iostream>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h> //здесь определена struct iphdr
#include <linux/if_ether.h>//здесь определена ethhdr
#include <linux/tcp.h>//здесь struct tcphdr
#include <linux/udp.h>

#define PRINT_BYTES_PER_LINE 16


struct bpf_program filter_prog; //Структура bpf_program является указателем на программу BPF-фильтра и используется функцией PacketSetBPF для установки фильтра в драйвере

using namespace std;

static char errbuf[PCAP_ERRBUF_SIZE];//буфер ошибок



static void  print_data_hex(const uint8_t* data, int size)
{
    int offset = 0;
    int nlines = size / PRINT_BYTES_PER_LINE;
    if(nlines * PRINT_BYTES_PER_LINE < size)
        nlines++;

    printf("        ");

    for(int i = 0; i < PRINT_BYTES_PER_LINE; i++)
        printf("%02X ", i);

    printf("\n\n");

    for(int line = 0; line < nlines; line++)
    {
        printf("%04X    ", offset);
        for(int j = 0; j < PRINT_BYTES_PER_LINE; j++)
        {
            if(offset + j >= size)
                printf("   ");
            else
                printf("%02X ", data[offset + j]);
        }

        printf("   ");

        for(int j = 0; j < PRINT_BYTES_PER_LINE; j++)
        {
            if(offset + j >= size)
                printf(" ");
            else if(data[offset + j] > 31 && data[offset + j] < 127)
                printf("%c", data[offset + j]);
            else
                printf(".");
        }

        offset += PRINT_BYTES_PER_LINE;
        printf("\n");
    }
}



//pcap_pkthdr - хранит информацию о пакете : время , длина пакета , длина порции или фрагмента
static void handle_packet(uint8_t* user, const struct pcap_pkthdr *hdr, const uint8_t* bytes)
{

    (void)user;

    struct iphdr* ip_header = (struct iphdr*)(bytes + sizeof(struct ethhdr));//iphdr - структура для работы с ip заголовками
    //ethhdr - струткура Ethernet-пакета
    struct sockaddr_in  source, dest; // струткура sockaddr_in описывает сокет для работы с протоколами IP

    memset(&source, 0, sizeof(source));//заполняем 0лями source
    memset(&dest, 0, sizeof(dest));

    //sin_addr - ip-адрес
    source.sin_addr.s_addr = ip_header->saddr;// saddr (откуда)
    dest.sin_addr.s_addr = ip_header->daddr;//daddr (куда)

    char source_ip[128];
    char dest_ip[128];

    strncpy(source_ip, inet_ntoa(source.sin_addr), sizeof(source_ip));//inet_ntoa - конвертирует адрес в стандартный формат интернет
    strncpy(dest_ip, inet_ntoa(dest.sin_addr), sizeof(dest_ip));

    int source_port = 0;
    int dest_port = 0;
    int data_size = 0;
    int ip_header_size = ip_header->ihl * 4;//ihl - The Internet Header Length - Поле Internet заголовка. Представляет собой длину Internet заголовка, измеренную в 32-битных словах.
    char* next_header = (char*)ip_header + ip_header_size;

    if(ip_header->protocol == IPPROTO_TCP)
    {
        struct tcphdr* tcp_header = (struct tcphdr*)next_header;
        source_port = ntohs(tcp_header->source);//ntohs - преобразует сетевой порядок расположения байтов положительного короткого целого netshort в узловой порядок расположения байтов.
        dest_port = ntohs(tcp_header->dest);
        int tcp_header_size = tcp_header->doff * 4;
        data_size = hdr->len - sizeof(struct ethhdr) - ip_header_size - tcp_header_size;
    }
   else if(ip_header->protocol == IPPROTO_UDP)
    {
        struct udphdr* udp_header = (struct udphdr*)next_header;
        source_port = ntohs(udp_header->source);
        dest_port = ntohs(udp_header->dest);
        data_size = hdr->len - sizeof(struct ethhdr) - ip_header_size - sizeof(struct udphdr);
    }

    printf("\n%s:%d -> %s:%d, %d (0x%x) bytes\n\n",
    source_ip, source_port, dest_ip, dest_port, data_size, data_size);

    if(data_size > 0)
    {
        int headers_size = hdr->len - data_size;
        print_data_hex(bytes + headers_size, data_size);
    }
}



void list_devs()
{

    pcap_if_t *alldevs, *currdev;

    pcap_findalldevs(&alldevs, errbuf);

    currdev = alldevs;

    while(currdev)
    {
        printf("%s%s\t%s\n", currdev->name, ":",
               currdev->description ? currdev->description :
               "(нет описания)"
        );
        currdev = currdev->next;
    }

    if(alldevs)
        pcap_freealldevs(alldevs);//очищаем список
}



int main()
{

    setlocale(LC_ALL, "Russian");

    printf("Список доступных устройств: \n\n");

    list_devs();//выводим список доступных устройств

    const char* device;
    const char* filter;

    device = pcap_lookupdev(errbuf);//здесь берётся первый благоприятный для снифинга интерфейс
    //думаю, нужно переделать дать возможность выбора

    pcap_t* pcap = pcap_open_live(device, BUFSIZ, 1, 65535, errbuf);

    pcap_compile(pcap, &filter_prog, filter, 0, PCAP_NETMASK_UNKNOWN); //Компилируем фильтр

    pcap_setfilter(pcap, &filter_prog);//Устанавливаем откомпилированный фильтр


//здесь будет функция выводящая перехваченные пакеты

    printf("Listening %s, filter: %s...\n", device, filter);
    int res = pcap_loop(pcap, -1, handle_packet, NULL);
    printf("pcap_loop returned %d\n", res);

    pcap_close(pcap);

    return 0;
}