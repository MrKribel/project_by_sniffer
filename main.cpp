//
// Created by root on 02.08.17.
//

#include <pcap/pcap.h>
#include <iostream>


struct bpf_program filter_prog;

using namespace std;

static char errbuf[PCAP_ERRBUF_SIZE];//буфер ошибок

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

    pcap_t* pcap = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);

    pcap_compile(pcap, &filter_prog, filter, 0, PCAP_NETMASK_UNKNOWN); //Компилируем фильтр

    pcap_setfilter(pcap, &filter_prog);//Устанавливаем откомпилированный фильтр


//здесь будет функция выводящая перехваченные пакеты

   


    return 0;
}