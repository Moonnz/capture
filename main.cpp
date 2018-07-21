#include <pcap.h>
#include <stdio.h>
#include <iostream>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>
#include <errno.h>
#include <string.h>

void pcapHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    struct radiotap_header{
        uint8_t it_rev;
        uint8_t it_pad;
        uint16_t it_len;
    };


    const u_char *bssid;
    const u_char *essid;
    const u_char *essidLen;
    const u_char *channel;
    const u_char *rssi;

    int offset = 0;
    struct radiotap_header *rtaphdr;
    rtaphdr = (struct radiotap_header *) packet;
    offset = rtaphdr->it_len;
    bssid = packet + 42;
    essid = packet + 64;
    essidLen = packet + 63;
    rssi = packet + 22;
    signed int rssiDbm = rssi[0] - 256;
    channel = packet + 18;
    int channelFreq = channel[1] * 256 + channel[0];
    char *ssid = malloc(63);
    unsigned int i = 0;
    while(essid[i] > 0x1){
        ssid[i] = essid[i];
        i++;
    }
    ssid[i] = '\0';
    fprintf(stdout,"RSSI: %d dBm\n",rssiDbm);
    fprintf(stdout,"AP Frequency: %iMhz\n",channelFreq);
    fprintf(stdout,"ESSID length: %i bytes.\n",essidLen[0]);
    fprintf(stdout,"ESSID string: %s\n", ssid);
    fprintf(stdout,"BSSID string: %02X:%02X:%02X:%02X:%02X:%02X\n",bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);


    return;
}

int main(int argc, char *argv[]) {
    pcap_t *handle;
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "type mgt subtype beacon";	/* The filter expression */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */

    /* Define the device */
    //dev = argv[1];
    dev = "wlx0025223c5ece";

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(2);
    }

    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(2);
    }

    pcap_loop(handle, 10, pcapHandler, NULL);

    pcap_close(handle);
    return(0);
}