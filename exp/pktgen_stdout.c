#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define PKTGEN_MAGIC   (0xbe9be955)
#define ETH_DST_MAC    (0x020000000002)
#define ETH_SRC_MAC    (0x020000000001)

#define IP4_SRC_IP     "10.0.0.1"
#define IP4_DST_IP     "10.0.0.2"
#define IP4_TTL        (0x20)
#define IP4_PROTO_UDP  (0x11)

#define UDP_SRC_PORT   (0x09)
#define UDP_DST_PORT   (0x09)

#define PKTDEV_HDR_LEN (4)
#define ETH_HDR_LEN    (14)
#define IP4_HDR_LEN    (20)

#define PKTDEV_MAGIC   (0x3776)

unsigned int id = 0;

#if 0
static const unsigned char pkt[] = {
  // magic code
  0x76, 0x37,
  // frame length
  0x3C, 0x00,
  // pktgen packet
  0x90, 0xe2, 0xba, 0x5d, 0x8d, 0xc9,
  0x90, 0xe2, 0xba, 0x5d, 0x8f, 0xcc,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x00, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00

};
static const unsigned short pktlen = sizeof(pkt) / sizeof(pkt[0]);
#endif

struct packet {
  u_int16_t pd_magic;
  u_int16_t pd_frame_len;

  u_int8_t  eth_dst_mac[6];
  u_int8_t  eth_src_mac[6];
  u_int16_t eth_type;

  u_int16_t ip4_vers;
  u_int16_t ip4_len;
  u_int16_t ip4_id;
  u_int16_t ip4_flags;
  u_int8_t  ip4_ttl;
  u_int8_t  ip4_protocol;
  u_int16_t ip4_csum;
  u_int32_t ip4_src_ip;
  u_int32_t ip4_dst_ip;

  u_int16_t udp_src;
  u_int16_t udp_dst;
  u_int16_t udp_len;
  u_int16_t udp_csum;

  u_int32_t pg_magic;
  u_int32_t pg_seq_num;
  u_int64_t pg_time;
} __attribute__((packed));

struct packet fill_packet(struct packet pkt, unsigned short frame_len)
{
  int ret;

  pkt.pd_magic = htons(PKTDEV_MAGIC);
  pkt.pd_frame_len = htons(frame_len);

  pkt.eth_dst_mac[5] = (ETH_DST_MAC      ) & 0xFF;
  pkt.eth_dst_mac[4] = (ETH_DST_MAC >>  8) & 0xFF;
  pkt.eth_dst_mac[3] = (ETH_DST_MAC >> 16) & 0xFF;
  pkt.eth_dst_mac[2] = (ETH_DST_MAC >> 24) & 0xFF;
  pkt.eth_dst_mac[1] = (ETH_DST_MAC >> 32) & 0xFF;
  pkt.eth_dst_mac[0] = (ETH_DST_MAC >> 40) & 0xFF;
  pkt.eth_src_mac[5] = (ETH_SRC_MAC      ) & 0xFF;
  pkt.eth_src_mac[4] = (ETH_SRC_MAC >>  8) & 0xFF;
  pkt.eth_src_mac[3] = (ETH_SRC_MAC >> 16) & 0xFF;
  pkt.eth_src_mac[2] = (ETH_SRC_MAC >> 24) & 0xFF;
  pkt.eth_src_mac[1] = (ETH_SRC_MAC >> 32) & 0xFF;
  pkt.eth_src_mac[0] = (ETH_SRC_MAC >> 40) & 0xFF;
  pkt.eth_type = htons(0x0800);

  pkt.ip4_vers = htons(0x4500);
  pkt.ip4_len = htons(frame_len - ETH_HDR_LEN);
  pkt.ip4_id = htons(1000 + id);
  pkt.ip4_flags = 0;
  pkt.ip4_ttl = IP4_TTL;
  pkt.ip4_protocol = IP4_PROTO_UDP;
  pkt.ip4_csum = 0;
  ret = inet_pton(AF_INET, IP4_SRC_IP, &pkt.ip4_src_ip);
  if (ret <= 0) {
    fprintf(stderr, "ip4_src_ip: format error\n");
    exit(EXIT_FAILURE);
  }
  ret = inet_pton(AF_INET, IP4_DST_IP, &pkt.ip4_dst_ip);
  if (ret <= 0) {
    fprintf(stderr, "ip4_src_ip: format error\n");
    exit(EXIT_FAILURE);
  }

  pkt.udp_src = htons(UDP_SRC_PORT);
  pkt.udp_dst = htons(UDP_DST_PORT);
  pkt.udp_len = htons(frame_len - ETH_HDR_LEN - IP4_HDR_LEN);
  pkt.udp_csum = 0;

  pkt.pg_magic = htonl(PKTGEN_MAGIC);
  pkt.pg_seq_num = htons(id++);
  pkt.pg_time = 0;

  return pkt;
};

// ./simple_pktgen frame_len nloop npkt
int main(int argc, char **argv)
{
  u_int8_t *pkt;//, *p;
  struct packet data;
  int i, len;

  unsigned short frame_len = 60;
  unsigned int npkt = 1;
  unsigned int nloop = 1;

  len = PKTDEV_HDR_LEN + frame_len;

  // npkt
  if (frame_len >= 60)
    pkt = calloc((size_t)(len * npkt), sizeof(u_int8_t));
  else {
    fprintf(stderr, "frame size error: %d\n", frame_len);
    return 1;
  }

  // fill packet
  data = fill_packet(data, frame_len);
  //memcpy(pkt, &data, sizeof(struct packet));

  // pack
  for (i = 0; i < npkt; i++)
    memcpy(pkt + (len * i), &data, sizeof(struct packet));

  // nloop
  for (i = 0; i < nloop; i++)
    write(1, pkt, len * npkt);

  if (pkt)
    free(pkt);

  return 0;
}
