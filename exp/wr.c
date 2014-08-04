#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

static const unsigned char pkt[] = {
  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x00, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x01, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x02, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x03, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x04, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x05, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x06, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x07, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x08, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x09, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x00, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x01, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x02, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x03, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x04, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x05, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x06, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x07, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x08, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x09, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x00, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x01, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x02, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x03, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x04, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x05, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x06, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x07, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x08, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x09, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x00, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x01, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x02, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x03, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x04, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x05, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x06, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x07, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x08, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x09, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x00, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x01, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x02, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x03, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x04, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x05, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x06, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x07, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x08, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00,

  // magic code
  0x37, 0x76,
  // frame length
  0x00, 0x3C,
  // pktgen packet
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x00,
  0x45, 0x00, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00,
  0x20, 0x11, 0x86, 0xb8, 0x0a, 0x00, 0x00, 0x01,
  0x0a, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x09,
  0x00, 0x1a, 0x00, 0x00, 0xbe, 0x9b, 0xe9, 0x55,
  0x00, 0x00, 0x00, 0x09, 0x52, 0x55, 0x1d, 0x74,
  0x00, 0x02, 0x43, 0xe2, 0x00, 0x00
};
static const unsigned short pktlen = sizeof(pkt) / sizeof(pkt[0]);

int main(int argc, char **argv)
{
  int fd, i, ret;
  struct timespec ts;

  ts.tv_sec  = 0;
  ts.tv_nsec = 10000;    // 1ms

  if (argc != 2) {
    printf("Usage: ./wr /dev/pkt/eth0\n");
    return 1;
  }

  fd = open(argv[1], O_WRONLY);
  if (fd < 0) {
    fprintf(stderr, "cannot open pktdev device: %s\n", argv[1]);
    return 1;
  }

  for (i = 0; i < 20; i++) {
    ret = write(fd, pkt, pktlen);
    if (ret != pktlen) {
      printf("write error: %d\n", ret);
      return 1;
    }
//    nanosleep(&ts, NULL);
  }

  close(fd);

  return 0;
}