#define _GNU_SOURCE /* for F_SETSIG */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"

#include "driver/ether_tap.h"

#define CLONE_DEVICE "/dev/net/tun"

#define ETHER_TAP_IRQ (INTR_IRQ_BASE+2)

struct ether_tap {
    char name[IFNAMSIZ];//TAPデバイス名
    int fd;//ファイルディスクリプタ
    unsigned int irq;//IRQ番号
};

#define PRIV(x) ((struct ether_tap *)x->priv)

//TAPデバイスのHWアドレス設定
static int ether_tap_addr(struct net_device *dev) {
  int soc;
  struct ifreq ifr = {};

  soc = socket(AF_INET, SOCK_DGRAM, 0); //適当なソケットを作る
  if(soc == -1) {
    errorf("socket: %s, dev=%s", strerror(errno), dev->name);
    return -1;
  }

  strncpy(ifr.ifr_name, PRIV(dev)->name, sizeof(ifr.ifr_name)-1);
  if (ioctl(soc, SIOCGIFHWADDR, &ifr) == -1) { //ハードウェアアドレスを取得
    errorf("ioctl [SIOCGIFHWADDR]: %s, dev=%s", strerror(errno), dev->name);
    close(soc);
    return -1;
  }
  memcpy(dev->addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);//取得したアドレスをデバイス構造体にコピー
  close(soc);
  return 0;
}

static int ether_tap_open(struct net_device *dev) {
  struct ether_tap *tap;
  struct ifreq ifr = {};

  tap = PRIV(dev);
  //引数がよくわからん
  tap->fd = open(CLONE_DEVICE, O_RDWR);
  if (tap->fd == -1) {
    errorf("open: %s, dev=%s", strerror(errno), dev->name);
    return -1;
  }
  strncpy(ifr.ifr_name, tap->name, sizeof(ifr.ifr_name)-1);
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI; // IFF_TAP=TAPモード IFF_NO_PI:パケットにヘッダを付けない(自分で付ける)
  if (ioctl(tap->fd, TUNSETIFF, &ifr) == -1) {
    errorf("ioctl [TUNSETIFF]: %s, dev=%s", strerror(errno), dev->name);
    close(tap->fd);
    return -1;
  }
  
  // シグナル駆動I/Oの設定
  if (fcntl(tap->fd, F_SETOWN, getpid()) == -1) {
    errorf("fcntl(F_SETOWN): %s, dev=%s", strerror(errno), dev->name);
    close(tap->fd);
    return -1;
  }
  if (fcntl(tap->fd, F_SETFL, O_ASYNC) == -1) {
    errorf("fcntl(F_SETFL): %s, dev=%s", strerror(errno), dev->name);
    close(tap->fd);
    return -1;
  }
  if (fcntl(tap->fd, F_SETSIG, tap->irq) == -1) {
    errorf("fcntl(F_SETSIG): %s, dev=%s", strerror(errno), dev->name);
    close(tap->fd);
    return -1;
  }

  if (memcmp(dev->addr, ETHER_ADDR_ANY, ETHER_ADDR_LEN) == 0) {
    if (ether_tap_addr(dev) == -1) {
      errorf("ether_tap_addr() failure dev=%s", dev->name);
      close(tap->fd);
      return 01;
    }
  }
  return 0;
}

static int ether_tap_close(struct net_device *dev) {
  close(PRIV(dev)->fd); //ディスクリプタをクローズ
  return 0;
}

static ssize_t ether_tap_write(struct net_device *dev, const uint8_t *frame, size_t flen) {
  return write(PRIV(dev)->fd, frame, flen);
}

//これラップする必要性がいまいちわからん
int ether_tap_transmit(struct net_device *dev, uint16_t type, const uint8_t *buf, size_t len, const void *dst) {
  return ether_transmit_helper(dev, type, buf, len, dst, ether_tap_write);
}

//read() で読みだすだけ
static ssize_t ether_tap_read(struct net_device *dev, uint8_t *buf, size_t size) {
  ssize_t len;

  len = read(PRIV(dev)->fd, buf, size);
  if (len <= 0) {
    if (len == -1 && errno != EINTR) { //EINTR アセンブリのライブラリからインポートされてて怖
      errorf("read: %s, dev=%s", strerror(errno), dev->name);
    }
    return -1;
  }
  return len;
}

// 割り込みハンドラの設定
static int ether_tap_isr(unsigned int irq, void *id) {
  struct net_device *dev;
  struct pollfd pfd;
  int ret;

  dev = (struct net_device *)id;
  // fdってな～に?
  pfd.fd = PRIV(dev)->fd;
  pfd.events = POLL_IN;
  while (1) {
    ret = poll(&pfd, 1, 0);
    if (ret == -1) {
      if (errno == EINTR) { //処理中に割り込みが入ってきた場合、再試行する
        continue;
      }
      errorf("poll: %s, dev=%s", strerror(errno), dev->name);
      return -1;
    }
    if (ret == 0) { //読み込み可能なデータが無い場合(タイムアウト)
      break;
    }
    ether_input_helper(dev, ether_tap_read);
  }
  return 0;

}

static struct net_device_ops ether_tap_ops = {
    .open = ether_tap_open,
    .close = ether_tap_close,
    .transmit = ether_tap_transmit,
};

struct net_device * ether_tap_init(const char *name, const char *addr) {
  struct net_device *dev;
  struct ether_tap *tap;

  dev = net_device_alloc();
  if (!dev) {
    errorf("net_device_alloc() failure");
    return NULL;
  }

  ether_setup_helper(dev);//共通パラメータを設定

  if (addr) {
    if (ether_addr_pton(addr, dev->addr) == -1) {
      errorf("invaild address, addr=%s", addr);
      return NULL;
    }
  }
  dev->ops = &ether_tap_ops;
  tap = memory_alloc(sizeof(*tap));
  if (!tap) {
    errorf("memory_alloc() failure");
    return NULL;
  }
  strncpy(tap->name, name, sizeof(tap->name)-1); 
  tap->fd = -1;//無効値をとりあえずセット
  tap->irq = ETHER_TAP_IRQ;
  dev->priv = tap;
  if (net_device_register(dev) == -1) {
    errorf("net_device_register() failure");
    memory_free(tap);
    return NULL;
  }
  intr_request_irq(tap->irq, ether_tap_isr, INTR_IRQ_SHARED, dev->name, dev);
  infof("ethernet device initialized, dev=%s", dev->name);
  return dev;
  
  intr_request_irq(tap->irq, ether_tap_isr, INTR_IRQ_SHARED, dev->name, dev);//割り込みハンドラの設定
  infof("ethernet device initialized, dev=%s", dev->name);
  return dev;
}
