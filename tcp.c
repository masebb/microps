#include <asm-generic/errno-base.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

#include "platform.h"

#include "util.h"
#include "ip.h"
#include "tcp.h"

#define TCP_FLG_FIN 0x01
#define TCP_FLG_SYN 0x02
#define TCP_FLG_RST 0x04
#define TCP_FLG_PSH 0x08
#define TCP_FLG_ACK 0x10
#define TCP_FLG_URG 0x20

#define TCP_FLG_IS(x, y) ((x & 0x3f) == (y))
#define TCP_FLG_ISSET(x, y) ((x & 0x3f) & (y) ? 1 : 0)

#define TCP_PCB_SIZE 16

#define TCP_PCB_STATE_FREE         0
#define TCP_PCB_STATE_CLOSED       1
#define TCP_PCB_STATE_LISTEN       2
#define TCP_PCB_STATE_SYN_SENT     3
#define TCP_PCB_STATE_SYN_RECEIVED 4
#define TCP_PCB_STATE_ESTABLISHED  5
#define TCP_PCB_STATE_FIN_WAIT1    6
#define TCP_PCB_STATE_FIN_WAIT2    7
#define TCP_PCB_STATE_CLOSING      8
#define TCP_PCB_STATE_TIME_WAIT    9
#define TCP_PCB_STATE_CLOSE_WAIT  10
#define TCP_PCB_STATE_LAST_ACK    11

struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

struct tcp_hdr {
    uint16_t src;  //送信元ポート
    uint16_t dst;  //送信ポート
    uint32_t seq;  //シーケンス番号
    uint32_t ack;  //確認応答番号
    uint8_t off;  //Data Offset
    uint8_t flg;  //フラグ
    uint16_t wnd; //ウィンドウサイズ
    uint16_t sum;  //チェックサム
    uint16_t up; //緊急ポインタ(未使用)
};

struct tcp_segment_info {
    uint32_t seq;  //シーケンス番号
    uint32_t ack;  //確認応答番号
    uint16_t len;  //シーケンス番号を消費するデータ長
    uint16_t wnd;  // 受信ウィンドウ(相手の受信バッファの空き)
    uint16_t up;  //緊急ポインタ(未使用)
};

struct tcp_pcb {
    int state; //コネクション状態
    struct ip_endpoint local; //local側コネクション情報
    struct ip_endpoint foreign;  //foreign側コネクション情報
    struct {
        uint32_t nxt;  //次に送信するシーケンス番号
        uint32_t una;  //ACKが帰ってきてない最後のシーケンス番号
        uint16_t wnd;  //相手の受信ウィンドウ
        uint16_t up;   //緊急ポインタ(未使用)
        uint32_t wl1;  //snd.windを更新した時の受信セグメントのシーケンス番号
        uint32_t wl2;  //snd.windを更新した際の受信セグメントのACK番号
    } snd; //送信時に必要な情報
    uint32_t iss; //自分の初期シーケンス番号
    struct {
        uint32_t nxt; //次に受信を期待するシーケンス番号
        uint16_t wnd; //自分の受信ウィンドウ
        uint16_t up;  //緊急ポインタ(未使用)
    } rcv; //受信時に必要な情報
    uint32_t irs;  //相手の初期シーケンス番号
    uint16_t mtu;  //送信デバイスのMTU
    uint16_t mss;  //最大セグメントサイズ
    uint8_t buf[65535]; /* receive buffer */
    struct sched_ctx ctx;
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct tcp_pcb pcbs[TCP_PCB_SIZE];

static char *
tcp_flg_ntoa(uint8_t flg)
{
    static char str[9];

    snprintf(str, sizeof(str), "--%c%c%c%c%c%c",
        TCP_FLG_ISSET(flg, TCP_FLG_URG) ? 'U' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_ACK) ? 'A' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_PSH) ? 'P' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_RST) ? 'R' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_SYN) ? 'S' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_FIN) ? 'F' : '-');
    return str;
}

static void
tcp_dump(const uint8_t *data, size_t len) 
{
    struct tcp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct tcp_hdr *)data;
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "        seq: %u\n", ntoh32(hdr->seq));
    fprintf(stderr, "        ack: %u\n", ntoh32(hdr->ack));
    fprintf(stderr, "        off: 0x%02x (%d)\n", hdr->off, (hdr->off >> 4) << 2);
    fprintf(stderr, "        flg: 0x%02x (%s)\n", hdr->flg, tcp_flg_ntoa(hdr->flg));
    fprintf(stderr, "        wnd: %u\n", ntoh16(hdr->wnd));
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "         up: %u\n", ntoh16(hdr->up));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/*
 * TCP Protocol Control Block (PCB)
 *
 * NOTE: TCP PCB functions must be called after mutex locked
 */

static struct tcp_pcb *
tcp_pcb_alloc(void)
{
  struct tcp_pcb *pcb;

  for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
    if (pcb->state == TCP_PCB_STATE_FREE) {
      pcb->state = TCP_PCB_STATE_CLOSED;
      sched_ctx_init(&pcb->ctx);
      return pcb;
    }
  }
  return NULL;
}

static void
tcp_pcb_release(struct tcp_pcb *pcb)
{
  char ep1[IP_ENDPOINT_STR_LEN];
  char ep2[IP_ENDPOINT_STR_LEN];

  if (sched_ctx_destroy(&pcb->ctx) == -1) {
    // 解放できない場合、起床させる
    sched_wakeup(&pcb->ctx);
    return;
  }
  debugf("released, local=%s, foreign=%s",
      ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)),
      ip_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2))
      );
  memset(pcb, 0, sizeof(*pcb));//初期化が面倒なのでインチキ
}

static struct tcp_pcb *
tcp_pcb_select(struct ip_endpoint *local, struct ip_endpoint *foreign)
{
  struct tcp_pcb *pcb, *listen_pcb = NULL;
  
  for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
    //ローカルアドレスがマッチしているか
    if ((pcb->local.addr == IP_ADDR_ANY || pcb->local.addr == local->addr) && pcb->local.port == local->port) {
      //ローカルアドレスにbind可能かどうか調べるときは外部アドレスは指定されないので、検証
      if (!foreign) {
        return pcb;
      }
      //ローカルアドレスと外部アドレスが共に一致
      if (pcb->foreign.addr == foreign->addr && pcb->foreign.port == foreign->port) {
        return pcb;
      }
      //外部アドレスを指定していない
      if (pcb->state == TCP_PCB_STATE_LISTEN) {
        if (pcb->foreign.addr == IP_ADDR_ANY && pcb->foreign.port == 0) {
          listen_pcb = pcb;
        }
      }
    }
  }
  return listen_pcb;
}

static struct tcp_pcb *
tcp_pcb_get(int id)
{
  struct tcp_pcb *pcb;

  if (id < 0 || id >= (int)countof(pcbs)) {
    return NULL;
  }
  pcb = &pcbs[id];
  if (pcb->state == TCP_PCB_STATE_FREE) {
    return NULL;
  }
  return pcb;
}

static int
tcp_pcb_id(struct tcp_pcb *pcb)
{
  return indexof(pcbs, pcb);
}

static ssize_t
tcp_output_segment(uint32_t seq, uint32_t ack, uint8_t flg, uint16_t wnd, uint8_t *data, size_t len, struct ip_endpoint *local, struct ip_endpoint *foreign)
{
  uint8_t buf[IP_PAYLOAD_SIZE_MAX] = {};
  struct tcp_hdr *hdr;
  struct pseudo_hdr pseudo;
  uint16_t psum;
  uint16_t total;
  char ep1[IP_ENDPOINT_STR_LEN];
  char ep2[IP_ENDPOINT_STR_LEN];

  hdr = (struct tcp_hdr *)buf;

  // ヘッダ作成
  hdr->seq = hton32(seq);
  hdr->ack = hton32(ack);
  hdr->flg = flg;
  hdr->wnd = hton16(wnd);
  hdr->src = local->port;
  hdr->dst = foreign->port;
  hdr->up = 0;
  hdr->off = (sizeof(*hdr) >> 2) << 4;
  memcpy(hdr+1, data, len);
  hdr->sum = 0;

  //疑似ヘッダ
  pseudo.src = local->addr;
  pseudo.dst = foreign->addr;
  pseudo.zero = 0;
  pseudo.protocol = IP_PROTOCOL_TCP;
  total = sizeof(*hdr) + len;
  pseudo.len = hton16(total);
  psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);

  // チェックサム挿入
  hdr->sum = cksum16((uint16_t *)hdr, total, psum);

  debugf("%s => %s, len=%zu (payload=%zu)",
      ip_endpoint_ntop(local, ep1, sizeof(ep1)),
      ip_endpoint_ntop(foreign, ep2, sizeof(ep2)),
      total, len);
  tcp_dump((uint8_t *)hdr, total);

  if (ip_output(IP_PROTOCOL_TCP, (uint8_t *)hdr, total, local->addr, foreign->addr) == -1 ){
    errorf("ip_output() failure");
    return -1;
  }
  return len;
}

static ssize_t
tcp_output(struct tcp_pcb *pcb, uint8_t flg, uint8_t *data, size_t len)
{
  uint32_t seq;

  seq = pcb->snd.nxt;
  // 初回送信時は初期シーケンス番号(iss)を使う
  if (TCP_FLG_ISSET(flg, TCP_FLG_SYN)) {
    seq = pcb->iss;
  }
  if (TCP_FLG_ISSET(flg, TCP_FLG_SYN | TCP_FLG_FIN) || len) {
    //TODO
  }
  return tcp_output_segment(seq, pcb->rcv.nxt, flg, pcb->rcv.wnd, data, len, &pcb->local, &pcb->foreign);
}

/* rfc793 - section 3.9 [Event Processing > SEGMENT ARRIVES] */
static void
tcp_segment_arrives(struct tcp_segment_info *seg, uint8_t flags, uint8_t *data, size_t len, struct ip_endpoint *local, struct ip_endpoint *foreign)
{
  struct tcp_pcb *pcb;

  pcb = tcp_pcb_select(local, foreign); 
  // 使用していないポートあてに届いたTCPセグメントの処理
  if (!pcb || pcb->state == TCP_PCB_STATE_CLOSED) {
    // RSTフラグを含んでいたら無視
    if (TCP_FLG_ISSET(flags, TCP_FLG_RST)) {
      return;
    }
    // ACKフラグを含まないセグメント受信(こちらは何も送信していないのでRSTを送る)
    if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
      tcp_output_segment(0, seg->seq + seg->len, TCP_FLG_RST | TCP_FLG_ACK, 0, NULL, 0, local, foreign);
    } else {
      tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
    }
    return;
  }
  switch(pcb->state) {
    case TCP_PCB_STATE_LISTEN:
      /*
       * 1st check for an RST
       */
      // 無視
      if (TCP_FLG_ISSET(flags, TCP_FLG_RST)) {
        return;
      }
      /*
       * 2nd check for an ACK
       */
      // ACKフラグを含んでいたらRSTを送信
      if (TCP_FLG_ISSET(flags, TCP_FLG_ACK)) { 
        tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
        return;
      }

      /*
       * 3rd check for an SYN
       */
      if (TCP_FLG_ISSET(flags, TCP_FLG_SYN)) {
        /* ignore: security/compartment check */
        /* ignore: precedence check */
        pcb->local = *local;
        pcb->foreign = *foreign;
        pcb->rcv.wnd = sizeof(pcb->buf);
        pcb->rcv.nxt = seg->seq + 1;
        pcb->irs = seg->seq;
        pcb->iss = random();
        tcp_output(pcb, TCP_FLG_SYN | TCP_FLG_ACK, NULL, 0);
        pcb->snd.nxt = pcb->iss;
        pcb->snd.una = pcb->iss;
        pcb->state = TCP_PCB_STATE_SYN_RECEIVED;

        //TODO COPY COMMENT FROM SLIDE

        return;
      }

      /*
       * 4th other text or control
       */

      /* drop segment */
      return;
    case TCP_PCB_STATE_SYN_SENT:
      /*
       * 1st check the ACK bit
       */

      /*
       * 2nd check the RST bit
       */

      /*
       * 3rd check security and precedence (ignore)
       */

      /*
       * 4th check the SYN bit
       */

      /*
       * 5th, if neither of the SYN or RST bits is set then drop the segment and return
       */
      if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
        //drop
        return;
      }
      switch (pcb->state) {
        case TCP_PCB_STATE_SYN_RECEIVED:
          // 送信セグメントに対する妥当なACK番号の範囲かチェック
          if (pcb->snd.una <= seg->ack && seg->ack <= pcb->snd.nxt) {
            // ESTABLISHEDに
            pcb->state = TCP_PCB_STATE_ESTABLISHED;
            sched_wakeup(&pcb->ctx);
          } else {
            tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
            return;
          }
          break;
      }

      /* drop segment */
      return;
  }
  /*
   * Otherwise
   */

  /*
   * 1st check sequence number
   */

  /*
   * 2nd check the RST bit
   */

  /*
   * 3rd check security and precedence (ignore)
   */

  /*
   * 4th check the SYN bit
   */

  /*
   * 5th check the ACK field
   */

  /*
   * 6th, check the URG bit (ignore)
   */

  /*
   * 7th, process the segment text
   */

  /*
   * 8th, check the FIN bit
   */

  return;
}

static void
tcp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
  struct tcp_hdr *hdr;
  // 疑似ヘッダ
  struct pseudo_hdr pseudo;
  uint16_t psum;
  char addr1[IP_ADDR_STR_LEN];
  char addr2[IP_ADDR_STR_LEN];
  struct ip_endpoint local, foreign;
  uint16_t hlen;
  struct tcp_segment_info seg;

  if (len < sizeof(*hdr)) {
    errorf("too short");
    return;
  }

  hdr = (struct tcp_hdr *)data;

  // チェックサム検証
  // 疑似ヘッダ作成
  pseudo.src = src;
  pseudo.dst = dst;
  pseudo.zero = 0;
  pseudo.protocol = IP_PROTOCOL_TCP;
  pseudo.len = hton16(len);
  psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);

  if (cksum16((uint16_t *)hdr, len, psum) != 0) {
    errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
    return;
  }

  if (src == IP_ADDR_BROADCAST || dst == IP_ADDR_BROADCAST) {
    errorf("broadcast is not allowed");
    return;
  }

  debugf("%s:%d => %s:%d, len=%zu (payload=%zu)", 
      ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
      ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
      len, len - sizeof(*hdr)
      );
  tcp_dump(data, len);

  // 送信に備える
  local.addr = dst;
  local.port = hdr->dst;
  foreign.addr = src;
  foreign.port = hdr->src;
  hlen = (hdr->off >> 4) << 2;
  
  //tcp_segment_arrives()で必要な情報を集める
  seg.seq = ntoh32(hdr->seq);
  seg.ack = ntoh32(hdr->ack);
  seg.len = len - hlen;
  if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN)) {
    seg.len++;
  }
  if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN)) {
    seg.len++;
  }
  seg.wnd = ntoh16(hdr->wnd);
  seg.up = ntoh16(hdr->up);
  mutex_lock(&mutex);
  tcp_segment_arrives(&seg, hdr->flg, (uint8_t *)hdr + hlen, len - hlen, &local, &foreign);
  mutex_unlock(&mutex);

  return;
}

static void
event_handler(void *arg)
{
    struct tcp_pcb *pcb;

    mutex_lock(&mutex);
    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state != TCP_PCB_STATE_FREE) {
            sched_interrupt(&pcb->ctx);
        }
    }
    mutex_unlock(&mutex);
}

int
tcp_init(void)
{
  if (ip_protocol_register(IP_PROTOCOL_TCP, tcp_input) == -1) {
    errorf("ip_protocol_register() failure");
    return -1;
  }
  return 0;
}

/*
 * TCP User Command (RFC793)
 */

int
tcp_open_rfc793(struct ip_endpoint *local, struct ip_endpoint *foreign, int active)
{
  struct tcp_pcb *pcb;
  char ep1[IP_ENDPOINT_STR_LEN];
  char ep2[IP_ENDPOINT_STR_LEN];
  int state, id;

  mutex_lock(&mutex);
  pcb = tcp_pcb_alloc();
  if (!pcb) {
    errorf("tcp_pcb_alloc() failure");
    mutex_unlock(&mutex);
    return -1;
  }
  // 能動的なオープンは未実装のため弾く
  if (active) {
    errorf("active open does not implemant");
    tcp_pcb_release(pcb);
    mutex_unlock(&mutex);
    return -1;
  } else {
    debugf("passive open: local=%s, waiting for connection...", ip_endpoint_ntop(local, ep1, sizeof(ep1)));
    pcb->local = *local;
    if (foreign) {
      pcb->foreign = *foreign;
    }
    pcb->state = TCP_PCB_STATE_LISTEN;
  }
AGAIN:
  state = pcb->state;

  // waiting for state changed
  while (pcb->state == state) {
    //タスクを休止
    if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1) {
      //シグナルによる割り込みが発生
      debugf("interrputed");
      pcb->state = TCP_PCB_STATE_CLOSED;
      tcp_pcb_release(pcb);
      mutex_unlock(&mutex);
      errno = EINTR;
      return -1;
    }
  }

  if (pcb->state != TCP_PCB_STATE_ESTABLISHED) {
    if (pcb->state == TCP_PCB_STATE_SYN_RECEIVED) {
      goto AGAIN;
    }
    errorf("open error: %d", pcb->state);
    pcb->state = TCP_PCB_STATE_CLOSED;
    tcp_pcb_release(pcb);
    mutex_unlock(&mutex);
    return -1;
  }

  id = tcp_pcb_id(pcb);

  debugf("connection established: local=%s, foreign=%s",
      ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)),
      ip_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2))
      );
  
  mutex_unlock(&mutex);

  // コネクションが確立したらpcbのidを返す
  return id;
}

int
tcp_close(int id)
{
  struct tcp_pcb *pcb;

  mutex_lock(&mutex);
  pcb = tcp_pcb_get(id);
  if (!pcb) {
    errorf("pcb not found");
    mutex_unlock(&mutex);
    return -1;
  }

  //暫定処置でRSTを送信
  tcp_output(pcb, TCP_FLG_RST, NULL, 0);

  tcp_pcb_release(pcb);
  mutex_unlock(&mutex);

  return 0;
}
