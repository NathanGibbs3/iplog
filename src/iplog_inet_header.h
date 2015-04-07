/*
** $Id: iplog_inet_header.h,v 1.5 2000/12/09 20:20:20 odin Exp $
*/

#ifndef __IPLOG_INET_HEADER_H
#define __IPLOG_INET_HEADER_H

struct udphdr {
	u_int16_t uh_sport;
	u_int16_t uh_dport;
	u_int16_t uh_ulen;
	u_int16_t uh_sum;
} __attribute__ ((packed));

struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN
	u_int ip_hl:4;
	u_int ip_v:4;
#elif BYTE_ORDER == BIG_ENDIAN
	u_int ip_v:4;
	u_int ip_hl:4;
#else
#	error "No endianness defined"
#endif
	u_int8_t ip_tos;
	u_int16_t ip_len;
	u_int16_t ip_id;
	u_int16_t ip_off;
#define IP_RF		0x8000
#define IP_DF		0x4000
#define IP_MF		0x2000
#define IP_OFFMASK	0x1fff
	u_int8_t ip_ttl;
	u_int8_t ip_p;
	u_int16_t ip_sum;
	struct in_addr ip_src;
	struct in_addr ip_dst;
} __attribute__ ((packed));

struct tcphdr {
	u_int16_t th_sport;
	u_int16_t th_dport;
	u_int32_t th_seq;
	u_int32_t th_ack;
#if BYTE_ORDER == LITTLE_ENDIAN
	u_int8_t th_x2:4;
	u_int8_t th_off:4;
#elif BYTE_ORDER == BIG_ENDIAN
	u_int8_t th_off:4;
	u_int8_t th_x2:4;
#else
#	error "No endianness defined"
#endif
	u_int8_t th_flags;
#define TH_FIN	0x01
#define TH_SYN	0x02
#define TH_RST	0x04
#define TH_PUSH	0x08
#define TH_ACK	0x10
#define TH_URG	0x20
	u_int16_t th_win;
	u_int16_t th_sum;
	u_int16_t th_urp;
} __attribute__ ((packed));

#define ICMP_ECHO_REPLY			0
#define ICMP_DEST_UNREACHABLE	3
#define ICMP_SOURCE_QUENCH		4
#define ICMP_REDIRECT			5
#define ICMP_ECHO				8
#define ICMP_ROUTER_ADVERT		9
#define ICMP_ROUTER_SOLICIT		10
#define ICMP_TIME_EXCEEDED		11
#define ICMP_PARAMETER_PROBLEM	12
#define ICMP_TIMESTAMP			13
#define ICMP_TIMESTAMP_REPLY	14
#define ICMP_INFO_REQUEST		15
#define ICMP_INFO_REPLY			16
#define ICMP_ADDRESS			17
#define ICMP_ADDRESS_REPLY		18
#define ICMP_UNDEFINED			19

#define UNREACHABLE_MAX			16
#define REDIRECT_MAX			3

struct icmp {
	u_int8_t icmp_type;
	u_int8_t icmp_code;
	u_int16_t icmp_cksum;
	union {
		u_int8_t ih_pptr;
		struct in_addr ih_gwaddr;
		struct ih_idseq {
			u_int16_t icd_id;
			u_int16_t icd_seq;
		} ih_idseq;
		u_int32_t ih_reserved;
		struct ih_rdiscovery {
			u_int8_t num_addr;
			u_int8_t addr_entry_size;
			u_int16_t lifetime;
		} ih_rdiscovery;
	} icmp_hun;
#define	icmp_pptr		icmp_hun.ih_pptr
#define	icmp_gwaddr		icmp_hun.ih_gwaddr
#define	icmp_id			icmp_hun.ih_idseq.icd_id
#define	icmp_seq		icmp_hun.ih_idseq.icd_seq
#define	icmp_void		icmp_hun.ih_void
#define	icmp_pmvoid		icmp_hun.ih_pmtu.ipm_void
#define	icmp_nextmtu	icmp_hun.ih_pmtu.ipm_nextmtu
	union {
		struct id_ts {
			u_int32_t its_otime;
			u_int32_t its_rtime;
			u_int32_t its_ttime;
		} id_ts;
		struct id_ip {
			struct ip idi_ip;
		} id_ip;
		u_int32_t id_mask;
		char id_data[1];
		struct id_rdiscovery {
			struct in_addr router_addr;
			struct in_addr pref_level;
		} id_rdiscovery;
	} icmp_dun;
#define icmp_num_addr			icmp_hun.ih_rdiscovery.num_addr
#define icmp_addr_entry_size	icmp_hun.ih_rdiscovery.addr_entry_size
#define icmp_lifetime			icmp_hun.ih_rdiscovery.lifetime
#define	icmp_otime				icmp_dun.id_ts.its_otime
#define	icmp_rtime				icmp_dun.id_ts.its_rtime
#define	icmp_ttime				icmp_dun.id_ts.its_ttime
#define	icmp_ip					icmp_dun.id_ip.idi_ip
#define	icmp_mask				icmp_dun.id_mask
#define	icmp_data				icmp_dun.id_data
} __attribute__ ((packed));

#endif /* __IPLOG_INET_HEADER_H */
/* vim:ts=4:sw=8:tw=0 */
