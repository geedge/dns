#pragma once

#include "uthash.h"
#include "utlist.h"

#include <MESA/stream.h>
//#include <MESA/MESA_handle_logger.h>
//#include <MESA/MESA_prof_load.h>
//#include "dfb_dns_config.h"
//#include "dns_analyse.h"


#ifndef MIN
#define	MIN(a, b)	((a) > (b) ? (b) : (a))
#endif

#define	DNS_DIR_REQUEST		1
#define	DNS_DIR_RESPONSE	2
#define	DNS_DIR_DOUBLE		3

#define DNS_PORT			53
#define PROTID_DNS			6

#define DNSHDR_OPCODE_QUERY 	0
#define DNSHDR_OPCODE_IQUERY	1
#define DNSHDR_OPCODE_STATUS	2

#define DNSHDR_RCODE_NOERR	    0
#define DNSHDR_RCODE_FMTERR	1
#define DNSHDR_RCODE_SRVFAIL	2
#define DNSHDR_RCODE_NAMEERR	3
#define DNSHDR_RCODE_NOTIMPL	4
#define DNSHDR_RCODE_REFUSE	    5

#define GET_TYPE_YD1     1
#define GET_TYPE_YD2     2
#define GET_TYPE_AUTH    3
#define GET_TYPE_ADDIT   4

#define NS_INT16SZ		2
#define NS_INT32SZ		4

#define	DNS_RR_TYPE_ALL		0
#define	DNS_RR_TYPE_ANS		1
#define	DNS_RR_TYPE_AUTH	2
#define	DNS_RR_TYPE_ADD		3	

#define	DNS_ERROR_UNKNOWN		0
#define	DNS_ERROR_QUESTION		1
#define	DNS_ERROR_PAYLOAD_SHORT	2
#define	DNS_ERROR_CLASS_UNKNOWN	3
#define	DNS_ERROR_RR			4
#define	DNS_ERROR_ALL			5




#define NS_GET32(l, cp) do { \
	register u_char *t_cp = (u_char *)(cp); \
	(l) = ((u_int32_t)t_cp[0] << 24) \
	    | ((u_int32_t)t_cp[1] << 16) \
	    | ((u_int32_t)t_cp[2] << 8) \
	    | ((u_int32_t)t_cp[3]) \
	    ; \
	    (cp) += NS_INT32SZ; \
} while (0)

#define NS_PUT16(s, cp) do { \
	register u_int16_t t_s = (u_int16_t)(s); \
	register u_char *t_cp = (u_char *)(cp); \
	*t_cp++ = t_s >> 8; \
	*t_cp   = t_s; \
	(cp) += NS_INT16SZ; \
} while (0)

#define NS_PUT32(l, cp) do { \
	register u_int32_t t_l = (u_int32_t)(l); \
	register u_char *t_cp = (u_char *)(cp); \
	*t_cp++ = t_l >> 24; \
	*t_cp++ = t_l >> 16; \
	*t_cp++ = t_l >> 8; \
	*t_cp   = t_l; \
	(cp) += NS_INT32SZ; \
} while (0)

#define NS_GET16(s, cp) do { \
	register u_char *t_cp = (u_char *)(cp); \
	(s) = ((u_int16_t)t_cp[0] << 8) \
	    | ((u_int16_t)t_cp[1]) \
	    ; \
	    (cp) += NS_INT16SZ; \
} while (0)

/* 2015-09-07 lijia add, for get_plug_id() bug.  */
typedef struct
{
	const char *str;
	unsigned long long id;
}dns_str_contrast_id_t;

struct dns_session
{
	void *business_pme;
	int message_id;
	UT_hash_handle hh;
	struct dns_session *prev;
	struct dns_session *next;
};

struct dns_context
{
	char c2s_skiped_len;
	char s2c_skiped_len;
	char padding[4];
	short session_list_num;
	struct dns_session *session_list_head;
	struct dns_session *session_hash;

};

typedef struct _pcap_hdr
{
    u_int32_t tv_sec;
    u_int32_t tv_usec;
    u_int32_t len;
    u_int32_t caplen;
}pcap_hdr_t;

#define	MAX_LOG_PATH_LEN	256

enum dns_statis_info_t
{
	V4_T_PPS=0,
	V4_T_BPS,
	V4_U_PPS,
	V4_U_BPS,
	V6_T_PPS,
	V6_T_BPS,
	V6_U_PPS,
	V6_U_BPS,
	PKT_UNKNOWN,
	Q_PKT,
	R_PKT,
	ERR_PKT,
	Q_A,
	Q_AAAA,
	Q_CNAME,
	Q_QUESTION,
	Q_UNKNOWN
};

#define	DNS_MAX_FIELD_ID_NUM	17

typedef struct _dns_proto_info
{
	int log_level;
	int cycle_time;
	int session_list_num_max;
	int fild_id[DNS_MAX_FIELD_ID_NUM];
	char log_path[MAX_LOG_PATH_LEN];
	
	void *logger;
	void *stat_handle;
}g_dns_proto_info_t;

#ifdef __cplusplus
extern "C"
{
#endif

int DNS_INIT();
void DNS_DESTROY();
void PROT_FUNSTAT(long long protflag);
void GET_PLUGID(unsigned short plugid);
long long FLAG_CHANGE(char* raw_flag_str);
char DNS_UDP_ENTRY(struct streaminfo *a_udp, void **pme, int thread_seq, void *a_packet);
char DNS_TCP_ENTRY(struct streaminfo *a_tcp, void **pme, int thread_seq, void *a_packet);

int get_rr_domain( char * msg,unsigned char ** ptr, unsigned char * buf, int buflen, const char *end);

#ifdef __cplusplus
}
#endif

