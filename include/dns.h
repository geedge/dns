#ifndef DNS_ANALYSE_H
#define DNS_ANALYSE_H

#include <MESA/cJSON.h>

typedef unsigned char u_char;
typedef unsigned short u_int16_t;
typedef unsigned int u_int32_t;

#define G_DNS_TTL (rand()%1800+1800)//0.5->1hour 2015.01.26by ljp

#define	MAX_CHEAT_PKT_PAYLOAD_LEN	512

#define	DNS_MAX_SALT		256
#define	DNS_MAX_OWNER		256
#define	DNS_MAX_MAPS		256
#define	DNS_MAX_PUBLIC_KEY	256
#define	DNS_MAX_SIGNER_NAME	256
#define	DNS_MAX_SIGNATURE	256
#define	DNS_MAX_DIGEST		256
#define	DNS_MAX_TARGET		256

#define DNS_HINFO_MAX_CPU	40
#define DNS_HINFO_MAX_OS	40
#define DNS_MAX_NAME		255

/* RR type */
#define DNS_TYPE_A			1
#define DNS_TYPE_NS			2
#define DNS_TYPE_MD			3
#define DNS_TYPE_MF			4
#define DNS_TYPE_CNAME		5
#define DNS_TYPE_SOA		6
#define DNS_TYPE_MB			7
#define DNS_TYPE_MG			8
#define DNS_TYPE_MR			9
#define DNS_TYPE_NULL		10
#define DNS_TYPE_WKS		11
#define DNS_TYPE_PTR		12
#define DNS_TYPE_HINFO		13
#define DNS_TYPE_MINFO		14
#define DNS_TYPE_MX			15
#define DNS_TYPE_TXT		16
#define DNS_TYPE_RP			17
#define	DNS_TYPE_ISDN		20
#define DNS_TYPE_AAAA		28	//dns_ipv6
#define	DNS_TYPE_SRV		33
#define	DNS_TYPE_DNAME		39
#define	DNS_TYPE_OPT		41
#define	DNS_TYPE_DS			43
#define	DNS_TYPE_RRSIG		46
#define	DNS_TYPE_NSEC		47
#define	DNS_TYPE_DNSKEY		48
#define	DNS_TYPE_NSEC3		50
#define	DNS_TYPE_NSEC3PARAM	51
#define DNS_QTYPE_AXFR		252
#define DNS_QTYPE_MAILB		253
#define DNS_QTYPE_MAILA		254
#define DNS_QTYPE_ANY		255
#define DNS_TYPE_DLV		32769	/* DSNSEC Lokkaside Validation */
#define DNS_TYPE_UNKNOWN	65534

#define DNS_CLASS_UNKNOWN	0
#define DNS_CLASS_IN		1
#define DNS_CLASS_CS		2
#define DNS_CLASS_CH		3
#define DNS_CLASS_HS		4
#define DNS_QCLASS_ANY		255

typedef struct _dns_hdr
{
	u_int16_t id;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_char rd:1;
	u_char tc:1;
	u_char aa:1;
	u_char opcode:4;
	u_char qr:1;
	u_char rcode:4;
	u_char z:3;
	u_char ra:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_char qr:1;
	u_char opcode:4;
	u_char aa:1;
	u_char tc:1;
	u_char rd:1;
	u_char ra:1;
	u_char z:3;
	u_char rcode:4;
#endif
	u_int16_t qdcount;
	u_int16_t ancount;
	u_int16_t aucount;//authority count
	u_int16_t adcount;//additional count
} dns_hdr_t;

typedef struct _hinfo
{
	u_char os_len;
	u_char cpu_len;
	u_char cpu[DNS_HINFO_MAX_CPU+1];
	u_char os[DNS_HINFO_MAX_OS+1];
}hinfo_t;

typedef struct _minfo
{
	u_char rmailbx[DNS_MAX_NAME+1];
	u_char emailbx[DNS_MAX_NAME+1];
}minfo_t;

typedef struct _mx
{
	u_int16_t preference;
	u_char exchange[DNS_MAX_NAME+1];
}mx_t;

typedef struct _soa
{
	u_char mname[DNS_MAX_NAME+1];
	u_char rname[DNS_MAX_NAME+1];
	u_int32_t serial;
	u_int32_t refresh;
	u_int32_t retry;
	u_int32_t expire;
	u_int32_t minimum;
}soa_t;

typedef struct _rp_t
{
	u_char mailbox[DNS_MAX_NAME+1];
	u_char txt_rr[DNS_MAX_NAME+1];
}rp_t;

typedef struct _txt_t
{
	u_char txt[DNS_MAX_NAME+1];
	u_char size;
}txt_t;

typedef struct _null
{
	u_char null[DNS_MAX_NAME+1];
	u_char size;
}null_t;

typedef struct _wks
{
	u_char protocol;
	u_int32_t addr;
	u_int32_t size;
	u_char * bitmap;
}wks_t;

typedef struct _srv
{
	u_int16_t priority;
	u_int16_t weight;
	u_int16_t port;
	u_char target[DNS_MAX_TARGET];
}srv_t;

typedef struct _ds
{
	u_int16_t key_tag;
	u_char algo;
	u_char digest_type;
	u_int32_t digest_len;
	u_char *digest;
}ds_t;


typedef struct _rrsig
{
	u_int16_t type_covered;
	u_char algo;
	u_char labels;
	u_int32_t original_ttl;
	u_int32_t sig_expiration;
	u_int32_t sig_inception;
	u_int32_t key_tag;
	u_int32_t signature_len;
	u_char signer_name[DNS_MAX_SIGNER_NAME];
	u_char *signature;
}rrsig_t;

typedef struct _nsec
{
	u_int16_t maps_len;
	u_char next_domain[DNS_MAX_OWNER];
	u_char type_bit_maps[DNS_MAX_MAPS];
}nsec_t;

typedef struct _dnskey
{
	u_int16_t flags;
	u_char protocol;
	u_char algo;
	u_int32_t public_key_len;
	u_char *public_key; 
}dnskey_t;


typedef struct _nsec3
{
	u_char hash_algo;
	u_char flags;
	u_char salt_len;
	u_char hash_len;
	u_int16_t iteration;
	u_int16_t maps_len;
	u_char *salt_value;
	u_char *next_hash_owner;
	u_char type_bit_maps[DNS_MAX_MAPS];
}nsec3_t;

typedef struct _nsec3param
{
	u_char hash_algo;
	u_char flags;
	u_char salt_len;
	u_int16_t iteration;
	u_char *salt_value;
}nsec3param_t;

typedef struct _dns_rr
{
	u_char name[DNS_MAX_NAME+1];
	u_int16_t type;
	u_int16_t rr_class;
	u_int32_t ttl;		/* 1byte: extended RCODE; 1byte: version; 2bytes: Z(upper bit) if type is OPT */
	u_int16_t rdlength;
	union
	{
		u_char cname[DNS_MAX_NAME + 1];	/* cname[DNS_MAX_NAME + 1]; */
		hinfo_t hinfo;
		u_char mb[DNS_MAX_NAME + 1];		/* mb[DNS_MAX_NAME + 1]; */
		u_char md[DNS_MAX_NAME + 1];		/* md[DNS_MAX_NAME + 1]; */
		u_char mf[DNS_MAX_NAME + 1];		/* mf[DNS_MAX_NAME + 1]; */
		u_char mg[DNS_MAX_NAME + 1];		/* mg[DNS_MAX_NAME + 1]; */
		minfo_t minfo;
		u_char mr[DNS_MAX_NAME + 1];		/* mr[DNS_MAX_NAME + 1]; */
		mx_t mx;
		u_char ns[DNS_MAX_NAME + 1];		/* ns[DNS_MAX_NAME + 1]; */
		u_char ptr[DNS_MAX_NAME + 1];	/* ptr[DNS_MAX_NAME + 1]; */
		soa_t soa;
		u_char a[DNS_MAX_NAME + 1];
		u_char aaaa[DNS_MAX_NAME + 1];	/* aaaa[16]; */
		u_char dname[DNS_MAX_NAME + 1];
		u_char isdn[DNS_MAX_NAME + 1];
		u_char unknown_data[DNS_MAX_NAME + 1];
		txt_t txt;
		rp_t rp;
		null_t null;
		wks_t wks;
		srv_t srv;
		ds_t ds;
		rrsig_t rrsig;
		nsec_t nsec;
		dnskey_t dnskey;
		nsec3_t nsec3;
		nsec3param_t nsec3param;
	} rdata;
} dns_rr_t;

typedef struct _fake_packet_opt
{
	u_int16_t cfg_type;	/* IP or STR */
	u_int16_t res_type;
	u_int32_t ttl;
	u_int32_t res_len;
	u_char res_info[DNS_MAX_NAME+1];
}cheat_pkt_opt_t;

typedef struct
{
	u_int16_t qtype;
	u_int16_t qclass;
	u_char qname[DNS_MAX_NAME+1];
} dns_query_question_t;

#define	MAX_RR_NUM	256

typedef struct _dns_info
{
	dns_hdr_t hdr_info;
	int rr_count;
	dns_rr_t rr[MAX_RR_NUM];	
	dns_query_question_t query_question;
}dns_info_t;



enum flag_id
{
	/* 解各个字段时，都会自动带上头部信息 */
	DNS_UNKOWN			=0,
	ALL					= 1<<0,		/* 全解 */
	DNS_ALL				= 1<<1,		/* 全解 */
	DNS_REQ_ALL 		= 1<<2,		/* 请求侧全解 */
	DNS_RES_ALL			= 1<<3,		/* 解解应答侧全部内容 */
	DNS_REQ_HDR 		= 1<<4,		/* 解请求侧头部内容 */
	DNS_RES_HDR 		= 1<<5,		/* 解应答侧头部内容 */	
	//DNS_REQ_QUERY		= 1<<6,		/* 解应答侧中的请求信息(解请求侧请求查询信息会自动带上头部，即为DNS_REQ_ALL_FLAG_ID，所有没必要再设一个值) */
	DNS_RES_QUERY		= 1<<7,		/* 解应答侧中的请求信息 */
	DNS_RES_RRS			= 1<<8,		/* 解所有应答资源记录 */
	DNS_RES_ANSWER		= 1<<9,		/* 解answer应答记录 */
	DNS_RES_AUTH		= 1<<10,		/* 解授权资源记录 */
	DNS_RES_ADD			= 1<<11,		/* 解附加资源记录 */
};


#ifdef __cplusplus
extern "C"
{
#endif

/*
* name:build_dns_payload
* functionality:build dns packet
* param:
*       pay_load_buf:the thread num
*       len:buffer length
*       pkt_para:option parameter
*       opt_cnt:option counts
*
*  returns:
*        >0:build sucess
*       -1:ibuild failed
*
* */

int get_rr_str2json(cJSON *object, dns_info_t *dns_info, int *dns_sec);
int get_rr_content2buf(dns_rr_t *rr, int rr_count, char *rr_buf, int buflen, int *dns_sec);
int dns_save_raw_pkt(char *buf, int buflen, const struct streaminfo * a_stream);
int build_cheat_pkt(unsigned char *payload, int payload_len, dns_query_question_t *query_question, cheat_pkt_opt_t *cheat_opt, int cheat_opt_num);

#ifdef __cplusplus
}
#endif
#endif

